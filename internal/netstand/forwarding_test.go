package netstand

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"familyvpn.local/platform/internal/netguard"
	"familyvpn.local/platform/internal/runtimeenv"
)

// Synthetic state-machine tests only: no network or process is executed.
func syntheticForwarding() forwardingObservation {
	o := forwardingObservation{scope: runtimeenv.Scope{BootID: "12345678-1234-1234-1234-123456789abc", NetNSDevice: 4, NetNSInode: 5}, links: map[string]int{"lo": 1, "ens3": 2, "eth0.200": 3}, conf: map[string]map[string]int32{}, features: map[string]forwardingFeatures{}}
	for _, name := range []string{"all", "default", "lo", "ens3", "eth0.200"} {
		o.conf[name] = map[string]int32{}
		for _, key := range forwardingConfKeys {
			o.conf[name][key] = 0
		}
		o.conf[name]["accept_redirects"] = 1
		o.conf[name]["send_redirects"] = 1
		o.conf[name]["medium_id"] = -1
		o.conf[name]["igmpv2_unsolicited_report_interval"] = 10000
		o.conf[name]["igmpv3_unsolicited_report_interval"] = 1000
	}
	o.conf["lo"]["forwarding"] = 1
	for name := range o.links {
		o.features[name] = forwardingFeatures{names: []string{"tx-checksum-ipv4", "rx-lro"}, words: [][4]uint32{{1, 1, 1, 0}}}
	}
	return o
}

func syntheticForwardingOwned(o forwardingObservation) forwardingObservation {
	o = cloneForwarding(o)
	o.links[netguard.HostVeth] = 4
	o.conf[netguard.HostVeth] = map[string]int32{}
	for key, value := range o.conf["default"] {
		o.conf[netguard.HostVeth][key] = value
	}
	o.conf[netguard.HostVeth]["rp_filter"] = 1
	o.conf[netguard.HostVeth]["forwarding"] = 1
	for _, key := range []string{"accept_redirects", "send_redirects", "route_localnet"} {
		o.conf[netguard.HostVeth][key] = 0
	}
	o.features[netguard.HostVeth] = forwardingFeatures{names: []string{"tx-checksum-ipv4", "rx-lro"}, words: [][4]uint32{{1, 1, 1, 0}}}
	return o
}

func TestForwardingBaselineRejectsAmbiguousEffectiveForwardingAndOffloads(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*forwardingObservation)
	}{
		{"global_already_on", func(o *forwardingObservation) { o.global = 1; o.conf["all"]["forwarding"] = 1 }},
		{"mixed_uplink_forwarding", func(o *forwardingObservation) { o.conf["ens3"]["forwarding"] = 1 }},
		{"mixed_other_forwarding", func(o *forwardingObservation) { o.conf["eth0.200"]["forwarding"] = 1 }},
		{"requested_lro", func(o *forwardingObservation) { f := o.features["ens3"]; f.words[0][1] |= 2; o.features["ens3"] = f }},
		{"pending_other_feature", func(o *forwardingObservation) { f := o.features["ens3"]; f.words[0][1] ^= 1; o.features["ens3"] = f }},
		{"feature_outside_table", func(o *forwardingObservation) { f := o.features["ens3"]; f.words[0][2] |= 4; o.features["ens3"] = f }},
		{"active_lro", func(o *forwardingObservation) {
			f := o.features["eth0.200"]
			f.words[0][2] |= 2
			o.features["eth0.200"] = f
		}},
		{"unknown_lro", func(o *forwardingObservation) { f := o.features["lo"]; f.names[1] = "rx-gro"; o.features["lo"] = f }},
		{"duplicate_lro", func(o *forwardingObservation) { f := o.features["ens3"]; f.names[0] = "rx-lro"; o.features["ens3"] = f }},
		{"missing_vector", func(o *forwardingObservation) { delete(o.features, "eth0.200") }},
		{"unknown_sysctl", func(o *forwardingObservation) { o.conf["default"]["unreviewed_extension"] = 0 }},
		{"missing_sysctl", func(o *forwardingObservation) { delete(o.conf["lo"], "accept_local") }},
		{"duplicate_ifindex", func(o *forwardingObservation) { o.links["ens3"] = 1 }},
		{"ifname_path", func(o *forwardingObservation) { o.links["../ens3"] = 2 }},
		{"owned_name", func(o *forwardingObservation) { *o = syntheticForwardingOwned(*o) }},
		{"changed_scope", func(o *forwardingObservation) { o.scope.BootID = "" }},
		{"alias_global", func(o *forwardingObservation) { o.conf["all"]["forwarding"] = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := syntheticForwarding()
			tc.mutate(&o)
			if _, e := newForwardingPreservation(o, "ens3"); e == nil {
				t.Fatal("ambiguous baseline accepted")
			}
		})
	}
	if _, e := newForwardingPreservation(syntheticForwarding(), "ens3"); e != nil {
		t.Fatal("closed baseline rejected")
	}
	o := syntheticForwarding()
	f := o.features["lo"]
	f.names = append(f.names, "loopback")
	f.words[0][2] |= 4 // immutable active feature, absent from mutable/requested
	o.features["lo"] = f
	if _, e := newForwardingPreservation(o, "ens3"); e != nil {
		t.Fatal("immutable active feature wrongly treated as a pending request")
	}
}

func TestForwardingBaselineImmutableAndExpectedDigestReadOnly(t *testing.T) {
	o := syntheticForwarding()
	p, e := newForwardingPreservation(o, "ens3")
	if e != nil {
		t.Fatal(e)
	}
	original := p.baselineHash()
	expected := p.expectedHash()
	o.conf["all"]["accept_redirects"] = 0
	o.links["ens3"] = 99
	f := o.features["lo"]
	f.names[0] = "corrupt"
	f.words[0][2] = 99
	o.features["lo"] = f
	if p.baselineHash() != original || p.expectedHash() != expected || original == expected || !digestValid(expected) {
		t.Fatal("mutable input changed memory baseline")
	}
	post := p.expected()
	if post.global != 1 || post.conf["all"]["forwarding"] != 1 || post.conf["ens3"]["forwarding"] != 1 || post.conf["eth0.200"]["forwarding"] != 0 || post.conf["lo"]["forwarding"] != 1 || post.conf["default"]["forwarding"] != 0 || post.conf["all"]["accept_redirects"] != 1 || post.conf["ens3"]["medium_id"] != -1 {
		t.Fatal("expected behavior does not preserve unrelated/default vector")
	}
	post.links["ens3"] = 777
	if forwardingFingerprint(post) != expected {
		t.Fatal("restart expectation incorrectly contains generated identity")
	}
	if _, e := json.Marshal(p); e == nil || strings.Contains(p.String(), "ens3") || strings.Contains(p.GoString(), expected) {
		t.Fatal("private baseline serializes or discloses fields")
	}
	p.close()
	if p.baselineHash() != "" || p.expectedHash() != "" {
		t.Fatal("closed baseline retained authority")
	}
}

type syntheticForwardingBackend struct {
	state                                forwardingObservation
	writes                               []forwardingWrite
	events                               []string
	guards, observes                     int
	failGuardAt, failReadAt, failWriteAt int
	mutate                               func(*forwardingObservation, int)
	cancel                               context.CancelFunc
}

func (b *syntheticForwardingBackend) Observe(context.Context) (forwardingObservation, error) {
	b.observes++
	b.events = append(b.events, "read")
	if b.mutate != nil {
		b.mutate(&b.state, b.observes)
	}
	if b.failReadAt == b.observes {
		return forwardingObservation{}, ErrForwarding
	}
	return cloneForwarding(b.state), nil
}
func (b *syntheticForwardingBackend) Guard(context.Context) error {
	b.guards++
	b.events = append(b.events, "guard")
	if b.cancel != nil {
		b.cancel()
	}
	if b.failGuardAt == b.guards {
		return ErrGuardProof
	}
	return nil
}
func (b *syntheticForwardingBackend) Write(_ context.Context, w forwardingWrite) error {
	b.writes = append(b.writes, w)
	b.events = append(b.events, "write")
	if w.interfaceName == "" {
		b.state.global = 1
		b.state.conf["all"]["forwarding"] = 1
		b.state.conf["all"]["accept_redirects"] = 0
		b.state.conf["default"]["forwarding"] = 1
		for name := range b.state.links {
			b.state.conf[name]["forwarding"] = 1
		}
	} else {
		b.state.conf[w.interfaceName][w.key] = w.value
	}
	if len(b.writes) == b.failWriteAt {
		return ErrForwarding
	}
	return nil
}

func TestForwardingPreservationGuardedOnceWithExactPostState(t *testing.T) {
	before := syntheticForwarding()
	p, _ := newForwardingPreservation(before, "ens3")
	b := &syntheticForwardingBackend{state: syntheticForwardingOwned(before)}
	if e := p.preserve(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	if forwardingFingerprint(b.state) != p.expectedHash() || b.state.conf[netguard.HostVeth]["forwarding"] != 1 || b.state.conf[netguard.HostVeth]["rp_filter"] != 1 {
		t.Fatal("poststate differs from expectation")
	}
	if len(b.writes) != 5 || b.writes[0] != (forwardingWrite{key: "ip_forward", value: 1}) {
		t.Fatal("closed transition sequence changed")
	}
	for n, event := range b.events {
		if event == "write" && (n < 2 || b.events[n-1] != "read" || b.events[n-2] != "guard") {
			t.Fatal("write without immediate guard and exact current read")
		}
	}
	for _, w := range b.writes[1:] {
		if w.key == "ip_forward" || w.interfaceName == "ens3" || w.interfaceName == netguard.HostVeth {
			t.Fatal("unexpected inverse toggle or unrelated write")
		}
	}
	count := len(b.writes)
	if p.preserve(context.Background(), b) == nil || len(b.writes) != count {
		t.Fatal("consumed baseline replayed")
	}
}

func TestForwardingPreservationBlocksBeforeWriteOnGuardScopeIdentityOrConfigurationChange(t *testing.T) {
	cases := []struct {
		name   string
		change func(*syntheticForwardingBackend)
	}{
		{"guard", func(b *syntheticForwardingBackend) { b.failGuardAt = 1 }},
		{"new_interface", func(b *syntheticForwardingBackend) { b.state.links["new0"] = 9 }},
		{"changed_ifindex", func(b *syntheticForwardingBackend) { b.state.links["ens3"] = 9 }},
		{"changed_boot", func(b *syntheticForwardingBackend) { b.state.scope.BootID = "22345678-1234-1234-1234-123456789abc" }},
		{"changed_setting", func(b *syntheticForwardingBackend) { b.state.conf["eth0.200"]["rp_filter"] = 2 }},
		{"owned_not_hardened", func(b *syntheticForwardingBackend) { b.state.conf[netguard.HostVeth]["accept_redirects"] = 1 }},
		{"feature_change_after_guard", func(b *syntheticForwardingBackend) {
			b.mutate = func(o *forwardingObservation, n int) {
				if n == 2 {
					f := o.features["ens3"]
					f.words[0][0] ^= 1
					o.features["ens3"] = f
				}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := syntheticForwarding()
			p, _ := newForwardingPreservation(o, "ens3")
			b := &syntheticForwardingBackend{state: syntheticForwardingOwned(o)}
			tc.change(b)
			if p.preserve(context.Background(), b) == nil || len(b.writes) != 0 {
				t.Fatal("changed/unguarded transition wrote")
			}
		})
	}
}

func TestForwardingPreservationFailureAndCancellationNeverReplayOrToggleBack(t *testing.T) {
	for n := 1; n <= 5; n++ {
		o := syntheticForwarding()
		p, _ := newForwardingPreservation(o, "ens3")
		b := &syntheticForwardingBackend{state: syntheticForwardingOwned(o), failWriteAt: n}
		if p.preserve(context.Background(), b) == nil || len(b.writes) != n || p.preserve(context.Background(), b) == nil || len(b.writes) != n {
			t.Fatal("failed write replayed or succeeded")
		}
		for _, w := range b.writes {
			if w.interfaceName == "" && w.value != 1 {
				t.Fatal("inverse global transition attempted")
			}
		}
	}
	o := syntheticForwarding()
	p, _ := newForwardingPreservation(o, "ens3")
	ctx, cancel := context.WithCancel(context.Background())
	b := &syntheticForwardingBackend{state: syntheticForwardingOwned(o), cancel: cancel}
	if p.preserve(ctx, b) == nil || len(b.writes) != 0 {
		t.Fatal("cancelled guard wrote")
	}
	p, _ = newForwardingPreservation(o, "ens3")
	b = &syntheticForwardingBackend{state: syntheticForwardingOwned(o), failReadAt: 3}
	if p.preserve(context.Background(), b) == nil || len(b.writes) != 1 || !p.used {
		t.Fatal("lost transition readback did not fence baseline")
	}
}

func TestForwardingValueCanonicalBoundsAndClosedNames(t *testing.T) {
	for _, s := range []string{"0\n", "1\n", "-1\n", "2147483647\n", "-2147483648\n"} {
		if _, e := forwardingNumber([]byte(s)); e != nil {
			t.Fatal("canonical kernel integer rejected")
		}
	}
	for _, s := range []string{"", "0", "01\n", "-0\n", "+1\n", " 1\n", "1 \n", "1\n1\n", "2147483648\n", "-2147483649\n", strings.Repeat("9", 40) + "\n"} {
		if _, e := forwardingNumber([]byte(s)); e == nil {
			t.Fatal("ambiguous or out-of-bound integer accepted")
		}
	}
	for _, s := range []string{"ens3", "eth0.200", "lo"} {
		if !forwardingName(s) {
			t.Fatal("closed interface name rejected")
		}
	}
	for _, s := range []string{"", "..", "../lo", "/proc", "all", "default", "x\n", strings.Repeat("x", 16)} {
		if forwardingName(s) {
			t.Fatal("path or pseudo-interface accepted")
		}
	}
	if !sortStringsEqual(forwardingConfKeys) {
		t.Fatal("fixed vector order drift")
	}
}

func sortStringsEqual(v []string) bool {
	for n := 1; n < len(v); n++ {
		if v[n-1] >= v[n] {
			return false
		}
	}
	return true
}
