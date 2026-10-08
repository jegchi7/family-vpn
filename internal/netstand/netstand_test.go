package netstand

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"familyvpn.local/platform/internal/netguard"
	"familyvpn.local/platform/internal/runtimeenv"
)

func syntheticPlan(t *testing.T) (netguard.Inputs, Target, netguard.Inventory, netguard.Plan) {
	t.Helper()
	i := netguard.Inputs{Role: "ru", RUIPv4: netip.MustParseAddr("8.8.4.4"), ForeignIPv4: netip.MustParseAddr("1.1.1.1"), HostPublicIPv4: netip.MustParseAddr("8.8.4.4"), Transit: netip.MustParsePrefix("10.222.0.0/30"), Uplink: "eth0"}
	target := Target{Scope: runtimeenv.Scope{BootID: "12345678-1234-1234-1234-123456789abc", NetNSDevice: 4, NetNSInode: 5}, IP_SHA256: strings.Repeat("a", 64), NFT_SHA256: strings.Repeat("b", 64), SysctlSHA256: strings.Repeat("c", 64), TCSHA256: strings.Repeat("d", 64)}
	v := netguard.Inventory{Interfaces: []string{"lo", "eth0"}, Addresses: []netguard.Address{{Interface: "lo", Prefix: netip.MustParsePrefix("127.0.0.1/8")}, {Interface: "eth0", Prefix: netip.MustParsePrefix("8.8.4.4/24")}}, Routes: []netguard.Route{{Interface: "eth0", Destination: netip.MustParsePrefix("0.0.0.0/0")}}, IPv4Forwarding: true}
	p, e := netguard.Build(i, v)
	if e != nil {
		t.Fatal(e)
	}
	return i, target, v, p
}
func TestProtectedArtifactCannotRelabelOrReplayObservation(t *testing.T) {
	i, target, v, p := syntheticPlan(t)
	a, e := buildArtifacts(i, target, v, p)
	if e != nil {
		t.Fatal(e)
	}
	m, e := validateArtifacts(a)
	if e != nil {
		t.Fatal(e)
	}
	s := summary(m)
	if !s.ConfigurationValidated || s.InventoryChecked || s.ExecutionScopeBound || s.KernelGuardVerified || s.NetworkChanged || s.ServicesStarted || s.NativeAcceptance || s.ClientVerified || s.Ready {
		t.Fatal("stored artifact acquired observation or readiness")
	}
	changes := []artifacts{
		{Manifest: append(bytes.Clone(a.Manifest), '\n'), Host: a.Host, Namespace: a.Namespace},
		{Manifest: bytes.Replace(a.Manifest, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1), Host: a.Host, Namespace: a.Namespace},
		{Manifest: a.Manifest, Host: append(bytes.Clone(a.Host), '\n'), Namespace: a.Namespace},
		{Manifest: bytes.Replace(a.Manifest, []byte(`"steps":`), []byte(`"unknown":false,"steps":`), 1), Host: a.Host, Namespace: a.Namespace},
		{Manifest: a.Manifest, Host: a.Host, Namespace: a.Namespace, ForeignXray: []byte("private unexpected")},
	}
	for _, changed := range changes {
		if _, e := validateArtifacts(changed); e == nil {
			t.Fatal("changed/ambiguous artifact accepted")
		}
	}
	// Even a recomputed digest cannot turn a caller-selected command script into
	// the plan generated from closed topology inputs and recorded inventory.
	m.HostSHA256 = hash([]byte("flush ruleset\n"))
	changed := a
	changed.Host = []byte("flush ruleset\n")
	changed.Manifest, _ = json.Marshal(m)
	if _, e := validateArtifacts(changed); e == nil {
		t.Fatal("arbitrary script with matching digest accepted")
	}
}

type syntheticRunner struct {
	events []string
	failAt int
	checks int
	reject bool
	cancel context.CancelFunc
}

func (r *syntheticRunner) Run(_ context.Context, s netguard.Step) error {
	r.events = append(r.events, "step")
	if activationStep(s) {
		r.events[len(r.events)-1] = "activation"
	}
	if len(r.events) == r.failAt {
		return errors.New("synthetic failure")
	}
	return nil
}
func (r *syntheticRunner) GuardReadback(_ context.Context, _ netguard.Plan) error {
	r.events = append(r.events, "readback")
	r.checks++
	if r.cancel != nil {
		r.cancel()
	}
	if r.reject {
		return ErrGuardProof
	}
	return nil
}
func TestSyntheticEngineReadsGuardsBeforeEveryActivationAndStopsClosed(t *testing.T) {
	_, _, _, p := syntheticPlan(t)
	boundary := -1
	for n, s := range p.Steps {
		if activationStep(s) {
			boundary = n
			break
		}
	}
	r := &syntheticRunner{}
	n, e := execute(context.Background(), p, r, boundary)
	if e != nil || n != len(p.Steps) {
		t.Fatal("synthetic ordered plan failed")
	}
	activations := 0
	for n, event := range r.events {
		if event == "activation" {
			activations++
			if n == 0 || r.events[n-1] != "readback" {
				t.Fatal("activation without immediately preceding guard readback")
			}
		}
	}
	if activations < 3 || r.checks != activations {
		t.Fatal("not all activations guarded")
	}
	reject := &syntheticRunner{reject: true}
	n, e = execute(context.Background(), p, reject, boundary)
	if !errors.Is(e, ErrGuardProof) || n != boundary {
		t.Fatal("readback rejection did not stop before first activation")
	}
	for _, event := range reject.events {
		if event == "activation" {
			t.Fatal("rejected readback activated a link")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancelAtReadback := &syntheticRunner{cancel: cancel}
	n, e = execute(ctx, p, cancelAtReadback, boundary)
	if !errors.Is(e, ErrExecution) || n != boundary {
		t.Fatal("cancel during guard readback did not stay closed")
	}
	earlyFailure := &syntheticRunner{failAt: 2}
	n, e = execute(context.Background(), p, earlyFailure, boundary)
	if e == nil || n != 1 || len(earlyFailure.events) != 2 {
		t.Fatal("failure triggered later commands or cleanup")
	}
	if _, e = execute(context.Background(), p, &syntheticRunner{}, 0); !errors.Is(e, ErrInput) {
		t.Fatal("unguarded execution accepted")
	}
}
func TestProofIsBoundedPrivateAndDoesNotSurviveClose(t *testing.T) {
	i, target, _, _ := syntheticPlan(t)
	file, e := os.CreateTemp(t.TempDir(), "synthetic-namespace-")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	p := Proof{inputs: i, target: target, namespace: file, observed: now}
	if !p.valid(i, target, now) || p.valid(i, target, now.Add(10*time.Second)) || p.valid(i, target, now.Add(-time.Nanosecond)) {
		t.Fatal("invalid proof TTL boundary")
	}
	other := target
	other.TCSHA256 = strings.Repeat("e", 64)
	if p.valid(i, other, now) {
		t.Fatal("tool pin change preserved proof")
	}
	i.Role = "foreign"
	if p.valid(i, target, now) {
		t.Fatal("topology change preserved proof")
	}
	if b, e := json.Marshal(p); e == nil || len(b) != 0 {
		t.Fatal("kernel proof serialized")
	}
	p.Close()
	if p.namespace != nil || !p.observed.IsZero() {
		t.Fatal("closed proof remained usable")
	}
}

func TestSyntheticNamespaceStartAlwaysRestoresBeforeReleasingThread(t *testing.T) {
	for _, fail := range []string{"", "enter", "namespace", "start", "restore", "host"} {
		var events []string
		phase := func(name string) func() error {
			return func() error {
				events = append(events, name)
				if name == fail {
					return ErrExecution
				}
				return nil
			}
		}
		started, restored, e := namespaceStart(phase("enter"), phase("namespace"), phase("start"), phase("restore"), phase("host"))
		if fail == "" {
			if !started || !restored || e != nil || strings.Join(events, ",") != "enter,namespace,start,restore,host" {
				t.Fatal("namespace restore order changed")
			}
			continue
		}
		if e == nil {
			t.Fatal("failed boundary accepted")
		}
		if fail == "enter" {
			if started || !restored || len(events) != 1 {
				t.Fatal("failed entry continued")
			}
			continue
		}
		if fail == "namespace" {
			if started || !restored || strings.Join(events, ",") != "enter,namespace,restore,host" {
				t.Fatal("namespace scope rejection skipped restore")
			}
			continue
		}
		if fail == "start" {
			if started || !restored || strings.Join(events, ",") != "enter,namespace,start,restore,host" {
				t.Fatal("child start failure skipped restore")
			}
			continue
		}
		if !started || restored {
			t.Fatal("failed restoration authorized thread release")
		}
		if fail == "restore" && strings.Join(events, ",") != "enter,namespace,start,restore" {
			t.Fatal("failed restore continued execution")
		}
	}
}
