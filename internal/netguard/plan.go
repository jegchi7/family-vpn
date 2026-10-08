// Package netguard builds a closed primary-only VPN network plan in memory.
// It does not inspect or change the host, execute tools, start services, or
// attest native firewall/routing/client acceptance.
package netguard

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	Namespace        = "vpn-data"
	HostVeth         = "fvpn-host"
	NamespaceVeth    = "fvpn-ns"
	HostTable        = "family_vpn_guard"
	NATTable         = "family_vpn_nat"
	NamespaceTable   = "family_vpn_data"
	IPExecutable     = "/usr/sbin/ip"
	NFTExecutable    = "/usr/sbin/nft"
	SysctlExecutable = "/usr/sbin/sysctl"
)

var ErrInput = errors.New("invalid VPN network topology")
var ErrInventory = errors.New("VPN network inventory conflicts with topology")

type Inputs struct {
	Role                                string
	RUIPv4, ForeignIPv4, HostPublicIPv4 netip.Addr
	Transit                             netip.Prefix
	Uplink                              string
}
type Address struct {
	Interface string
	Prefix    netip.Prefix
}
type Route struct {
	Interface   string
	Destination netip.Prefix
}
type Inventory struct {
	Interfaces     []string
	Addresses      []Address
	Routes         []Route
	IPv4Forwarding bool
}
type Step struct {
	Scope      string
	Executable string
	Args       []string
	Stdin      []byte
}
type Plan struct {
	Role, RUIPv4, ForeignIPv4, HostPublicIPv4, Transit, HostIPv4, NamespaceIPv4, Uplink string
	HostFirewall, NamespaceFirewall                                                     []byte
	Steps                                                                               []Step
}
type Summary struct {
	Role                string `json:"role"`
	StepCount           int    `json:"step_count"`
	KernelGuardVerified bool   `json:"kernel_guard_verified"`
	RuntimeVerified     bool   `json:"runtime_verified"`
	ClientVerified      bool   `json:"client_verified"`
	Ready               bool   `json:"ready"`
}

func (p Plan) SafeSummary() Summary { return Summary{Role: p.Role, StepCount: len(p.Steps)} }

var deniedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("168.63.129.16/32"),
}

func publicIPv4(a netip.Addr) bool {
	if !a.Is4() || !a.IsGlobalUnicast() || a.Zone() != "" {
		return false
	}
	for _, p := range deniedIPv4 {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
func interfaceName(s string) bool {
	if len(s) < 1 || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return s != "." && s != ".."
}
func ValidateInputs(i Inputs) error {
	if i.Role != "ru" && i.Role != "foreign" || !publicIPv4(i.RUIPv4) || !publicIPv4(i.ForeignIPv4) || i.RUIPv4 == i.ForeignIPv4 || !interfaceName(i.Uplink) || i.Uplink == "lo" || i.Uplink == HostVeth || i.Uplink == NamespaceVeth {
		return ErrInput
	}
	expected := i.RUIPv4
	if i.Role == "foreign" {
		expected = i.ForeignIPv4
	}
	if i.HostPublicIPv4 != expected {
		return ErrInput
	}
	if !i.Transit.IsValid() || !i.Transit.Addr().Is4() || i.Transit.Bits() != 30 || i.Transit != i.Transit.Masked() {
		return ErrInput
	}
	private := false
	for _, p := range []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")} {
		if p.Contains(i.Transit.Addr()) && p.Contains(i.Transit.Addr().Next().Next().Next()) {
			private = true
		}
	}
	if !private {
		return ErrInput
	}
	return nil
}

func validateInventory(i Inputs, v Inventory) error {
	if len(v.Interfaces) == 0 || len(v.Interfaces) > 256 || len(v.Addresses) == 0 || len(v.Addresses) > 512 || len(v.Routes) == 0 || len(v.Routes) > 1024 {
		return ErrInventory
	}
	interfaces := map[string]bool{}
	for _, name := range v.Interfaces {
		if !interfaceName(name) || interfaces[name] || name == HostVeth || name == NamespaceVeth {
			return ErrInventory
		}
		interfaces[name] = true
	}
	if !interfaces[i.Uplink] {
		return ErrInventory
	}
	seenPublic := false
	remote := i.ForeignIPv4
	if i.Role == "foreign" {
		remote = i.RUIPv4
	}
	for _, a := range v.Addresses {
		if !interfaces[a.Interface] || !a.Prefix.IsValid() || a.Prefix.Addr().Is4In6() {
			return ErrInventory
		}
		if a.Prefix.Addr() == remote {
			return ErrInventory
		}
		if a.Interface == i.Uplink && a.Prefix.Addr() == i.HostPublicIPv4 {
			seenPublic = true
		}
		if a.Prefix.Addr().Is4() && a.Prefix.Overlaps(i.Transit) {
			return ErrInventory
		}
	}
	defaults := 0
	for _, r := range v.Routes {
		if !interfaces[r.Interface] || !r.Destination.IsValid() || r.Destination != r.Destination.Masked() || r.Destination.Addr().Is4In6() {
			return ErrInventory
		}
		if !r.Destination.Addr().Is4() {
			continue
		}
		if r.Destination.Bits() == 0 {
			defaults++
			if r.Interface != i.Uplink {
				return ErrInventory
			}
			continue
		}
		if r.Destination.Overlaps(i.Transit) {
			return ErrInventory
		}
		if i.Role == "ru" && r.Destination.Contains(i.ForeignIPv4) && r.Interface != i.Uplink {
			return ErrInventory
		}
	}
	if !seenPublic || defaults != 1 {
		return ErrInventory
	}
	return nil
}

func blockedPrefixes(i Inputs, v Inventory) []string {
	all := append([]netip.Prefix{}, deniedIPv4...)
	all = append(all, netip.PrefixFrom(i.RUIPv4, 32), netip.PrefixFrom(i.ForeignIPv4, 32))
	for _, a := range v.Addresses {
		if a.Prefix.Addr().Is4() {
			all = append(all, netip.PrefixFrom(a.Prefix.Addr(), 32))
		}
	}
	sort.Slice(all, func(a, b int) bool {
		if all[a].Bits() != all[b].Bits() {
			return all[a].Bits() < all[b].Bits()
		}
		return all[a].Addr().Compare(all[b].Addr()) < 0
	})
	kept := []netip.Prefix{}
	for _, p := range all {
		covered := false
		for _, k := range kept {
			if k.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}
	sort.Slice(kept, func(a, b int) bool { return kept[a].Addr().Compare(kept[b].Addr()) < 0 })
	out := make([]string, len(kept))
	for n, p := range kept {
		out[n] = p.String()
	}
	return out
}

func Build(i Inputs, v Inventory) (Plan, error) {
	if err := ValidateInputs(i); err != nil {
		return Plan{}, err
	}
	if err := validateInventory(i, v); err != nil {
		return Plan{}, err
	}
	p := Plan{Role: i.Role, RUIPv4: i.RUIPv4.String(), ForeignIPv4: i.ForeignIPv4.String(), HostPublicIPv4: i.HostPublicIPv4.String(), Transit: i.Transit.String(), HostIPv4: i.Transit.Addr().Next().String(), NamespaceIPv4: i.Transit.Addr().Next().Next().String(), Uplink: i.Uplink}
	p.HostFirewall = []byte(hostFirewall(p, blockedPrefixes(i, v), v.IPv4Forwarding))
	p.NamespaceFirewall = []byte(namespaceFirewall(p, blockedPrefixes(i, v)))
	add := func(scope, exe string, args ...string) {
		p.Steps = append(p.Steps, Step{Scope: scope, Executable: exe, Args: args})
	}
	p.Steps = append(p.Steps, Step{Scope: "host", Executable: NFTExecutable, Args: []string{"-f", "-"}, Stdin: append([]byte{}, p.HostFirewall...)})
	add("host", IPExecutable, "netns", "add", Namespace)
	p.Steps = append(p.Steps, Step{Scope: Namespace, Executable: NFTExecutable, Args: []string{"-f", "-"}, Stdin: append([]byte{}, p.NamespaceFirewall...)})
	add("host", IPExecutable, "link", "add", HostVeth, "type", "veth", "peer", "name", NamespaceVeth)
	add("host", IPExecutable, "link", "set", NamespaceVeth, "netns", Namespace)
	add("host", IPExecutable, "address", "add", p.HostIPv4+"/30", "dev", HostVeth)
	add(Namespace, IPExecutable, "address", "add", p.NamespaceIPv4+"/30", "dev", NamespaceVeth)
	hostSysctls := []string{"-w", "net.ipv6.conf." + HostVeth + ".disable_ipv6=1", "net.ipv4.conf." + HostVeth + ".rp_filter=1", "net.ipv4.conf." + HostVeth + ".accept_redirects=0", "net.ipv4.conf." + HostVeth + ".send_redirects=0", "net.ipv4.conf." + HostVeth + ".route_localnet=0"}
	add("host", SysctlExecutable, hostSysctls...)
	nsSysctls := []string{"-w", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1", "net.ipv6.conf.lo.disable_ipv6=1", "net.ipv6.conf." + NamespaceVeth + ".disable_ipv6=1", "net.ipv4.ip_forward=0"}
	// In host mode accept_redirects uses all/interface OR semantics. The veth
	// was already created, so changing default alone cannot close that setting.
	for _, iface := range []string{"all", "default", "lo", NamespaceVeth} {
		for _, setting := range []string{"rp_filter=1", "accept_redirects=0", "send_redirects=0", "route_localnet=0"} {
			nsSysctls = append(nsSysctls, "net.ipv4.conf."+iface+"."+setting)
		}
	}
	add(Namespace, SysctlExecutable, nsSysctls...)
	// Linux creates connected prefix/loopback routes only when the link is UP.
	// Guard readback precedes every UP; no core starts until the final readback
	// also verifies the newly created connected routes and this exact default.
	add("host", IPExecutable, "link", "set", HostVeth, "up")
	add(Namespace, IPExecutable, "link", "set", "lo", "up")
	add(Namespace, IPExecutable, "link", "set", NamespaceVeth, "up")
	add(Namespace, IPExecutable, "route", "add", "default", "via", p.HostIPv4, "dev", NamespaceVeth)
	if !v.IPv4Forwarding {
		add("host", SysctlExecutable, "-w", "net.ipv4.ip_forward=1")
		// ip_forward changes reset IPv4 host/router defaults. Reassert only the
		// owned veth settings; unrelated host sysctls are not rewritten here.
		add("host", SysctlExecutable, hostSysctls...)
	}
	return p, nil
}

func setBlock(blocked []string) string {
	return " set blocked { type ipv4_addr; flags interval; elements = { " + strings.Join(blocked, ", ") + " }; }\n"
}
func line(s string, args ...any) string { return "  " + fmt.Sprintf(s, args...) + "\n" }

// Each stage checks the actual destination as well as the conntrack original
// tuple: a Docker DNAT/redirect cannot turn an approved endpoint into a bypass.
// There is no blanket established/related accept for namespace traffic.
func hostFirewall(p Plan, blocked []string, forwarding bool) string {
	b := strings.Builder{}
	b.WriteString("table inet " + HostTable + " {\n" + setBlock(blocked))
	for _, stage := range []string{"pre", "forward", "post"} {
		b.WriteString(" chain from_data_" + stage + " {\n")
		b.WriteString(line("meta nfproto != ipv4 drop"))
		if stage == "post" {
			b.WriteString(line("ip saddr != %s drop", p.HostPublicIPv4))
		} else {
			b.WriteString(line("ip saddr != %s drop", p.NamespaceIPv4))
		}
		b.WriteString(line("ct state invalid drop"))
		iface := ""
		if stage != "pre" {
			iface = fmt.Sprintf("oifname %q ", p.Uplink)
		}
		client := "ip daddr != @blocked ct original ip saddr != @blocked "
		if p.Role == "foreign" {
			client = fmt.Sprintf("ip daddr %s ct original ip saddr %s ", p.RUIPv4, p.RUIPv4)
		}
		b.WriteString(line("%s%sct direction reply ct state established ct original ip daddr %s ct original protocol tcp ct original proto-dst 443 tcp sport 443 accept", iface, client, p.HostPublicIPv4))
		b.WriteString(line("%s%sct state related ct original ip daddr %s ct original protocol tcp ct original proto-dst 443 ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept", iface, client, p.HostPublicIPv4))
		b.WriteString(line("ct direction != original drop"))
		b.WriteString(line("ct original ip saddr != %s drop", p.NamespaceIPv4))
		if p.Role == "ru" {
			b.WriteString(line("%sip daddr %s ct original ip daddr %s ct original protocol tcp ct original proto-dst 443 tcp dport 443 ct state { new, established } accept", iface, p.ForeignIPv4, p.ForeignIPv4))
		} else {
			b.WriteString(line("ip daddr @blocked drop"))
			b.WriteString(line("ct original ip daddr @blocked drop"))
			for _, protocol := range []string{"tcp", "udp"} {
				b.WriteString(line("%smeta l4proto %s ct original protocol %s ct state { new, established } accept", iface, protocol, protocol))
			}
		}
		b.WriteString(line("drop"))
		b.WriteString(" }\n")
	}
	b.WriteString(" chain to_data {\n" + line("meta nfproto != ipv4 drop") + line("ip daddr != %s drop", p.NamespaceIPv4) + line("ct state invalid drop"))
	from := fmt.Sprintf("iifname %q ", p.Uplink)
	client := "ip saddr != @blocked ct original ip saddr != @blocked "
	if p.Role == "foreign" {
		client = fmt.Sprintf("ip saddr %s ct original ip saddr %s ", p.RUIPv4, p.RUIPv4)
	}
	b.WriteString(line("%s%sct direction original ct original ip daddr %s ct original protocol tcp ct original proto-dst 443 tcp dport 443 ct state { new, established } accept", from, client, p.HostPublicIPv4))
	if p.Role == "ru" {
		b.WriteString(line("%sip saddr %s ct direction reply ct original ip saddr %s ct original ip daddr %s ct original protocol tcp ct original proto-dst 443 tcp sport 443 ct state established accept", from, p.ForeignIPv4, p.NamespaceIPv4, p.ForeignIPv4))
		b.WriteString(line("%sct original ip saddr %s ct original ip daddr %s ct original protocol tcp ct original proto-dst 443 ct state related ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept", from, p.NamespaceIPv4, p.ForeignIPv4))
	} else {
		b.WriteString(line("ct original ip daddr @blocked drop"))
		b.WriteString(line("%sct original ip saddr %s ct original protocol { tcp, udp } ct state related ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept", from, p.NamespaceIPv4))
		b.WriteString(line("ip saddr @blocked drop"))
		for _, protocol := range []string{"tcp", "udp"} {
			b.WriteString(line("%sct direction reply ct original ip saddr %s meta l4proto %s ct original protocol %s ct state established accept", from, p.NamespaceIPv4, protocol, protocol))
		}
	}
	b.WriteString(line("drop") + " }\n")
	b.WriteString(" chain input { type filter hook input priority 300; policy accept;\n" + line("iifname %q drop", HostVeth) + " }\n")
	b.WriteString(" chain prerouting { type filter hook prerouting priority -150; policy accept;\n" + line("iifname %q jump from_data_pre", HostVeth) + " }\n")
	b.WriteString(" chain forward { type filter hook forward priority 300; policy accept;\n" + line("iifname %q jump from_data_forward", HostVeth) + line("oifname %q jump to_data", HostVeth))
	if !forwarding {
		b.WriteString(line("drop"))
	}
	b.WriteString(" }\n")
	b.WriteString(" chain postrouting { type filter hook postrouting priority 300; policy accept;\n" + line("iifname %q jump from_data_post", HostVeth) + line("oifname %q jump to_data", HostVeth) + " }\n}\n")
	b.WriteString("table ip " + NATTable + " {\n chain prerouting { type nat hook prerouting priority -100; policy accept;\n")
	source := ""
	if p.Role == "foreign" {
		source = "ip saddr " + p.RUIPv4 + " "
	}
	b.WriteString(line("iifname %q %sip daddr %s tcp dport 443 dnat to %s:443", p.Uplink, source, p.HostPublicIPv4, p.NamespaceIPv4) + " }\n chain postrouting { type nat hook postrouting priority 100; policy accept;\n")
	b.WriteString(line("iifname %q oifname %q ip saddr %s ct direction original snat to %s", HostVeth, p.Uplink, p.NamespaceIPv4, p.HostPublicIPv4) + " }\n}\n")
	return b.String()
}

func namespaceFirewall(p Plan, blocked []string) string {
	b := strings.Builder{}
	b.WriteString("table inet " + NamespaceTable + " {\n" + setBlock(blocked))
	lo := ""
	if p.Role == "ru" {
		lo = line("iifname \"lo\" ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 accept")
	}
	b.WriteString(" chain input { type filter hook input priority 300; policy drop;\n" + line("meta nfproto != ipv4 drop") + line("ct state invalid drop") + lo + line("iifname != %q drop", NamespaceVeth) + line("ip daddr != %s drop", p.NamespaceIPv4))
	client := "ip saddr != @blocked "
	if p.Role == "foreign" {
		client = "ip saddr " + p.RUIPv4 + " "
	}
	b.WriteString(line("%sct direction original tcp dport 443 ct state { new, established } accept", client))
	if p.Role == "ru" {
		b.WriteString(line("ip saddr %s ct direction reply ct original ip saddr %s ct original ip daddr %s ct original protocol tcp ct original proto-dst 443 tcp sport 443 ct state established accept", p.ForeignIPv4, p.NamespaceIPv4, p.ForeignIPv4))
		b.WriteString(line("ct original ip saddr %s ct original ip daddr %s ct original protocol tcp ct original proto-dst 443 ct state related ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept", p.NamespaceIPv4, p.ForeignIPv4))
	} else {
		b.WriteString(line("ct original ip daddr @blocked drop"))
		b.WriteString(line("ct original ip saddr %s ct original protocol { tcp, udp } ct state related ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept", p.NamespaceIPv4))
		b.WriteString(line("ip saddr @blocked drop"))
		for _, protocol := range []string{"tcp", "udp"} {
			b.WriteString(line("ct direction reply ct original ip saddr %s meta l4proto %s ct original protocol %s ct state established accept", p.NamespaceIPv4, protocol, protocol))
		}
	}
	b.WriteString(" }\n chain output { type filter hook output priority 300; policy drop;\n" + line("meta nfproto != ipv4 drop") + line("ct state invalid drop"))
	if p.Role == "ru" {
		b.WriteString(line("oifname \"lo\" ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 accept"))
	}
	b.WriteString(line("oifname != %q drop", NamespaceVeth) + line("ip saddr != %s drop", p.NamespaceIPv4))
	client = "ip daddr != @blocked ct original ip saddr != @blocked "
	if p.Role == "foreign" {
		client = "ip daddr " + p.RUIPv4 + " ct original ip saddr " + p.RUIPv4 + " "
	}
	b.WriteString(line("%sct direction reply ct original ip daddr %s ct original protocol tcp ct original proto-dst 443 tcp sport 443 ct state established accept", client, p.NamespaceIPv4))
	b.WriteString(line("%sct original ip daddr %s ct original protocol tcp ct original proto-dst 443 ct state related ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept", client, p.NamespaceIPv4))
	b.WriteString(line("ct direction != original drop") + line("ct original ip saddr != %s drop", p.NamespaceIPv4))
	if p.Role == "ru" {
		b.WriteString(line("ip daddr %s ct original ip daddr %s ct original protocol tcp ct original proto-dst 443 tcp dport 443 ct state { new, established } accept", p.ForeignIPv4, p.ForeignIPv4))
	} else {
		b.WriteString(line("ip daddr @blocked drop") + line("ct original ip daddr @blocked drop"))
		for _, protocol := range []string{"tcp", "udp"} {
			b.WriteString(line("meta l4proto %s ct original protocol %s ct state { new, established } accept", protocol, protocol))
		}
	}
	b.WriteString(" }\n chain forward { type filter hook forward priority 300; policy drop;\n }\n}\n")
	return b.String()
}
