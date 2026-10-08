package netguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func topology(role string) (Inputs, Inventory) {
	i := Inputs{Role: role, RUIPv4: netip.MustParseAddr("45.8.9.10"), ForeignIPv4: netip.MustParseAddr("46.9.10.11"), Transit: netip.MustParsePrefix("10.231.240.0/30"), Uplink: "eth0"}
	i.HostPublicIPv4 = i.RUIPv4
	if role == "foreign" {
		i.HostPublicIPv4 = i.ForeignIPv4
	}
	v := Inventory{Interfaces: []string{"lo", "eth0", "docker0"}, Addresses: []Address{{"lo", netip.MustParsePrefix("127.0.0.1/8")}, {"eth0", netip.PrefixFrom(i.HostPublicIPv4, 24)}, {"docker0", netip.MustParsePrefix("172.17.0.1/16")}}, Routes: []Route{{"eth0", netip.MustParsePrefix("0.0.0.0/0")}, {"eth0", netip.PrefixFrom(i.HostPublicIPv4, 24).Masked()}, {"docker0", netip.MustParsePrefix("172.17.0.0/16")}}}
	return i, v
}
func TestTopologyRejectsUnsafeAddressesAndOverrides(t *testing.T) {
	i, v := topology("ru")
	for _, p := range deniedIPv4 {
		t.Run(p.String(), func(t *testing.T) {
			bad := i
			bad.ForeignIPv4 = p.Addr()
			if !errors.Is(ValidateInputs(bad), ErrInput) {
				t.Fatal("nonpublicForeignaccepted")
			}
		})
	}
	for _, a := range []string{"::1", "2001:db8::1", "::ffff:45.8.9.10"} {
		bad := i
		bad.ForeignIPv4 = netip.MustParseAddr(a)
		if ValidateInputs(bad) == nil {
			t.Fatal("IPv6/mappedaccepted")
		}
	}
	for _, role := range []string{"", "admin", "RU"} {
		bad := i
		bad.Role = role
		if ValidateInputs(bad) == nil {
			t.Fatal("unapprovedrole")
		}
	}
	for _, name := range []string{"lo", HostVeth, NamespaceVeth, "eth0\nflush ruleset", "eth0;drop", "$(id)", "abcdefghijklmnop"} {
		bad := i
		bad.Uplink = name
		if ValidateInputs(bad) == nil {
			t.Fatal("unsafeuplink")
		}
	}
	for _, transit := range []string{"10.1.2.1/30", "10.1.2.0/29", "127.1.2.0/30", "169.254.1.0/30", "100.64.1.0/30", "45.1.2.0/30", "fd00::/126"} {
		bad := i
		bad.Transit = netip.MustParsePrefix(transit)
		if ValidateInputs(bad) == nil {
			t.Fatal("unsafetransit")
		}
	}
	bad := i
	bad.HostPublicIPv4 = i.ForeignIPv4
	if ValidateInputs(bad) == nil {
		t.Fatal("rolepublicmismatch")
	}
	bad = i
	bad.ForeignIPv4 = i.RUIPv4
	if ValidateInputs(bad) == nil {
		t.Fatal("samehop")
	}
	if _, err := Build(i, v); err != nil {
		t.Fatal("explicitdefaulttreatedasoverlap", err)
	}
}

func TestInventoryOverlapDefaultIdentityAndOwnedCollisions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*Inventory)
	}{
		{"connectedoverlap", func(v *Inventory) {
			v.Addresses = append(v.Addresses, Address{"docker0", netip.MustParsePrefix("10.231.240.1/24")})
		}},
		{"routeoverlap", func(v *Inventory) {
			v.Routes = append(v.Routes, Route{"docker0", netip.MustParsePrefix("10.231.0.0/16")})
		}},
		{"defaultrouteabsent", func(v *Inventory) { v.Routes = v.Routes[1:] }},
		{"wrongdefaultuplink", func(v *Inventory) { v.Routes[0].Interface = "docker0" }},
		{"multipledefaults", func(v *Inventory) { v.Routes = append(v.Routes, v.Routes[0]) }},
		{"foreignroutedifferentlink", func(v *Inventory) {
			v.Routes = append(v.Routes, Route{"docker0", netip.MustParsePrefix("46.9.10.11/32")})
		}},
		{"missingpublicidentity", func(v *Inventory) { v.Addresses[1].Prefix = netip.MustParsePrefix("45.8.9.12/24") }},
		{"localForeignalias", func(v *Inventory) {
			v.Addresses = append(v.Addresses, Address{"eth0", netip.MustParsePrefix("46.9.10.11/32")})
		}},
		{"existinghostveth", func(v *Inventory) { v.Interfaces = append(v.Interfaces, HostVeth) }},
		{"existingnsveth", func(v *Inventory) { v.Interfaces = append(v.Interfaces, NamespaceVeth) }},
		{"unknownrouteinterface", func(v *Inventory) { v.Routes[0].Interface = "not-observed" }},
		{"unknownaddressinterface", func(v *Inventory) { v.Addresses[1].Interface = "not-observed" }},
		{"noncanonicalroute", func(v *Inventory) { v.Routes[1].Destination = netip.MustParsePrefix("45.8.9.10/24") }},
		{"duplicateinterface", func(v *Inventory) { v.Interfaces = append(v.Interfaces, "eth0") }},
		{"excessiveinterfaces", func(v *Inventory) { v.Interfaces = make([]string, 257) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, v := topology("ru")
			tc.modify(&v)
			if _, err := Build(i, v); !errors.Is(err, ErrInventory) {
				t.Fatal("inventoryconflictaccepted", err)
			}
		})
	}
}

func TestPlanClosedTablesAndGuardedActivation(t *testing.T) {
	for _, role := range []string{"ru", "foreign"} {
		for _, forwarding := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/forwarding=%v", role, forwarding), func(t *testing.T) {
				i, v := topology(role)
				v.IPv4Forwarding = forwarding
				p, err := Build(i, v)
				if err != nil {
					t.Fatal(err)
				}
				if p.HostIPv4 != "10.231.240.1" || p.NamespaceIPv4 != "10.231.240.2" {
					t.Fatal("transitnotderived")
				}
				for _, forbidden := range []string{"flush ", "delete ", "masquerade", "log ", "counter", "iptables", "DIRECT", "udp dport 443", "tcp dport 22", "tcp dport 8443"} {
					if bytes.Contains(p.HostFirewall, []byte(forbidden)) || bytes.Contains(p.NamespaceFirewall, []byte(forbidden)) {
						t.Fatal("unapprovednetworkoperation")
					}
				}
				if !strings.Contains(string(p.HostFirewall), "table inet "+HostTable) || !strings.Contains(string(p.HostFirewall), "table ip "+NATTable) || !strings.Contains(string(p.NamespaceFirewall), "table inet "+NamespaceTable) {
					t.Fatal("ownedtablesmissing")
				}
				firstUp, lastUp, route, forward := -1, -1, -1, -1
				for n, s := range p.Steps {
					if s.Scope != "host" && s.Scope != Namespace {
						t.Fatal("arbitrarynamespace")
					}
					if s.Executable != IPExecutable && s.Executable != NFTExecutable && s.Executable != SysctlExecutable {
						t.Fatal("arbitraryhelper")
					}
					joined := strings.Join(s.Args, " ")
					if strings.HasPrefix(joined, "link set ") && strings.HasSuffix(joined, " up") {
						if firstUp < 0 {
							firstUp = n
						}
						lastUp = n
					}
					if strings.HasPrefix(joined, "route ") {
						if s.Scope != Namespace || joined != "route add default via 10.231.240.1 dev "+NamespaceVeth {
							t.Fatal("hostroutechanged")
						}
						route = n
					}
					if joined == "-w net.ipv4.ip_forward=1" {
						forward = n
					}
				}
				if len(p.Steps) < 12 || p.Steps[0].Executable != NFTExecutable || p.Steps[0].Scope != "host" || p.Steps[2].Executable != NFTExecutable || p.Steps[2].Scope != Namespace || firstUp <= 3 || route <= lastUp {
					t.Fatal("guard installation must precede activation and the default must follow link UP")
				}
				if forwarding && forward != -1 || !forwarding && (forward <= route || p.Steps[forward+1].Executable != SysctlExecutable) {
					t.Fatal("forwardingbaselineignored")
				}
				encoded, _ := json.Marshal(p.SafeSummary())
				for _, value := range []string{i.RUIPv4.String(), i.ForeignIPv4.String(), "10.231.240.0", `"ready":true`, `"kernel_guard_verified":true`} {
					if bytes.Contains(encoded, []byte(value)) {
						t.Fatal("summarycontainsaddressorattestation")
					}
				}
			})
		}
	}
}

// This deliberately small evaluator exercises the generated closed policy
// dialect as packet predicates. It is a synthetic model, not nft/kernel/native
// acceptance; actual conntrack/NAT/fragment/PMTU tests remain required on Linux.
type packet struct {
	src, dst, originalSrc, originalDst                               netip.Addr
	protocol, originalProtocol, state, direction, iif, oif, icmpType string
	sport, dport, originalDport                                      int
}

func outgoing(p Plan, dst string, protocol string, port int) packet {
	return packet{src: netip.MustParseAddr(p.NamespaceIPv4), dst: netip.MustParseAddr(dst), originalSrc: netip.MustParseAddr(p.NamespaceIPv4), originalDst: netip.MustParseAddr(dst), protocol: protocol, originalProtocol: protocol, state: "new", direction: "original", sport: 49152, dport: port, originalDport: port, iif: HostVeth, oif: NamespaceVeth}
}
func balancedBody(t *testing.T, s, head string) string {
	t.Helper()
	at := strings.Index(s, head)
	if at < 0 {
		t.Fatal("missingpolicybody", head)
	}
	at += len(head)
	depth := 1
	for n := at; n < len(s); n++ {
		if s[n] == '{' {
			depth++
		}
		if s[n] == '}' {
			depth--
			if depth == 0 {
				return s[at:n]
			}
		}
	}
	t.Fatal("unbalancedpolicybody")
	return ""
}

var anonymousSet = regexp.MustCompile(`\{([^{}]+)\}`)

func policyAccepts(t *testing.T, script, table, chain string, p packet, blocked []string) bool {
	t.Helper()
	body := balancedBody(t, script, "table inet "+table+" {")
	body = balancedBody(t, body, "chain "+chain+" {")
	policy := strings.Contains(body, "policy accept;")
	for _, raw := range strings.Split(body, "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "type ") {
			continue
		}
		raw = anonymousSet.ReplaceAllStringFunc(raw, func(s string) string { return strings.ReplaceAll(s, " ", "") })
		tokens := strings.Fields(raw)
		match := true
		for at := 0; at < len(tokens); {
			verb := tokens[at]
			if verb == "accept" || verb == "drop" {
				if match {
					return verb == "accept"
				}
				break
			}
			if verb == "jump" {
				if match {
					return policyAccepts(t, script, table, tokens[at+1], p, blocked)
				}
				break
			}
			var actual string
			switch verb {
			case "iifname":
				actual = p.iif
				at++
			case "oifname":
				actual = p.oif
				at++
			case "meta":
				at++
				switch tokens[at] {
				case "nfproto":
					actual = "ipv6"
					if p.src.Is4() && p.dst.Is4() {
						actual = "ipv4"
					}
				case "l4proto":
					actual = p.protocol
				default:
					t.Fatal("unsupportedmetapredicate")
				}
				at++
			case "ct":
				at++
				switch tokens[at] {
				case "state":
					actual = p.state
					at++
				case "direction":
					actual = p.direction
					at++
				case "original":
					at++
					switch tokens[at] {
					case "protocol":
						actual = p.originalProtocol
						at++
					case "proto-dst":
						actual = strconv.Itoa(p.originalDport)
						at++
					case "ip":
						at++
						if tokens[at] == "saddr" {
							actual = p.originalSrc.String()
						} else if tokens[at] == "daddr" {
							actual = p.originalDst.String()
						} else {
							t.Fatal("unknownctippredicate")
						}
						at++
					default:
						t.Fatal("unknownctoriginalpredicate")
					}
				default:
					t.Fatal("unknownctpredicate")
				}
			case "ip":
				at++
				switch tokens[at] {
				case "saddr":
					actual = p.src.String()
				case "daddr":
					actual = p.dst.String()
				case "protocol":
					actual = p.protocol
				default:
					t.Fatal("unknownippredicate")
				}
				if !p.src.Is4() || !p.dst.Is4() {
					match = false
				}
				at++
			case "tcp":
				if p.protocol != "tcp" {
					match = false
				}
				at++
				if tokens[at] == "sport" {
					actual = strconv.Itoa(p.sport)
				} else if tokens[at] == "dport" {
					actual = strconv.Itoa(p.dport)
				} else {
					t.Fatal("unknowntcppredicate")
				}
				at++
			case "icmp":
				if p.protocol != "icmp" {
					match = false
				}
				at++
				if tokens[at] != "type" {
					t.Fatal("unknownICMPpredicate")
				}
				actual = p.icmpType
				at++
			default:
				t.Fatal("unknownpolicytoken", verb)
			}
			invert := false
			if tokens[at] == "!=" {
				invert = true
				at++
			}
			expected := strings.Trim(tokens[at], `"`)
			at++
			equal := actual == expected
			if expected == "@blocked" {
				equal = false
				a, err := netip.ParseAddr(actual)
				if err != nil {
					t.Fatal("nonaddressblockedpredicate")
				}
				for _, cidr := range blocked {
					if netip.MustParsePrefix(cidr).Contains(a) {
						equal = true
					}
				}
			} else if strings.HasPrefix(expected, "{") {
				equal = false
				for _, value := range strings.Split(strings.Trim(expected, "{}"), ",") {
					if actual == value {
						equal = true
					}
				}
			} else if strings.Contains(expected, "/") {
				a, err := netip.ParseAddr(actual)
				equal = err == nil && netip.MustParsePrefix(expected).Contains(a)
			}
			if invert {
				equal = !equal
			}
			match = match && equal
		}
	}
	return policy
}

func TestRUGeneratedPolicyRejectsDNSUDPIPv6AndNATBypass(t *testing.T) {
	i, v := topology("ru")
	p, err := Build(i, v)
	if err != nil {
		t.Fatal(err)
	}
	blocked := blockedPrefixes(i, v)
	for _, tc := range []struct {
		name, dst, protocol string
		port                int
		allowed             bool
	}{
		{"exactForeign", p.ForeignIPv4, "tcp", 443, true}, {"directHTTPS", "8.8.8.8", "tcp", 443, false}, {"publicDNS", "1.1.1.1", "udp", 53, false}, {"ForeignDNS", p.ForeignIPv4, "udp", 53, false}, {"ForeignUDP", p.ForeignIPv4, "udp", 443, false}, {"ForeignWrongPort", p.ForeignIPv4, "tcp", 8443, false}, {"metadata", "169.254.169.254", "tcp", 80, false}, {"private", "10.0.0.1", "tcp", 443, false}, {"hostmanagement", p.HostPublicIPv4, "tcp", 443, false}, {"IPv6", "2606:4700:4700::1111", "tcp", 443, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := outgoing(p, tc.dst, tc.protocol, tc.port)
			if got := policyAccepts(t, string(p.NamespaceFirewall), NamespaceTable, "output", f, blocked); got != tc.allowed {
				t.Fatal("namespacepolicy", got)
			}
			f.oif = p.Uplink
			if got := policyAccepts(t, string(p.HostFirewall), HostTable, "from_data_forward", f, blocked); got != tc.allowed {
				t.Fatal("hostpolicy", got)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*packet)
	}{
		{"DNATpublic", func(f *packet) { f.dst = netip.MustParseAddr("8.8.8.8") }},
		{"DNATprivate", func(f *packet) { f.dst = netip.MustParseAddr("10.0.0.1") }},
		{"DNATport", func(f *packet) { f.dport = 8443 }},
		{"originaldestinationbypass", func(f *packet) { f.originalDst = netip.MustParseAddr("8.8.8.8") }},
		{"originalportbypass", func(f *packet) { f.originalDport = 53 }},
		{"spoofsource", func(f *packet) { f.src = netip.MustParseAddr("10.231.240.3") }},
		{"wronguplink", func(f *packet) { f.oif = "docker0" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := outgoing(p, p.ForeignIPv4, "tcp", 443)
			f.oif = p.Uplink
			tc.mutate(&f)
			if policyAccepts(t, string(p.HostFirewall), HostTable, "from_data_forward", f, blocked) {
				t.Fatal("NAT/sourcebypassaccepted")
			}
		})
	}
	post := outgoing(p, p.ForeignIPv4, "tcp", 443)
	post.oif = p.Uplink
	post.src = netip.MustParseAddr(p.HostPublicIPv4)
	if !policyAccepts(t, string(p.HostFirewall), HostTable, "from_data_post", post, blocked) {
		t.Fatal("ownedSNATblocked")
	}
	post.dst = netip.MustParseAddr("8.8.8.8")
	if policyAccepts(t, string(p.HostFirewall), HostTable, "from_data_post", post, blocked) {
		t.Fatal("lateDNATbypass")
	}
	loop := outgoing(p, "127.0.0.1", "udp", 52123)
	loop.src = netip.MustParseAddr("127.0.0.1")
	loop.oif = "lo"
	if !policyAccepts(t, string(p.NamespaceFirewall), NamespaceTable, "output", loop, blocked) {
		t.Fatal("localSOCKSUDPassociationblocked")
	}
}

func TestForeignGeneratedPolicyBlocksResolvedPrivateAndManagement(t *testing.T) {
	i, v := topology("foreign")
	v.Addresses = append(v.Addresses, Address{"eth0", netip.MustParsePrefix("46.9.10.12/32")})
	p, err := Build(i, v)
	if err != nil {
		t.Fatal(err)
	}
	blocked := blockedPrefixes(i, v)
	for _, protocol := range []string{"tcp", "udp"} {
		for _, destination := range []struct {
			addr    string
			allowed bool
		}{{"1.1.1.1", true}, {"8.8.8.8", true}, {"169.254.169.254", false}, {"168.63.129.16", false}, {"10.0.0.1", false}, {"172.17.0.1", false}, {"127.0.0.1", false}, {p.RUIPv4, false}, {p.ForeignIPv4, false}, {"46.9.10.12", false}, {"2606:4700:4700::1111", false}} {
			f := outgoing(p, destination.addr, protocol, 53)
			if got := policyAccepts(t, string(p.NamespaceFirewall), NamespaceTable, "output", f, blocked); got != destination.allowed {
				t.Fatal("Foreignnamespacepublicpolicy", protocol, destination.addr, got)
			}
			f.oif = p.Uplink
			if got := policyAccepts(t, string(p.HostFirewall), HostTable, "from_data_forward", f, blocked); got != destination.allowed {
				t.Fatal("Foreignhostpublicpolicy", protocol, destination.addr, got)
			}
		}
	}
	f := outgoing(p, "8.8.8.8", "tcp", 443)
	f.oif = p.Uplink
	f.dst = netip.MustParseAddr("10.0.0.1")
	if policyAccepts(t, string(p.HostFirewall), HostTable, "from_data_forward", f, blocked) {
		t.Fatal("rebinding/DNATactualprivateaccepted")
	}
	f = outgoing(p, "10.0.0.1", "tcp", 443)
	f.oif = p.Uplink
	f.dst = netip.MustParseAddr("8.8.8.8")
	if policyAccepts(t, string(p.HostFirewall), HostTable, "from_data_forward", f, blocked) {
		t.Fatal("originalprivateDNATaccepted")
	}
	f = outgoing(p, "8.8.8.8", "tcp", 443)
	f.protocol = "udp"
	if policyAccepts(t, string(p.NamespaceFirewall), NamespaceTable, "output", f, blocked) {
		t.Fatal("protocolrewriteaccepted")
	}
}

func TestIngressReplyIsolationAndHostForwardBaseline(t *testing.T) {
	for _, role := range []string{"ru", "foreign"} {
		i, v := topology(role)
		p, err := Build(i, v)
		if err != nil {
			t.Fatal(err)
		}
		blocked := blockedPrefixes(i, v)
		client := netip.MustParseAddr("47.10.11.12")
		if role == "foreign" {
			client = i.RUIPv4
		}
		ingress := packet{src: client, dst: netip.MustParseAddr(p.NamespaceIPv4), originalSrc: client, originalDst: i.HostPublicIPv4, protocol: "tcp", originalProtocol: "tcp", state: "new", direction: "original", iif: i.Uplink, oif: HostVeth, sport: 49152, dport: 443, originalDport: 443}
		if !policyAccepts(t, string(p.HostFirewall), HostTable, "to_data", ingress, blocked) {
			t.Fatal("boundedDNATingressblocked", role)
		}
		ingress.dport = 1080
		if policyAccepts(t, string(p.HostFirewall), HostTable, "to_data", ingress, blocked) {
			t.Fatal("openSOCKSforward")
		}
		ingress.dport = 443
		ingress.originalDport = 8443
		if policyAccepts(t, string(p.HostFirewall), HostTable, "to_data", ingress, blocked) {
			t.Fatal("managementDNATbypass")
		}
		ingress.originalDport = 443
		if role == "foreign" {
			ingress.src = netip.MustParseAddr("47.10.11.12")
			ingress.originalSrc = ingress.src
			if policyAccepts(t, string(p.HostFirewall), HostTable, "to_data", ingress, blocked) {
				t.Fatal("nonRUForeigningress")
			}
		}
		reply := packet{src: netip.MustParseAddr(p.NamespaceIPv4), dst: client, originalSrc: client, originalDst: i.HostPublicIPv4, protocol: "tcp", originalProtocol: "tcp", state: "established", direction: "reply", iif: HostVeth, oif: i.Uplink, sport: 443, dport: 49152, originalDport: 443}
		if !policyAccepts(t, string(p.HostFirewall), HostTable, "from_data_forward", reply, blocked) {
			t.Fatal("ingressreplyblocked", role)
		}
		reply.direction = "original"
		if policyAccepts(t, string(p.HostFirewall), HostTable, "from_data_forward", reply, blocked) {
			t.Fatal("newconnectiondisguisedasreply")
		}
		management := outgoing(p, p.HostIPv4, "tcp", 22)
		if policyAccepts(t, string(p.HostFirewall), HostTable, "input", management, blocked) {
			t.Fatal("namespaceaccessSSHallowed")
		}
		other := packet{iif: "docker0", oif: i.Uplink, src: netip.MustParseAddr("172.17.0.2"), dst: netip.MustParseAddr("8.8.8.8")}
		if policyAccepts(t, string(p.HostFirewall), HostTable, "forward", other, blocked) {
			t.Fatal("forwardingenablingunownedflow")
		}
		v.IPv4Forwarding = true
		p, err = Build(i, v)
		if err != nil {
			t.Fatal(err)
		}
		if !policyAccepts(t, string(p.HostFirewall), HostTable, "forward", other, blocked) {
			t.Fatal("existingforwardflowblocked")
		}
	}
}
