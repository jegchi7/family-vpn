//go:build linux

package netstand

import (
	"bytes"
	"context"
	"io"
	"os"
	"sort"
	"strings"

	"familyvpn.local/platform/internal/netguard"
	"golang.org/x/sys/unix"
)

// Both legacy families are observed independently of nft and alternatives.
// Missing legacy modules do not substitute for the nft ruleset readback.
func legacyNames(ctx context.Context, t Target) ([2][]string, error) {
	var result [2][]string
	if ctx.Err() != nil || scopeCheck(t) != nil {
		return result, ErrInventory
	}
	parent, e := unix.Open("/proc/thread-self/net", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return result, ErrInventory
	}
	defer unix.Close(parent)
	var fs unix.Statfs_t
	var directory unix.Stat_t
	if unix.Fstatfs(parent, &fs) != nil || uint64(fs.Type) != uint64(unix.PROC_SUPER_MAGIC) || unix.Fstat(parent, &directory) != nil || !protectedDir(directory, false) {
		return result, ErrInventory
	}
	for n, name := range []string{"ip_tables_names", "ip6_tables_names"} {
		var before, after unix.Stat_t
		err := unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW)
		if err == unix.ENOENT {
			continue
		}
		if err != nil {
			return result, ErrInventory
		}
		fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if e != nil {
			return result, ErrInventory
		}
		f := os.NewFile(uintptr(fd), "fixed-legacy-table-names")
		valid := unix.Fstat(fd, &after) == nil && forwardingProcIdentity(before, after) && forwardingProcFile(fd, after)
		data, e := io.ReadAll(io.LimitReader(f, 4097))
		valid = valid && unix.Fstatat(parent, name, &after, unix.AT_SYMLINK_NOFOLLOW) == nil && forwardingProcIdentity(before, after)
		f.Close()
		if !valid || e != nil || len(data) > 4096 {
			return result, ErrInventory
		}
		seen := map[string]bool{}
		for _, name := range strings.Split(string(data), "\n") {
			if name == "" {
				continue
			}
			if name != "filter" && name != "nat" && name != "raw" && name != "mangle" && name != "security" || seen[name] {
				return result, ErrInventory
			}
			seen[name] = true
			result[n] = append(result[n], name)
		}
		sort.Strings(result[n])
	}
	var after unix.Stat_t
	if unix.Fstat(parent, &after) != nil || !forwardingProcDirIdentity(directory, after) || scopeCheck(t) != nil || ctx.Err() != nil {
		return result, ErrInventory
	}
	return result, nil
}

func savedNames(data []byte) []string {
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "*") {
			names = append(names, line[1:])
		}
	}
	sort.Strings(names)
	return names
}

func legacyReadback(ctx context.Context, t Target, tools map[string]*pinnedTool, scope netguard.DockerScope) ([2][]byte, error) {
	var saved [2][]byte
	before, e := legacyNames(ctx, t)
	if e != nil || scopeCheck(t) != nil || ctx.Err() != nil {
		return saved, ErrInventory
	}
	tool := tools["xtables-legacy-multi"]
	if tool == nil {
		if len(before[0])+len(before[1]) != 0 {
			return saved, ErrInventory
		}
		return saved, nil
	}
	for n, command := range []string{"iptables-save", "ip6tables-save"} {
		saved[n], e = runTool(ctx, t, tool, []string{command, "-M", netguard.LegacyDisableModuleAutoload})
		family := "ip"
		if n == 1 {
			family = "ip6"
		}
		if e != nil || netguard.RequireScopedIPTables(saved[n], family, scope) != nil || !equalStrings(savedNames(saved[n]), before[n]) {
			return saved, ErrInventory
		}
	}
	after, e := legacyNames(ctx, t)
	if e != nil || !equalStrings(before[0], after[0]) || !equalStrings(before[1], after[1]) || scopeCheck(t) != nil || ctx.Err() != nil {
		return saved, ErrInventory
	}
	return saved, nil
}

func validateDockerBridgeLinks(data []byte, v netguard.Inventory) error {
	links, _, e := kernelLinks(data)
	if e != nil {
		return ErrInventory
	}
	for _, name := range v.Interfaces {
		if name != "docker0" && name != "amn0" {
			continue
		}
		info, ok := links[name].row["linkinfo"].(map[string]any)
		if !ok || info["info_kind"] != "bridge" {
			return ErrInventory
		}
		if _, enslaved := links[name].row["master"]; enslaved {
			return ErrInventory
		}
	}
	return nil
}

func collectCoexistence(ctx context.Context, i netguard.Inputs, t Target, tools map[string]*pinnedTool, v netguard.Inventory, expected *coexistence) (coexistence, error) {
	nft, e := runTool(ctx, t, tools["nft"], []string{"-j", "list", "ruleset"})
	if e != nil {
		return coexistence{}, ErrInventory
	}
	if i.Role != "foreign" {
		names, e := legacyNames(ctx, t)
		if e != nil || len(names[0])+len(names[1]) != 0 || netguard.RequireNoUnownedPacketRewrite(nft) != nil {
			return coexistence{}, ErrInventory
		}
		return coexistence{}, nil
	}
	scope, e := netguard.ForeignDockerScope(i, v)
	if e != nil {
		return coexistence{}, ErrInventory
	}
	links, e := runTool(ctx, t, tools["ip"], []string{"-j", "-d", "link", "show"})
	if e != nil || validateDockerBridgeLinks(links, v) != nil {
		return coexistence{}, ErrInventory
	}
	saved, e := legacyReadback(ctx, t, tools, scope)
	if e != nil {
		return coexistence{}, ErrInventory
	}
	c := coexistence{}
	if expected != nil {
		c.LegacyForward, c.NFTForward = expected.LegacyForward, expected.NFTForward
	}
	if expected == nil {
		c.NFTForward, e = netguard.NFTForwardingNeedsGuard(nft, scope)
		if e != nil {
			return c, ErrInventory
		}
		if t.XTLegacySHA256 != "" {
			c.LegacyForward, e = netguard.LegacyForwardingNeedsGuard(saved[0], scope)
			if e != nil {
				return c, ErrInventory
			}
		}
	}
	c.NFTSHA256, e = netguard.NFTPolicySHA256(nft, scope, c.NFTForward && expected != nil)
	if e != nil {
		return c, ErrInventory
	}
	if t.XTLegacySHA256 != "" {
		c.LegacySHA256, e = netguard.LegacyPolicySHA256(saved[0], "ip", scope, c.LegacyForward && expected != nil)
		if e != nil {
			return c, ErrInventory
		}
		c.LegacyIPv6SHA256, e = netguard.LegacyPolicySHA256(saved[1], "ip6", scope, false)
		if e != nil {
			return c, ErrInventory
		}
	}
	if c.valid(i, t) != nil || expected != nil && c != *expected {
		return c, ErrInventory
	}
	return c, nil
}

// The shared-chain inserts happen with the owned veth still DOWN. Check both
// independently owned firewall layers before each fixed insertion. Full shared
// policy/topology/readback is mandatory before the first activation.
func (r *nativeRunner) guardInsertion(ctx context.Context, p netguard.Plan) error {
	for _, scope := range []string{"host", netguard.Namespace} {
		data, e := r.read(ctx, scope, "nft", "-j", "list", "ruleset")
		if e != nil || netguard.VerifyNFTReadback(p, scope, data) != nil {
			return ErrGuardProof
		}
	}
	for _, q := range []struct{ scope, name string }{{"host", netguard.HostVeth}, {netguard.Namespace, netguard.NamespaceVeth}} {
		data, e := r.read(ctx, q.scope, "ip", "-j", "-d", "link", "show")
		if e != nil {
			return ErrGuardProof
		}
		links, _, e := kernelLinks(data)
		l, found := links[q.name]
		if e != nil || !found || l.up || ownedLink(l, false, false) != nil {
			return ErrGuardProof
		}
	}
	if ctx.Err() != nil || scopeCheck(r.target) != nil {
		return ErrGuardProof
	}
	return nil
}

func ownedForwardInsertion(s netguard.Step, c coexistence) bool {
	for _, item := range []struct {
		need    bool
		backend string
	}{{c.LegacyForward, "legacy"}, {c.NFTForward, "nft"}} {
		if !item.need {
			continue
		}
		steps, e := netguard.DockerForwardInsertions(item.backend)
		if e != nil {
			return false
		}
		for _, want := range steps {
			if s.Scope == want.Scope && s.Executable == want.Executable && equalStrings(s.Args, want.Args) && bytes.Equal(s.Stdin, want.Stdin) {
				return true
			}
		}
	}
	return false
}
