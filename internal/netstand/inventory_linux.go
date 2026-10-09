//go:build linux

package netstand

import (
	"context"
	"familyvpn.local/platform/internal/netguard"
	"io"
	"os"
)

func collectInventory(ctx context.Context, t Target, tools map[string]*pinnedTool) (netguard.Inventory, error) {
	var v netguard.Inventory
	read := func(tool string, args ...string) ([]byte, error) { return runTool(ctx, t, tools[tool], args) }
	links, e := read("ip", "-j", "-d", "link", "show")
	if e != nil {
		return v, e
	}
	if _, v.Interfaces, e = kernelLinks(links); e != nil {
		return v, e
	}
	if len(v.Interfaces) >= 256 {
		return v, ErrInventory
	}
	addresses, e := read("ip", "-j", "address", "show")
	if e != nil {
		return v, e
	}
	if v.Addresses, e = parseAddresses(addresses); e != nil {
		return v, e
	}
	routes, e := read("ip", "-j", "-4", "-N", "route", "show", "table", "all")
	if e != nil {
		return v, e
	}
	if v.Routes, e = parseRoutes(routes); e != nil {
		return v, e
	}
	rules, e := read("ip", "-j", "-4", "-N", "rule", "show")
	if e != nil || parsePolicyRules(rules) != nil {
		return v, ErrInventory
	}
	names, e := read("ip", "netns", "list")
	if e != nil {
		return v, e
	}
	existing, e := parseNamespaces(names)
	if e != nil || existing {
		return v, ErrInventory
	}
	if noNamespaceOverrides() != nil {
		return v, ErrProtected
	}
	tables, e := read("nft", "-j", "list", "tables")
	if e != nil {
		return v, e
	}
	existing, e = ownedTables(tables)
	if e != nil || existing {
		return v, ErrInventory
	}
	data, e := read("sysctl", "-n", "net.ipv4.ip_forward")
	if e != nil {
		return v, e
	}
	if v.IPv4Forwarding, e = forwarding(data); e != nil {
		return v, e
	}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, e := os.Open(path)
		if e != nil {
			return v, ErrInventory
		}
		data, e := io.ReadAll(io.LimitReader(f, 1024*1024+1))
		f.Close()
		if e != nil || port443Free(data) != nil {
			return v, ErrInventory
		}
	}
	r := &nativeRunner{target: t, tools: tools}
	if r.verifyTC(ctx, "host", v.Interfaces) != nil {
		return v, ErrInventory
	}
	return v, nil
}
