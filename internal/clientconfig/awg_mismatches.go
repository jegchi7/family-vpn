package clientconfig

// ValidAWGMismatchFields is the shared bounded metadata vocabulary for AWG
// comparison and stored diagnostics. It accepts no values, duplicate fields or
// arbitrary backend text. The entire vocabulary can be reported at once.
func ValidAWGMismatchFields(fields []string) bool {
	if fields == nil || len(fields) > 18 {
		return false
	}
	seen := map[string]bool{}
	for _, f := range fields {
		switch f {
		case "endpoint", "server_key", "header_protection", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "randomtrailers", "disablecookies", "address_conflict", "peer_missing", "preshared_key", "peer_addresses", "advanced_security":
		default:
			return false
		}
		if seen[f] {
			return false
		}
		seen[f] = true
	}
	return true
}
