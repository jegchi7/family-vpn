//go:build linux

package netstand

import "context"

// This guard permits only ordinary queue disciplines and absence of filters.
// It does not turn local synthetic checks into native packet acceptance.
func (r *nativeRunner) verifyTC(ctx context.Context, scope string, interfaces []string) error {
	q, e := r.read(ctx, scope, "tc", "-j", "qdisc", "show")
	if e != nil || parseQdiscs(q, interfaces) != nil {
		return ErrGuardProof
	}
	for _, name := range interfaces {
		for _, parent := range []string{"ingress", "egress", "root"} {
			f, e := r.read(ctx, scope, "tc", "-j", "filter", "show", "dev", name, parent)
			if e != nil || parseEmptyTCFilters(f) != nil {
				return ErrGuardProof
			}
		}
	}
	return nil
}
