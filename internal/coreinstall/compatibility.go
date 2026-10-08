package coreinstall

// These versions bind the generated configuration contracts to the installer
// catalogue. They are independent of the portal application's release version.
const (
	XrayVersion     = "26.3.27"
	SingBoxVersion  = "1.14.2"
	HysteriaVersion = "2.13.0"
)

// Compatibility describes the implemented format boundary, not a responding
// core, working route, connected client or readiness permission.
type Compatibility struct {
	Core               string   `json:"core"`
	Version            string   `json:"version"`
	Protocol           string   `json:"protocol"`
	ConfigurationScope string   `json:"configuration_scope"`
	ObservationScope   string   `json:"observation_scope"`
	NativeAcceptance   bool     `json:"native_acceptance"`
	ClientAcceptance   bool     `json:"client_acceptance"`
	Ready              bool     `json:"ready"`
	Blockers           []string `json:"blockers"`
}

// ConfigurationCompatibility returns closed, non-secret facts. Fresh slices
// prevent a caller from altering a later report's limits.
func ConfigurationCompatibility(core string) (Compatibility, error) {
	switch core {
	case "xray":
		return Compatibility{Core: core, Version: XrayVersion, Protocol: "vless-reality", ConfigurationScope: "ru-ingress-and-foreign-primary-templates", ObservationScope: "named-users-partial", Blockers: []string{"NATIVE_CORE_ACCEPTANCE_PENDING", "NATIVE_NETWORK_ISOLATION_ACCEPTANCE_PENDING", "BOUND_CLIENT_ISSUANCE_PENDING", "CLIENT_ACCEPTANCE_PENDING"}}, nil
	case "sing-box":
		return Compatibility{Core: core, Version: SingBoxVersion, Protocol: "vless-reality", ConfigurationScope: "ru-loopback-socks-and-camouflage-relay", ObservationScope: "none", Blockers: []string{"UNPRIVILEGED_CORE_RUNTIME_PENDING", "NATIVE_NETWORK_ISOLATION_ACCEPTANCE_PENDING", "CLIENT_ACCEPTANCE_PENDING"}}, nil
	case "hysteria":
		return Compatibility{Core: core, Version: HysteriaVersion, Protocol: "hysteria2", ConfigurationScope: "none", ObservationScope: "none", Blockers: []string{"BACKUP_CONFIGURATION_PENDING", "BACKUP_TLS_PENDING", "NATIVE_CORE_ACCEPTANCE_PENDING", "CLIENT_ACCEPTANCE_PENDING"}}, nil
	default:
		return Compatibility{}, ErrArguments
	}
}
