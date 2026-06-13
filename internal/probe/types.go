package probe

type Status string

const (
	StatusSupported     Status = "supported"
	StatusNotSupported  Status = "not_supported"
	StatusNoTLS13       Status = "no_tls13"
	StatusConnectionErr Status = "connection_error"
	StatusDNSError      Status = "dns_error"
	StatusInvalidInput  Status = "invalid_input"
	StatusBlockedTarget Status = "blocked_target"
	StatusCertError     Status = "cert_error"
	StatusTimeout       Status = "timeout"
	StatusUnknown       Status = "unknown"
)

type Target struct {
	Normalized string `json:"normalized"`
	Host       string `json:"host"`
	Port       string `json:"port"`
	SNI        string `json:"sni"`
}

type Result struct {
	InputURL    string   `json:"input_url"`
	Normalized  string   `json:"normalized"`
	Host        string   `json:"host"`
	Port        string   `json:"port"`
	SNI         string   `json:"sni"`
	ShareURL    string   `json:"share_url,omitempty"`
	ResolvedIPs []string `json:"resolved_ips"`
	Status      Status   `json:"status"`
	Summary     string   `json:"summary"`

	ControlProbe TLSProbeResult `json:"control_probe"`
	TLS12Probe   TLSProbeResult `json:"tls12_probe,omitempty"`
	PQProbe      TLSProbeResult `json:"pq_probe"`
	IPAttempts   []IPAttempt    `json:"ip_attempts,omitempty"`
	Warnings     []string       `json:"warnings,omitempty"`
}

type IPAttempt struct {
	IP      string         `json:"ip"`
	Control TLSProbeResult `json:"control_probe"`
	PQ      TLSProbeResult `json:"pq_probe"`
}

type TLSProbeResult struct {
	Attempted              bool     `json:"attempted"`
	Success                bool     `json:"success"`
	TLSVersion             string   `json:"tls_version,omitempty"`
	OfferedCurves          []string `json:"offered_curves,omitempty"`
	NegotiatedCurve        string   `json:"negotiated_curve,omitempty"`
	CipherSuite            string   `json:"cipher_suite,omitempty"`
	PeerCertificates       int      `json:"peer_certificates,omitempty"`
	CertificateValid       bool     `json:"certificate_valid"`
	CertificateError       string   `json:"certificate_error,omitempty"`
	ErrorClass             string   `json:"error_class,omitempty"`
	Error                  string   `json:"error,omitempty"`
	InsecureRetryPerformed bool     `json:"insecure_retry_performed"`
}
