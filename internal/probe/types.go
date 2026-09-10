package probe

type Grade string

const (
	GradeExcellent Grade = "excellent"
	GradeGood      Grade = "good"
	GradeFair      Grade = "fair"
	GradeBad       Grade = "bad"
	GradeFailed    Grade = "failed"
)

type DimensionAssessment struct {
	State   string `json:"state"`
	Label   string `json:"label"`
	Summary string `json:"summary"`
}

type Assessment struct {
	Grade            Grade               `json:"grade"`
	Headline         string              `json:"headline"`
	Explanation      string              `json:"explanation"`
	HNDLProtected    bool                `json:"hndl_protected"`
	KeyEstablishment DimensionAssessment `json:"key_establishment"`
	Authentication   DimensionAssessment `json:"authentication"`
	CertificateChain DimensionAssessment `json:"certificate_chain"`
	Deployment       DimensionAssessment `json:"deployment"`
	TLSBaseline      DimensionAssessment `json:"tls_baseline"`
	Reasons          []string            `json:"reasons,omitempty"`
}

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
	SchemaVersion string        `json:"schema_version"`
	InputURL      string        `json:"input_url"`
	Normalized    string        `json:"normalized"`
	Host          string        `json:"host"`
	Port          string        `json:"port"`
	SNI           string        `json:"sni"`
	ShareURL      string        `json:"share_url,omitempty"`
	ResolvedIPs   []string      `json:"resolved_ips"`
	CheckedIP     string        `json:"checked_ip,omitempty"`
	Network       NetworkResult `json:"network"`
	Status        Status        `json:"status"`
	Summary       string        `json:"summary"`
	Grade         Grade         `json:"grade"`
	Assessment    Assessment    `json:"assessment"`

	ControlProbe TLSProbeResult `json:"control_probe"`
	TLS12Probe   TLSProbeResult `json:"tls12_probe,omitempty"`
	PQProbe      TLSProbeResult `json:"pq_probe"`
	IPAttempts   []IPAttempt    `json:"-"`
	Warnings     []string       `json:"warnings,omitempty"`
}

type IPAttempt struct {
	IP        string         `json:"ip"`
	Family    string         `json:"family"`
	Readiness string         `json:"readiness,omitempty"`
	Control   TLSProbeResult `json:"control_probe"`
	PQ        TLSProbeResult `json:"pq_probe"`
}

type NetworkResult struct {
	ResolvedIPv4 []string `json:"resolved_ipv4,omitempty"`
	ResolvedIPv6 []string `json:"resolved_ipv6,omitempty"`
	TestedIPv4   string   `json:"tested_ipv4,omitempty"`
	TestedIPv6   string   `json:"tested_ipv6,omitempty"`
	Consistency  string   `json:"consistency"`
}

type TLSProbeResult struct {
	Attempted              bool                     `json:"attempted"`
	Success                bool                     `json:"success"`
	TLSVersion             string                   `json:"tls_version,omitempty"`
	OfferedCurves          []string                 `json:"offered_curves,omitempty"`
	NegotiatedCurve        string                   `json:"negotiated_curve,omitempty"`
	CipherSuite            string                   `json:"cipher_suite,omitempty"`
	ALPN                   string                   `json:"alpn,omitempty"`
	HelloRetryRequest      bool                     `json:"hello_retry_request"`
	OCSPStapled            bool                     `json:"ocsp_stapled"`
	SCTCount               int                      `json:"sct_count,omitempty"`
	PeerCertificates       int                      `json:"peer_certificates,omitempty"`
	PresentedChain         []CertificateObservation `json:"presented_chain,omitempty"`
	VerifiedChain          []CertificateObservation `json:"verified_chain,omitempty"`
	CertificateValid       bool                     `json:"certificate_valid"`
	CertificateError       string                   `json:"certificate_error,omitempty"`
	TransportErrorClass    string                   `json:"transport_error_class,omitempty"`
	ErrorClass             string                   `json:"error_class,omitempty"`
	Error                  string                   `json:"error,omitempty"`
	InsecureRetryPerformed bool                     `json:"insecure_retry_performed"`
}

type CertificateObservation struct {
	Position             int      `json:"position"`
	Role                 string   `json:"role"`
	Subject              string   `json:"subject"`
	Issuer               string   `json:"issuer"`
	PublicKeyAlgorithm   string   `json:"public_key_algorithm"`
	PublicKeyDetails     string   `json:"public_key_details,omitempty"`
	PublicKeyPostQuantum bool     `json:"public_key_post_quantum"`
	SignatureAlgorithm   string   `json:"signature_algorithm"`
	SignaturePostQuantum bool     `json:"signature_post_quantum"`
	NotBefore            string   `json:"not_before"`
	NotAfter             string   `json:"not_after"`
	DNSNames             []string `json:"dns_names,omitempty"`
}
