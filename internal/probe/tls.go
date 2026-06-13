package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func RunTLSProbe(ctx context.Context, host, port string, ip net.IP, cfg *tls.Config, allowInsecureCertRetry bool) TLSProbeResult {
	if cfg == nil {
		cfg = &tls.Config{}
	}

	result := TLSProbeResult{
		Attempted:        true,
		CertificateValid: true,
		OfferedCurves:    offeredCurveNames(cfg),
	}
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	address := net.JoinHostPort(ip.String(), port)

	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.ErrorClass = classifyNetError(err)
		result.Error = err.Error()
		return result
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, cfg)

	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		if allowInsecureCertRetry && isCertificateError(err) {
			insecure := cfg.Clone()
			insecure.InsecureSkipVerify = true
			insecureRes := RunTLSProbe(ctx, host, port, ip, insecure, false)
			if insecureRes.Success {
				insecureRes.CertificateValid = false
				insecureRes.CertificateError = err.Error()
				insecureRes.InsecureRetryPerformed = true
				return insecureRes
			}
			insecureRes.CertificateValid = false
			insecureRes.CertificateError = err.Error()
			insecureRes.InsecureRetryPerformed = true
			if insecureRes.ErrorClass == "" {
				insecureRes.ErrorClass = "certificate_error"
			}
			return insecureRes
		}

		result.ErrorClass = classifyTLSHandshakeError(err)
		result.Error = err.Error()
		if isCertificateError(err) {
			result.CertificateValid = false
			result.CertificateError = err.Error()
			if result.ErrorClass == "" {
				result.ErrorClass = "certificate_error"
			}
		}
		if isTimeoutError(err) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.ErrorClass = "timeout"
		}
		return result
	}

	state := tlsConn.ConnectionState()
	result.Success = true
	result.TLSVersion = tlsVersionString(state.Version)
	result.NegotiatedCurve = curveName(state.CurveID)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.PeerCertificates = len(state.PeerCertificates)
	return result
}

func controlConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName:       host,
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: defaultCurvePreferences(),
	}
}

func pqConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName:       host,
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}
}

func defaultCurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519MLKEM768,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
}

func offeredCurveNames(cfg *tls.Config) []string {
	curves := cfg.CurvePreferences
	if len(curves) == 0 {
		curves = defaultCurvePreferences()
	}
	out := make([]string, 0, len(curves))
	for _, curve := range curves {
		out = append(out, curveName(curve))
	}
	return out
}

func curveName(curve tls.CurveID) string {
	if curve == 0 {
		return ""
	}
	return curve.String()
}

func controlConfigWithRoots(host string, roots *x509.CertPool) *tls.Config {
	cfg := controlConfig(host)
	cfg.RootCAs = roots
	return cfg
}

func pqConfigWithRoots(host string, roots *x509.CertPool) *tls.Config {
	cfg := pqConfig(host)
	cfg.RootCAs = roots
	return cfg
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func classifyNetError(err error) string {
	if err == nil {
		return ""
	}
	if isTimeoutError(err) {
		return "timeout"
	}
	return "connection_error"
}

func classifyTLSHandshakeError(err error) string {
	if err == nil {
		return ""
	}
	if isTimeoutError(err) {
		return "timeout"
	}
	if isCertificateError(err) {
		return "certificate_error"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "protocol version"),
		strings.Contains(msg, "no supported versions"),
		strings.Contains(msg, "tls: version not supported"),
		strings.Contains(msg, "tls alert protocol version"),
		strings.Contains(msg, "alert protocol version"):
		return "no_tls13"
	}
	return "connection_error"
}

func isCertificateError(err error) bool {
	if err == nil {
		return false
	}
	var (
		x509Err *x509.CertificateInvalidError
		nameErr *x509.HostnameError
		unkErr  x509.UnknownAuthorityError
	)
	if errors.As(err, &x509Err) || errors.As(err, &nameErr) || errors.As(err, &unkErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "certificate") || strings.Contains(msg, "x509")
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}
