package probe

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
)

func summarizeResult(result *Result) {
	switch result.Status {
	case StatusSupported:
		result.Summary = "The server completed TLS 1.3 handshakes and negotiated supported ML-KEM hybrids on both probes."
	case StatusCertError:
		result.Summary = "The server appears to support the requested handshake, but certificate validation failed."
	case StatusNotSupported:
		if result.TLS12Probe.Success {
			result.Summary = "The server did not negotiate TLS 1.3, but it did complete a TLS 1.2 handshake."
		} else {
			result.Summary = "The server completed TLS 1.3, but the probes did not both negotiate a supported ML-KEM hybrid."
		}
	case StatusNoTLS13:
		result.Summary = "The server did not complete a TLS 1.3 handshake with a normal TLS 1.3 client configuration."
	case StatusBlockedTarget:
		result.Summary = "This hostname resolved to an address range that this checker is not allowed to scan."
	case StatusDNSError:
		result.Summary = "The hostname could not be resolved."
	case StatusInvalidInput:
		result.Summary = "The input was not a valid HTTPS hostname."
	case StatusTimeout:
		result.Summary = "The check timed out before it could complete."
	case StatusConnectionErr:
		result.Summary = "The checker could not complete a TLS probe due to a connection problem."
	default:
		result.Summary = "The checker could not determine ML-KEM hybrid support."
	}
}

func attachDetails(result *Result, attempts []IPAttempt) {
	result.IPAttempts = attempts
	if len(attempts) > 0 {
		result.ControlProbe = attempts[0].Control
		result.PQProbe = attempts[0].PQ
	}
}

func runTLS12Fallback(ctx context.Context, target Target, ip netip.Addr, roots *x509.CertPool) TLSProbeResult {
	return RunTLSProbe(ctx, target.Host, target.Port, net.IP(ip.AsSlice()), controlConfigTLS12WithRoots(target.SNI, roots), false)
}

func appendWarningf(warnings []string, format string, args ...any) []string {
	return append(warnings, fmt.Sprintf(format, args...))
}
