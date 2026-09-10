package probe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"time"
)

const (
	defaultMaxIPs    = 4
	defaultDNSBudget = 2 * time.Second
)

var ErrRateLimited = errors.New("rate limited")

type Checker struct {
	cache   *Cache
	limiter *Limiter
	sem     chan struct{}
	maxIPs  int
	roots   *x509.CertPool
}

func NewChecker() *Checker {
	return &Checker{
		cache:   NewCache(),
		limiter: NewLimiter(20, 5),
		sem:     make(chan struct{}, 32),
		maxIPs:  defaultMaxIPs,
	}
}

func (c *Checker) Check(ctx context.Context, input string, clientIP string) (Result, error) {
	target, err := NormalizeInput(input)
	if err != nil {
		result := Result{InputURL: input, Status: StatusInvalidInput}
		summarizeResult(&result)
		return result, nil
	}

	if clientIP == "" {
		clientIP = "unknown"
	}
	if !c.limiter.Allow(clientIP) {
		return Result{}, ErrRateLimited
	}

	if cached, ok := c.cache.Get(target.Host + ":" + target.Port); ok {
		cached.InputURL = input
		return cached, nil
	}

	if err := c.acquire(ctx); err != nil {
		return Result{}, err
	}
	defer c.release()

	result := Result{
		InputURL:   input,
		Normalized: target.Normalized,
		Host:       target.Host,
		Port:       target.Port,
		SNI:        target.SNI,
		ShareURL:   "/?q=" + url.QueryEscape(input),
	}

	dnsCtx, cancel := context.WithTimeout(ctx, defaultDNSBudget)
	safeIPs, warnings, err := ResolvePublicIPs(dnsCtx, target.Host, c.maxIPs)
	cancel()
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			result.Status = StatusTimeout
		case len(safeIPs) == 0 && len(warnings) > 0:
			result.Status = StatusBlockedTarget
		default:
			if isDangerousHostname(target.Host) {
				result.Status = StatusBlockedTarget
			} else {
				result.Status = StatusDNSError
			}
		}
		result.Warnings = append(result.Warnings, warnings...)
		summarizeResult(&result)
		c.cache.Store(target.Host+":"+target.Port, result)
		return result, nil
	}

	result = c.checkResolvedWithWarnings(ctx, input, target, safeIPs, warnings)
	c.cache.Store(target.Host+":"+target.Port, result)
	return result, nil
}

func (c *Checker) acquire(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Checker) release() {
	select {
	case <-c.sem:
	default:
	}
}

func (c *Checker) checkResolved(ctx context.Context, input string, target Target, ips []netip.Addr) Result {
	return c.checkResolvedWithWarnings(ctx, input, target, ips, nil)
}

func (c *Checker) checkResolvedWithWarnings(ctx context.Context, input string, target Target, ips []netip.Addr, warnings []string) Result {
	result := Result{
		InputURL:    input,
		Normalized:  target.Normalized,
		Host:        target.Host,
		Port:        target.Port,
		SNI:         target.SNI,
		ShareURL:    "/?q=" + url.QueryEscape(input),
		ResolvedIPs: make([]string, 0, len(ips)),
	}
	for _, ip := range ips {
		result.ResolvedIPs = append(result.ResolvedIPs, ip.String())
	}
	result.Warnings = append(result.Warnings, warnings...)
	for _, ip := range ips {
		if ip.Is4() {
			result.Network.ResolvedIPv4 = append(result.Network.ResolvedIPv4, ip.String())
		} else if ip.Is6() {
			result.Network.ResolvedIPv6 = append(result.Network.ResolvedIPv6, ip.String())
		}
	}
	representatives := RepresentativeIPs(ips)

	if len(ips) == 0 {
		result.Status = StatusUnknown
		summarizeResult(&result)
		return result
	}

	type outcome struct {
		attempt IPAttempt
		tls12   TLSProbeResult
	}
	outcomes := make(chan outcome, len(representatives))
	for _, ip := range representatives {
		go func(ip netip.Addr) { a, t := c.checkIP(ctx, target, ip); outcomes <- outcome{a, t} }(ip)
	}
	var sawNoTLS13, sawTimeout, sawConnErr, sawCertRetry, sawControlSuccess, sawSupportedPair, sawTLS12 bool
	var supportedControl, supportedPQ TLSProbeResult
	for range representatives {
		o := <-outcomes
		result.IPAttempts = append(result.IPAttempts, o.attempt)
		if o.attempt.Family == "ipv4" {
			result.Network.TestedIPv4 = o.attempt.IP
		} else {
			result.Network.TestedIPv6 = o.attempt.IP
		}
		if o.tls12.Success {
			sawTLS12 = true
			result.TLS12Probe = o.tls12
		}
		control, pq := o.attempt.Control, o.attempt.PQ
		if control.Success {
			sawControlSuccess = true
		}
		if o.attempt.Readiness == "post_quantum_preferred" {
			sawSupportedPair = true
			supportedControl, supportedPQ = control, pq
		}
		if control.InsecureRetryPerformed || pq.InsecureRetryPerformed || o.tls12.InsecureRetryPerformed {
			sawCertRetry = true
		}
		for _, p := range []TLSProbeResult{control, pq, o.tls12} {
			switch p.ErrorClass {
			case "timeout":
				sawTimeout = true
			case "no_tls13":
				sawNoTLS13 = true
			case "connection_error":
				sawConnErr = true
			case "certificate_error":
				sawCertRetry = true
			}
		}
	}
	if len(result.IPAttempts) > 0 {
		result.ControlProbe = result.IPAttempts[0].Control
		result.PQProbe = result.IPAttempts[0].PQ
		result.CheckedIP = result.IPAttempts[0].IP
	}
	if sawCertRetry {
		result.Status = StatusCertError
	} else if sawSupportedPair {
		result.ControlProbe = supportedControl
		result.PQProbe = supportedPQ
		result.Status = StatusSupported
	} else if sawTLS12 {
		result.Status = StatusNotSupported
	} else if sawControlSuccess {
		result.Status = StatusNotSupported
	} else if sawNoTLS13 {
		result.Status = StatusNoTLS13
	} else if sawTimeout {
		result.Status = StatusTimeout
	} else if sawConnErr {
		result.Status = StatusConnectionErr
	} else {
		result.Status = StatusUnknown
	}
	result.Network.Consistency = networkConsistency(result.IPAttempts)
	summarizeResult(&result)
	return result
}

func (c *Checker) checkIP(ctx context.Context, target Target, ip netip.Addr) (IPAttempt, TLSProbeResult) {
	a := IPAttempt{IP: ip.String()}
	if ip.Is4() {
		a.Family = "ipv4"
	} else {
		a.Family = "ipv6"
	}
	a.Control = RunTLSProbe(ctx, target.Host, target.Port, net.IP(ip.AsSlice()), controlConfigWithRoots(target.SNI, c.roots), true)
	if a.Control.Success || a.Control.InsecureRetryPerformed {
		a.PQ = RunTLSProbe(ctx, target.Host, target.Port, net.IP(ip.AsSlice()), pqConfigWithRoots(target.SNI, c.roots), true)
	}
	if !a.Control.Success && !a.Control.InsecureRetryPerformed {
		a.Readiness = "failed"
	} else if isPQHybridCurveName(a.Control.NegotiatedCurve) {
		a.Readiness = "post_quantum_preferred"
	} else if isPQHybridCurveName(a.PQ.NegotiatedCurve) {
		a.Readiness = "post_quantum_supported"
	} else {
		a.Readiness = "post_quantum_unsupported"
	}
	var tls12 TLSProbeResult
	if shouldAttemptTLS12Fallback(a.Control) {
		tls12 = runTLS12Fallback(ctx, target, ip, c.roots)
	}
	return a, tls12
}

func networkConsistency(attempts []IPAttempt) string {
	if len(attempts) < 2 {
		return "single_family"
	}
	if attempts[0].Readiness == "failed" || attempts[1].Readiness == "failed" {
		return "partial"
	}
	if attempts[0].Readiness == attempts[1].Readiness {
		return "consistent"
	}
	return "inconsistent"
}

func (c *Checker) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		MaxIPs int `json:"max_ips"`
	}{
		MaxIPs: c.maxIPs,
	})
}

func shouldAttemptTLS12Fallback(control TLSProbeResult) bool {
	if control.Success {
		return false
	}
	if control.TransportErrorClass == "refused" {
		return false
	}
	return control.ErrorClass == "connection_error" || control.ErrorClass == "no_tls13"
}
