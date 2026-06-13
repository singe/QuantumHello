package probe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
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

	for _, ip := range safeIPs {
		result.ResolvedIPs = append(result.ResolvedIPs, ip.String())
	}
	result.Warnings = append(result.Warnings, warnings...)

	attempts := make([]IPAttempt, 0, len(safeIPs))
	var sawNoTLS13 bool
	var sawTimeout bool
	var sawConnErr bool
	var sawPQSuccess bool
	var sawControlSuccess bool
	var sawCertRetry bool

	for i, ip := range safeIPs {
		if i >= c.maxIPs {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Only the first %d safe addresses were tested", c.maxIPs))
			break
		}

		attempt := IPAttempt{IP: ip.String()}
		control := RunTLSProbe(ctx, target.Host, target.Port, net.IP(ip.AsSlice()), controlConfigWithRoots(target.SNI, c.roots), true)
		attempt.Control = control
		if control.Success {
			sawControlSuccess = true
		}
		if control.InsecureRetryPerformed {
			sawCertRetry = true
		}
		switch control.ErrorClass {
		case "timeout":
			sawTimeout = true
		case "no_tls13":
			sawNoTLS13 = true
		case "connection_error":
			sawConnErr = true
		case "certificate_error":
			sawCertRetry = true
		}

		if !control.Success && (control.ErrorClass == "connection_error" || control.ErrorClass == "no_tls13") {
			tls12 := runTLS12Fallback(ctx, target, ip, c.roots)
			result.TLS12Probe = tls12
			if tls12.Success {
				result.Status = StatusNotSupported
				result.ControlProbe = control
				result.TLS12Probe = tls12
				attempts = append(attempts, attempt)
				result.IPAttempts = append(result.IPAttempts, attempts...)
				attachDetails(&result, attempts)
				summarizeResult(&result)
				c.cache.Store(target.Host+":"+target.Port, result)
				return result, nil
			}
			switch tls12.ErrorClass {
			case "timeout":
				sawTimeout = true
			case "connection_error":
				sawConnErr = true
			case "certificate_error":
				sawCertRetry = true
			case "no_tls13":
				sawNoTLS13 = true
			}
		}

		if control.Success || control.InsecureRetryPerformed {
			pq := RunTLSProbe(ctx, target.Host, target.Port, net.IP(ip.AsSlice()), pqConfigWithRoots(target.SNI, c.roots), true)
			attempt.PQ = pq
			if pq.Success {
				sawPQSuccess = true
			}
			if pq.InsecureRetryPerformed {
				sawCertRetry = true
			}
			switch pq.ErrorClass {
			case "timeout":
				sawTimeout = true
			case "no_tls13":
				sawNoTLS13 = true
			case "connection_error":
				sawConnErr = true
			case "certificate_error":
				sawCertRetry = true
			}
			attempts = append(attempts, attempt)
			if pq.Success {
				result.ControlProbe = control
				result.PQProbe = pq
				result.IPAttempts = append(result.IPAttempts, attempts...)
				if sawCertRetry {
					result.Status = StatusCertError
				} else if sawControlSuccess && sawPQSuccess {
					result.Status = StatusSupported
				} else {
					result.Status = StatusSupported
				}
				summarizeResult(&result)
				c.cache.Store(target.Host+":"+target.Port, result)
				return result, nil
			}
			continue
		}

		attempts = append(attempts, attempt)
	}

	result.IPAttempts = append(result.IPAttempts, attempts...)
	attachDetails(&result, attempts)
	if sawCertRetry {
		result.Status = StatusCertError
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
	summarizeResult(&result)
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
	result := Result{
		InputURL:    input,
		Normalized:  target.Normalized,
		Host:        target.Host,
		Port:        target.Port,
		SNI:         target.SNI,
		ResolvedIPs: make([]string, 0, len(ips)),
	}
	for _, ip := range ips {
		result.ResolvedIPs = append(result.ResolvedIPs, ip.String())
	}

	attempts := make([]IPAttempt, 0, len(ips))
	var sawNoTLS13 bool
	var sawTimeout bool
	var sawConnErr bool
	var sawPQSuccess bool
	var sawControlSuccess bool
	var sawCertRetry bool

	for i, ip := range ips {
		if i >= c.maxIPs {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Only the first %d safe addresses were tested", c.maxIPs))
			break
		}
		attempt := IPAttempt{IP: ip.String()}
		control := RunTLSProbe(ctx, target.Host, target.Port, net.IP(ip.AsSlice()), controlConfigWithRoots(target.SNI, c.roots), true)
		attempt.Control = control
		if control.Success {
			sawControlSuccess = true
		}
		if control.InsecureRetryPerformed {
			sawCertRetry = true
		}
		switch control.ErrorClass {
		case "timeout":
			sawTimeout = true
		case "no_tls13":
			sawNoTLS13 = true
		case "connection_error":
			sawConnErr = true
		case "certificate_error":
			sawCertRetry = true
		}
		if control.Success || control.InsecureRetryPerformed {
			pq := RunTLSProbe(ctx, target.Host, target.Port, net.IP(ip.AsSlice()), pqConfigWithRoots(target.SNI, c.roots), true)
			attempt.PQ = pq
			if pq.Success {
				sawPQSuccess = true
			}
			if pq.InsecureRetryPerformed {
				sawCertRetry = true
			}
			switch pq.ErrorClass {
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

		if !control.Success && (control.ErrorClass == "connection_error" || control.ErrorClass == "no_tls13") {
			tls12 := runTLS12Fallback(ctx, target, ip, c.roots)
			result.TLS12Probe = tls12
			if tls12.Success {
				result.Status = StatusNotSupported
				result.ControlProbe = control
				result.TLS12Probe = tls12
				attempts = append(attempts, attempt)
				result.IPAttempts = attempts
				attachDetails(&result, attempts)
				summarizeResult(&result)
				return result
			}
			switch tls12.ErrorClass {
			case "timeout":
				sawTimeout = true
			case "connection_error":
				sawConnErr = true
			case "certificate_error":
				sawCertRetry = true
			case "no_tls13":
				sawNoTLS13 = true
			}
		}
		attempts = append(attempts, attempt)
	}

	result.IPAttempts = attempts
	attachDetails(&result, attempts)
	if sawCertRetry {
		result.Status = StatusCertError
	} else if sawControlSuccess && sawPQSuccess {
		result.Status = StatusSupported
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
	summarizeResult(&result)
	return result
}

func (c *Checker) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		MaxIPs int `json:"max_ips"`
	}{
		MaxIPs: c.maxIPs,
	})
}
