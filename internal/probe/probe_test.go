package probe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeInput(t *testing.T) {
	tests := []struct {
		in   string
		host string
		port string
		ok   bool
	}{
		{"example.com", "example.com", "443", true},
		{"https://example.com:443/path?q=1", "example.com", "443", true},
		{"https://EXAMPLE.com.", "example.com", "443", true},
		{"http://example.com", "", "", false},
		{"https://user@example.com", "", "", false},
		{"localhost", "", "", false},
		{"127.0.0.1", "", "", false},
		{"https://[::1]", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizeInput(tt.in)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error")
			}
			if tt.ok {
				if got.Host != tt.host || got.Port != tt.port {
					t.Fatalf("got %#v", got)
				}
			}
		})
	}
}

func TestBlockedAddr(t *testing.T) {
	cases := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "fd00:ec2::254"}
	for _, c := range cases {
		addr, _ := netip.ParseAddr(c)
		if !isBlockedAddr(addr) {
			t.Fatalf("%s should be blocked", c)
		}
	}
}

func TestCacheExpiry(t *testing.T) {
	c := NewCache()
	r := Result{Status: StatusSupported}
	c.StoreWithTTL("k", r, 10*time.Millisecond)
	if _, ok := c.Get("k"); !ok {
		t.Fatalf("expected cache hit")
	}
	time.Sleep(25 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Fatalf("expected cache expiry")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(60, 2)
	if !l.Allow("a") || !l.Allow("a") {
		t.Fatal("expected initial burst")
	}
	if l.Allow("a") {
		t.Fatal("expected limiter to block")
	}
}

func TestCurvePreferences(t *testing.T) {
	wantControl := []string{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519", "CurveP256", "CurveP384", "CurveP521"}
	if got := offeredCurveNames(controlConfig("example.com")); !sameStrings(got, wantControl) {
		t.Fatalf("control curve order mismatch:\n got: %#v\nwant: %#v", got, wantControl)
	}

	wantPQ := []string{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}
	if got := offeredCurveNames(pqConfig("example.com")); !sameStrings(got, wantPQ) {
		t.Fatalf("pq curve order mismatch:\n got: %#v\nwant: %#v", got, wantPQ)
	}
}

func TestPQHybridSupportPair(t *testing.T) {
	control := TLSProbeResult{NegotiatedCurve: tls.SecP256r1MLKEM768.String()}
	pq := TLSProbeResult{NegotiatedCurve: tls.SecP384r1MLKEM1024.String()}
	if !supportsPQHybridPair(control, pq) {
		t.Fatalf("expected mixed ML-KEM hybrids to count as supported")
	}

	control = TLSProbeResult{NegotiatedCurve: tls.X25519.String()}
	if supportsPQHybridPair(control, pq) {
		t.Fatalf("expected classic curve to not count as supported")
	}
}

func TestShouldAttemptTLS12Fallback(t *testing.T) {
	if shouldAttemptTLS12Fallback(TLSProbeResult{ErrorClass: "connection_error", TransportErrorClass: "refused"}) {
		t.Fatalf("expected refused ports to skip TLS 1.2 fallback")
	}
	if !shouldAttemptTLS12Fallback(TLSProbeResult{ErrorClass: "connection_error"}) {
		t.Fatalf("expected handshake failures to try TLS 1.2 fallback")
	}
	if !shouldAttemptTLS12Fallback(TLSProbeResult{ErrorClass: "no_tls13"}) {
		t.Fatalf("expected no_tls13 to try TLS 1.2 fallback")
	}
}

func TestCheckerScansSupportedAndNotSupported(t *testing.T) {
	supportedHost, supportedPort, supportedIP, supportedRoots, supportedCleanup := startTLSServer(t, []tls.CurveID{tls.SecP384r1MLKEM1024}, tls.VersionTLS13, tls.VersionTLS13)
	defer supportedCleanup()

	unsupportedHost, unsupportedPort, unsupportedIP, unsupportedRoots, unsupportedCleanup := startTLSServer(t, []tls.CurveID{tls.X25519}, tls.VersionTLS13, tls.VersionTLS13)
	defer unsupportedCleanup()

	checker := NewChecker()
	checker.limiter = NewLimiter(1000, 1000)

	ctx := context.Background()
	checker.roots = supportedRoots
	supported := checker.checkResolved(ctx, "https://example.com", Target{Normalized: "https://example.com:" + supportedPort, Host: supportedHost, Port: supportedPort, SNI: supportedHost}, []netip.Addr{supportedIP})
	if supported.Status != StatusSupported {
		t.Fatalf("expected supported, got %s (%s)", supported.Status, supported.Summary)
	}

	checker.roots = unsupportedRoots
	notSupported := checker.checkResolved(ctx, "https://example.com", Target{Normalized: "https://example.com:" + unsupportedPort, Host: unsupportedHost, Port: unsupportedPort, SNI: unsupportedHost}, []netip.Addr{unsupportedIP})
	if notSupported.Status != StatusNotSupported {
		t.Fatalf("expected not_supported, got %s (%s)", notSupported.Status, notSupported.Summary)
	}
}

func TestCheckerUsesOnlyFirstResolvedIP(t *testing.T) {
	supportedHost, supportedPort, supportedIP, supportedRoots, supportedCleanup := startTLSServer(t, []tls.CurveID{tls.SecP256r1MLKEM768}, tls.VersionTLS13, tls.VersionTLS13)
	defer supportedCleanup()

	checker := NewChecker()
	checker.limiter = NewLimiter(1000, 1000)
	checker.roots = supportedRoots

	ctx := context.Background()
	result := checker.checkResolved(ctx, "https://example.com", Target{Normalized: "https://example.com:" + supportedPort, Host: supportedHost, Port: supportedPort, SNI: supportedHost}, []netip.Addr{supportedIP, netip.MustParseAddr("203.0.113.1")})
	if result.Status != StatusSupported {
		t.Fatalf("expected supported, got %s (%s)", result.Status, result.Summary)
	}
	if result.CheckedIP != supportedIP.String() {
		t.Fatalf("expected checked ip %s, got %s", supportedIP.String(), result.CheckedIP)
	}
	if len(result.IPAttempts) != 1 {
		t.Fatalf("expected only one IP attempt, got %d", len(result.IPAttempts))
	}
	foundWarning := false
	for _, warning := range result.Warnings {
		if warning == "Multiple safe addresses were resolved; only the first safe address was checked" {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("expected multi-IP warning, got %#v", result.Warnings)
	}
}

func TestResultJSONOmitsIPAttempts(t *testing.T) {
	b, err := json.Marshal(Result{
		Status:     StatusSupported,
		CheckedIP:  "203.0.113.10",
		IPAttempts: []IPAttempt{{IP: "203.0.113.10"}},
	})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if strings.Contains(string(b), "ip_attempts") {
		t.Fatalf("expected ip_attempts to be omitted from json, got %s", string(b))
	}
}

func TestCheckerCertErrorAndNoTLS13(t *testing.T) {
	certHost, certPort, certIP, certRoots, certCleanup := startTLSServer(t, []tls.CurveID{tls.X25519MLKEM768}, tls.VersionTLS13, tls.VersionTLS13)
	defer certCleanup()

	noTLSHost, noTLSPort, noTLSIP, noTLSRoots, noTLSCleanup := startTLSServer(t, []tls.CurveID{tls.X25519}, tls.VersionTLS12, tls.VersionTLS12)
	defer noTLSCleanup()

	checker := NewChecker()
	checker.limiter = NewLimiter(1000, 1000)

	ctx := context.Background()
	_ = certRoots
	checker.roots = nil
	certErr := checker.checkResolved(ctx, "https://example.com", Target{Normalized: "https://example.com:" + certPort, Host: certHost, Port: certPort, SNI: certHost}, []netip.Addr{certIP})
	if certErr.Status != StatusCertError {
		t.Fatalf("expected cert_error, got %s (%s)", certErr.Status, certErr.Summary)
	}

	checker.roots = noTLSRoots
	noTLS := checker.checkResolved(ctx, "https://example.com", Target{Normalized: "https://example.com:" + noTLSPort, Host: noTLSHost, Port: noTLSPort, SNI: noTLSHost}, []netip.Addr{noTLSIP})
	if noTLS.Status != StatusNotSupported {
		t.Fatalf("expected not_supported, got %s (%s)", noTLS.Status, noTLS.Summary)
	}
	if !noTLS.TLS12Probe.Success {
		t.Fatalf("expected tls1.2 fallback success, got %#v", noTLS.TLS12Probe)
	}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func startTLSServer(t *testing.T, curves []tls.CurveID, minVersion uint16, maxVersion uint16) (string, string, netip.Addr, *x509.CertPool, func()) {
	t.Helper()
	cert, pool := selfSignedCert(t, "example.com")
	cfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       minVersion,
		MaxVersion:       maxVersion,
		CurvePreferences: curves,
	}
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", addr.String(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_ = c.(*tls.Conn).Handshake()
			}(conn)
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	ip := netip.MustParseAddr("127.0.0.1")
	return "example.com", fmt.Sprintf("%d", tcpAddr.Port), ip, pool, func() {
		_ = ln.Close()
		<-done
		wg.Wait()
	}
}

func selfSignedCert(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cert, pool
}
