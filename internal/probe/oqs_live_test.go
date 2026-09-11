//go:build live

package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const oqsLiveHost = "test.openquantumsafe.org"

type oqsLivePoint struct {
	Signature string
	KEX       string
	Port      int
}

var oqsLiveRow = regexp.MustCompile(`<tr><td>([^<]+)</td><td>([^<]+)</td><td>([0-9]+)</td>`)

// TestOQSLiveMatrix is deliberately opt-in because it depends on a public
// interoperability service and exercises non-production ports.
func TestOQSLiveMatrix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	points, err := fetchOQSLivePoints(ctx)
	if err != nil {
		t.Fatalf("fetch OQS registry: %v", err)
	}
	if len(points) < 8 {
		t.Fatalf("OQS registry returned too few selected points: %d", len(points))
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", oqsLiveHost)
	if err != nil || len(ips) == 0 {
		t.Fatalf("resolve %s: %v", oqsLiveHost, err)
	}
	ip := ips[0]
	sem := make(chan struct{}, 4)
	for _, point := range points {
		point := point
		t.Run(fmt.Sprintf("%s_%s_%d", point.Signature, point.KEX, point.Port), func(t *testing.T) {
			sem <- struct{}{}
			defer func() { <-sem }()
			probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			cfg := oqsLiveTLSConfig(point.KEX)
			result := RunTLSProbe(probeCtx, oqsLiveHost, strconv.Itoa(point.Port), net.IP(ip.AsSlice()), cfg, false)
			if !result.Success {
				t.Fatalf("handshake failed: class=%s error=%s", result.ErrorClass, result.Error)
			}
			if result.NegotiatedCurve == "" {
				t.Fatal("no negotiated group")
			}
			if len(result.PresentedChain) == 0 {
				t.Fatal("no presented certificate chain")
			}
			leaf := result.PresentedChain[0]
			if leaf.PublicKeyAlgorithm == "" || leaf.PublicKeyAlgorithm == "0" || strings.HasSuffix(leaf.PublicKeyAlgorithm, ":0") {
				t.Fatalf("unparsed leaf public key: %#v", leaf)
			}
			if leaf.SignatureAlgorithm == "" || leaf.SignatureAlgorithm == "0" || strings.HasSuffix(leaf.SignatureAlgorithm, ":0") {
				t.Fatalf("unparsed leaf signature: %#v", leaf)
			}
		})
	}
}

func fetchOQSLivePoints(ctx context.Context) ([]oqsLivePoint, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+oqsLiveHost+"/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	// Go's standard crypto/tls currently interoperates with the classical
	// baselines and ML-DSA points. Experimental OQS signature schemes are
	// intentionally excluded until the client supports their TLS schemes.
	wanted := map[string]bool{"ecdsap256": true, "rsa3072": true, "mldsa44": true, "mldsa65": true, "mldsa87": true}
	selected := make(map[string]oqsLivePoint)
	for _, match := range oqsLiveRow.FindAllStringSubmatch(string(body), -1) {
		port, _ := strconv.Atoi(match[3])
		point := oqsLivePoint{Signature: match[1], KEX: match[2], Port: port}
		if match[2] == "*" && wanted[match[1]] {
			selected[match[1]+"/*"] = point
		}
		if match[1] == "mldsa44" && (match[2] == "X25519MLKEM768" || match[2] == "SecP256r1MLKEM768") {
			selected[match[1]+"/"+match[2]] = point
		}
		if match[1] == "mldsa65" && match[2] == "SecP384r1MLKEM1024" {
			selected[match[1]+"/"+match[2]] = point
		}
	}
	points := make([]oqsLivePoint, 0, len(selected))
	for _, point := range selected {
		points = append(points, point)
	}
	return points, nil
}

func oqsLiveTLSConfig(kex string) *tls.Config {
	curves := defaultCurvePreferences()
	if kex != "*" {
		curves = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}
	}
	return &tls.Config{ServerName: oqsLiveHost, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: curves, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}
}
