package probe

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

func NormalizeInput(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, errors.New("empty input")
	}

	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "https" {
		return Target{}, errors.New("only https URLs are allowed")
	}
	if u.User != nil {
		return Target{}, errors.New("userinfo is not allowed")
	}
	if u.Fragment != "" {
		return Target{}, errors.New("fragments are not allowed")
	}
	if u.Host == "" {
		return Target{}, errors.New("missing host")
	}

	host := u.Hostname()
	if host == "" {
		return Target{}, errors.New("missing host")
	}

	if ip := net.ParseIP(host); ip != nil {
		return Target{}, errors.New("please enter a hostname rather than an IP address")
	}

	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return Target{}, fmt.Errorf("convert host to ASCII: %w", err)
	}
	ascii = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ascii)), ".")
	if ascii == "" {
		return Target{}, errors.New("missing host")
	}
	if isDangerousHostname(ascii) {
		return Target{}, errors.New("host is blocked by safety policy")
	}
	if !strings.Contains(ascii, ".") {
		return Target{}, errors.New("host must be a public domain name")
	}

	port := u.Port()
	if port == "" {
		port = "443"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return Target{}, errors.New("invalid port")
	}
	if port != "443" {
		return Target{}, errors.New("only port 443 is allowed")
	}

	normalized := "https://" + net.JoinHostPort(ascii, port)
	return Target{
		Normalized: normalized,
		Host:       ascii,
		Port:       port,
		SNI:        ascii,
	}, nil
}

func isDangerousHostname(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || host == "localhost.localdomain" {
		return true
	}
	return strings.HasSuffix(host, ".localhost")
}
