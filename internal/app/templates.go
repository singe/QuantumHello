package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"sort"

	"quantumhello/internal/probe"
	"quantumhello/internal/ui"
)

type PageData struct {
	InputURL string
	Result   *probe.Result
}

func parseTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"statusLabel":    statusLabel,
		"statusIcon":     statusIcon,
		"statusHeadline": statusHeadline,
		"pretty":         prettyJSON,
	}

	tpl := template.New("").Funcs(funcs)
	files, err := fs.Glob(ui.Assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return tpl.ParseFS(ui.Assets, files...)
}

func statusLabel(status probe.Status) string {
	switch status {
	case probe.StatusSupported:
		return "Supported"
	case probe.StatusCertError:
		return "Certificate issue"
	case probe.StatusNotSupported:
		return "Not supported"
	case probe.StatusNoTLS13:
		return "TLS 1.3 unavailable"
	case probe.StatusDNSError:
		return "DNS error"
	case probe.StatusBlockedTarget:
		return "Blocked target"
	case probe.StatusInvalidInput:
		return "Invalid input"
	case probe.StatusTimeout:
		return "Timeout"
	case probe.StatusConnectionErr:
		return "Connection error"
	default:
		return "Unknown"
	}
}

func statusIcon(status probe.Status) string {
	switch status {
	case probe.StatusSupported:
		return "✓"
	case probe.StatusCertError:
		return "!"
	case probe.StatusNotSupported, probe.StatusNoTLS13, probe.StatusConnectionErr, probe.StatusTimeout:
		return "✕"
	case probe.StatusBlockedTarget, probe.StatusDNSError, probe.StatusInvalidInput:
		return "!"
	default:
		return "?"
	}
}

func statusHeadline(status probe.Status) string {
	switch status {
	case probe.StatusSupported:
		return "Supported"
	case probe.StatusCertError:
		return "Technically supported, but certificate validation failed"
	case probe.StatusNotSupported:
		return "Not supported"
	case probe.StatusNoTLS13:
		return "TLS 1.3 not available"
	case probe.StatusDNSError:
		return "DNS lookup failed"
	case probe.StatusBlockedTarget:
		return "Blocked target"
	case probe.StatusInvalidInput:
		return "Invalid input"
	case probe.StatusTimeout:
		return "Timed out"
	case probe.StatusConnectionErr:
		return "Connection error"
	default:
		return "Unknown"
	}
}

func prettyJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", v)
	}
	return string(b)
}

func renderTemplate(t *template.Template, name string, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
