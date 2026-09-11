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
	QueryURL string
	InputURL string
	Result   *probe.Result
}

func parseTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"statusLabel":    statusLabel,
		"statusIcon":     statusIcon,
		"statusHeadline": statusHeadline,
		"pretty":         prettyJSON,
		"prettyProbe":    prettyProbeJSON,
		"gradeLabel":     gradeLabel,
		"gradeIcon":      gradeIcon,
		"dimension":      viewDimension,
	}

	tpl := template.New("").Funcs(funcs)
	files, err := fs.Glob(ui.Assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return tpl.ParseFS(ui.Assets, files...)
}

type DimensionView struct {
	Title    string
	Guidance string
	probe.DimensionAssessment
}

func viewDimension(title string, assessment probe.DimensionAssessment) DimensionView {
	return DimensionView{Title: title, Guidance: dimensionGuidance(title, assessment), DimensionAssessment: assessment}
}

func dimensionGuidance(title string, assessment probe.DimensionAssessment) string {
	switch title {
	case "Key establishment":
		return "Measures how TLS creates shared secrets. This result shows whether a standardized ML-KEM hybrid is used normally; improve by enabling and preferring an RFC 10024 hybrid."
	case "Authentication":
		return "Measures the server certificate's authentication key. This result shows whether that key is post-quantum; the exact TLS CertificateVerify signature is not exposed yet. Improve by deploying a post-quantum authentication key and certificate."
	case "Certificate chain":
		return "Measures the signatures securing the verified certificate path. This result shows whether the chain is classical or post-quantum; improve by using a post-quantum-safe PKI path."
	case "Deployment":
		return "Measures consistency across tested network paths. This result shows whether IPv4 and IPv6 agree; improve by applying the same TLS configuration to every path."
	case "TLS baseline":
		return "Measures basic connection health. This result covers TLS version and certificate validation; improve by serving TLS 1.3 with a valid, trusted certificate."
	default:
		return assessment.Summary
	}
}

func gradeLabel(grade probe.Grade) string {
	if grade == "" {
		return "Assessment"
	}
	return string(grade)
}

func gradeIcon(grade probe.Grade) string {
	switch grade {
	case probe.GradeExcellent:
		return "✓✓"
	case probe.GradeGood:
		return "✓"
	case probe.GradeFair:
		return "!"
	case probe.GradeBad:
		return "✕"
	default:
		return "?"
	}
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

func prettyProbeJSON(checkedIP string, v any) string {
	if checkedIP == "" {
		return prettyJSON(v)
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return prettyJSON(v)
	}

	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return prettyJSON(v)
	}
	data["checked_ip"] = checkedIP

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return prettyJSON(v)
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
