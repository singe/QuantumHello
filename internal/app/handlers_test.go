package app

import (
	"net/http/httptest"
	"strings"
	"testing"

	"quantumhello/internal/probe"
)

func TestJSONFilenameSanitizesHost(t *testing.T) {
	if got := jsonFilename("Example.COM:443/evil"); got != "example.com-443-evil" {
		t.Fatalf("got %q", got)
	}
	if got := jsonFilename("!!!"); got != "result" {
		t.Fatalf("got %q", got)
	}
}

func TestWriteJSONResultModes(t *testing.T) {
	result := probe.Result{SchemaVersion: "2", Host: "example.com", Grade: probe.GradeGood}
	for _, tc := range []struct {
		name             string
		pretty, download bool
	}{{"compact", false, false}, {"pretty", true, false}, {"download", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRecorder()
			writeJSONResult(r, result, tc.pretty, tc.download)
			if r.Code != 200 || r.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("response: %d %v", r.Code, r.Header())
			}
			if tc.download && !strings.Contains(r.Header().Get("Content-Disposition"), "quantumhello-example.com.json") {
				t.Fatalf("missing download header: %q", r.Header().Get("Content-Disposition"))
			}
			if tc.pretty && !strings.Contains(r.Body.String(), "\n  \"schema_version\"") {
				t.Fatalf("not pretty JSON: %s", r.Body.String())
			}
		})
	}
}
