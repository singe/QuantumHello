package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"quantumhello/internal/probe"
	"quantumhello/internal/ui"
)

type Server struct {
	checker *probe.Checker
	tpl     *template.Template
	mux     *http.ServeMux
}

func NewServer(checker *probe.Checker) (*Server, error) {
	tpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}

	s := &Server{
		checker: checker,
		tpl:     tpl,
		mux:     http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.timeoutMiddleware(s.mux))
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.index)
	s.mux.HandleFunc("/favicon.ico", s.favicon)
	s.mux.HandleFunc("/check", s.check)
	s.mux.HandleFunc("/api/check", s.apiCheck)
	s.mux.HandleFunc("/healthz", s.healthz)
	s.mux.HandleFunc("/readyz", s.readyz)
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(staticFS())))
	s.mux.Handle("/images/", http.StripPrefix("/images/", http.FileServer(imagesFS())))
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	page := PageData{}
	if err := s.renderPage(w, page); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}
	input := strings.TrimSpace(r.FormValue("url"))
	if input == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}

	result, err := s.checker.Check(r.Context(), input, clientIP(r))
	if err != nil {
		if errors.Is(err, probe.ErrRateLimited) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isHXRequest(r) {
		if err := s.renderResultFragment(w, &result); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if err := s.renderPage(w, PageData{InputURL: input, Result: &result}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) apiCheck(w http.ResponseWriter, r *http.Request) {
	input := strings.TrimSpace(r.URL.Query().Get("url"))
	if input == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}

	result, err := s.checker.Check(r.Context(), input, clientIP(r))
	if err != nil {
		if errors.Is(err, probe.ErrRateLimited) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (s *Server) favicon(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(ui.Assets, "images/favicon.ico")
	if err != nil {
		http.Error(w, "favicon unavailable", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
	http.ServeContent(w, r, "favicon.ico", time.Now(), bytes.NewReader(data))
}

func (s *Server) renderPage(w http.ResponseWriter, data PageData) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return s.tpl.ExecuteTemplate(w, "base", data)
}

func (s *Server) renderResultFragment(w http.ResponseWriter, result *probe.Result) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return s.tpl.ExecuteTemplate(w, "result_card", result)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func clientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("Fly-Client-IP")); v != "" {
		if ip := net.ParseIP(v); ip != nil {
			return ip.String()
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
		first := strings.TrimSpace(strings.Split(v, ",")[0])
		if ip := net.ParseIP(first); ip != nil {
			if trustedProxy(r.RemoteAddr) {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func trustedProxy(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func isHXRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("HX-Request"), "true")
}
