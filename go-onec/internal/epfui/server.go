// Package epfui serves a local workbench for the observed managed-form subset.
// It never runs scripts, HTML or client modules supplied by 1C.
package epfui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"onec"
	"onec/internal/valueinput"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed web/*
var files embed.FS

type Model struct {
	Snapshot onec.FormSnapshot      `json:"snapshot"`
	Methods  []onec.FormMethodInfo  `json:"methods"`
	Context  *onec.FormContextState `json:"context,omitempty"`
}

type Options struct {
	Origin      string
	Model       Model
	Timeout     time.Duration
	Call        func(context.Context, string, ...onec.Value) (onec.Value, error)
	CallContext func(context.Context, string, uint64, []onec.FormParameter, ...onec.Value) (onec.FormContextResult, error)
}

type Server struct {
	options        Options
	prefix, host   string
	done           chan struct{}
	closed         atomic.Bool
	mu             sync.Mutex
	model          []byte
	modelMu        sync.RWMutex
	modelValue     Model
	allowed        map[string]bool
	contextAllowed map[string]bool
	attempted      atomic.Int64
	confirmed      atomic.Int64
	unconfirmed    atomic.Int64
	recovered      atomic.Int64
}

type Stats struct {
	Attempted       int64 `json:"calls_attempted"`
	Confirmed       int64 `json:"calls_confirmed"`
	Unconfirmed     int64 `json:"calls_failed_or_unconfirmed"`
	RecoveredErrors int64 `json:"context_errors_recovered"`
}

func (s *Server) Stats() Stats {
	return Stats{s.attempted.Load(), s.confirmed.Load(), s.unconfirmed.Load(), s.recovered.Load()}
}

func New(options Options) (*Server, error) {
	u, err := url.Parse(options.Origin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("UI requires a loopback HTTP origin")
	}
	host, port, err := net.SplitHostPort(u.Host)
	p, pe := strconv.Atoi(port)
	if err != nil || pe != nil || host != "127.0.0.1" || p < 1 || p > 65535 {
		return nil, errors.New("UI requires an explicit IPv4 loopback port")
	}
	if options.Call == nil || options.Timeout <= 0 || options.Timeout > 5*time.Minute {
		return nil, errors.New("invalid UI operation options")
	}
	if (options.Model.Context == nil) != (options.CallContext == nil) {
		return nil, errors.New("context state and callback must be supplied together")
	}
	model, err := json.Marshal(options.Model)
	if err != nil || len(model) > 4<<20 {
		return nil, errors.New("unsupported UI model")
	}
	s := &Server{options: options, prefix: "/" + rand.Text() + "/", host: u.Host, done: make(chan struct{}), model: model, allowed: map[string]bool{}, contextAllowed: map[string]bool{}}
	// Keep an owned model: callers cannot mutate the live UI through input slices.
	if err := json.Unmarshal(model, &s.modelValue); err != nil {
		return nil, errors.New("invalid UI model")
	}
	for _, method := range options.Model.Methods {
		if method.Exported && method.Context == "no-context" && method.Kind == "function" {
			s.allowed[method.Name] = true
		}
		if method.Exported && method.Context == "server" && method.Kind == "function" {
			s.contextAllowed[method.Name] = true
		}
	}
	return s, nil
}

// URL is a local capability, separate from all 1C authentication material.
func (s *Server) URL() string { return s.options.Origin + s.prefix }

// Done requests shutdown; it does not acknowledge remote logout. The owner
// must cancel/drain HTTP handlers before releasing the form and 1C session.
func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	if r.Host != s.host || r.URL.RawQuery != "" || !strings.HasPrefix(r.URL.Path, s.prefix) || r.URL.EscapedPath() != r.URL.Path {
		http.NotFound(w, r)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.options.Origin {
		http.Error(w, "origin rejected", http.StatusForbidden)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, s.prefix)
	if path == "api/call" || path == "api/context-call" || path == "api/close" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "POST required", 405)
			return
		}
		if r.Header.Get("Origin") != s.options.Origin || r.Header.Get("X-EPF-Request") != "1" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "request protection failed", http.StatusForbidden)
			return
		}
	} else if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET required", 405)
		return
	}
	if s.closed.Load() {
		writeJSON(w, http.StatusGone, map[string]any{"error": "Session is closing.", "submitted": false})
		return
	}
	switch path {
	case "", "app.js", "style.css":
		name := path
		if name == "" {
			name = "index.html"
		}
		body, err := files.ReadFile("web/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}[name])
		_, _ = w.Write(body)
	case "api/state":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		s.modelMu.RLock()
		defer s.modelMu.RUnlock()
		_, _ = w.Write(s.model)
	case "api/call":
		s.call(w, r)
	case "api/context-call":
		s.contextCall(w, r)
	case "api/close":
		var body struct{}
		if !readJSON(w, r, &body, 64) {
			return
		}
		if s.closed.CompareAndSwap(false, true) {
			close(s.done)
		}
		writeJSON(w, 200, map[string]any{"closing": true})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) call(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Method    string          `json:"method"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if !readJSON(w, r, &request, 256<<10) {
		return
	}
	if !s.allowed[request.Method] {
		writeJSON(w, 400, map[string]any{"error": "Only listed exported no-context functions can be called.", "submitted": false})
		return
	}
	if len(request.Arguments) == 0 {
		request.Arguments = json.RawMessage("[]")
	}
	arguments, inputErr := valueinput.Arguments(request.Arguments)
	if inputErr != nil {
		writeJSON(w, 400, map[string]any{"error": "Invalid scalar function arguments.", "submitted": false})
		return
	}
	// Refuse concurrent clicks rather than queueing uncertain repeated writes.
	if !s.mu.TryLock() {
		writeJSON(w, 409, map[string]any{"error": "A call is already running.", "submitted": false})
		return
	}
	defer s.mu.Unlock()
	if s.closed.Load() {
		writeJSON(w, 410, map[string]any{"error": "Session is closing.", "submitted": false})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.options.Timeout)
	defer cancel()
	s.attempted.Add(1)
	value, err := s.options.Call(ctx, request.Method, arguments...)
	if err != nil {
		s.unconfirmed.Add(1)
		// Remote diagnostics may contain sensitive application data. Never echo
		// a raw request, credential or server response through the UI error path.
		writeJSON(w, 502, map[string]string{"error": "The call failed or its outcome is unconfirmed. It was not retried."})
		return
	}
	s.confirmed.Add(1)
	data, err := json.Marshal(map[string]any{"value": value})
	if err != nil || len(data) > 4<<20 {
		writeJSON(w, 502, map[string]any{"execution_confirmed": true, "error": "The server confirmed execution, but the result cannot be displayed. Do not repeat the call just to recover its result."})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(data)
}

func readJSON(w http.ResponseWriter, r *http.Request, destination any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(destination); err != nil {
		writeJSON(w, 400, map[string]any{"error": "Invalid request.", "submitted": false})
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		writeJSON(w, 400, map[string]any{"error": "Invalid trailing data.", "submitted": false})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 4<<20 {
		http.Error(w, "response limit", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
