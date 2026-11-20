package epfui

import (
	"context"
	"encoding/json"
	"net/http"
	"onec"
	"onec/internal/valueinput"
	"strings"
	"unicode/utf8"
)

func (s *Server) contextCall(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Method    string          `json:"method"`
		Revision  uint64          `json:"revision"`
		Arguments json.RawMessage `json:"arguments"`
		Changes   []struct {
			Name  valueinput.JSONString `json:"name"`
			Value valueinput.JSONString `json:"value"`
		} `json:"changes"`
	}
	if !readJSON(w, r, &request, 256<<10) {
		return
	}
	if s.options.CallContext == nil || !s.contextAllowed[request.Method] {
		writeJSON(w, 400, map[string]any{"error": "Only listed exported context functions are available in interactive mode.", "submitted": false})
		return
	}
	if !s.mu.TryLock() {
		writeJSON(w, 409, map[string]any{"error": "A call is already running. It was not queued.", "submitted": false})
		return
	}
	defer s.mu.Unlock()
	if s.closed.Load() {
		writeJSON(w, 410, map[string]any{"error": "Session is closing.", "submitted": false})
		return
	}
	s.modelMu.RLock()
	state := s.modelValue.Context
	s.modelMu.RUnlock()
	if state == nil || !state.Usable {
		writeJSON(w, 409, map[string]any{"error": "Form state is unavailable. Close this session and start a new one.", "state": state, "submitted": false})
		return
	}
	if request.Revision != state.Revision {
		writeJSON(w, 409, map[string]any{"error": "The form changed in another request. Reload before editing again; this call was not sent.", "state": state, "submitted": false})
		return
	}
	if len(request.Changes) > 32 {
		writeJSON(w, 400, map[string]any{"error": "Too many field changes.", "submitted": false})
		return
	}
	if len(request.Arguments) == 0 {
		request.Arguments = json.RawMessage("[]")
	}
	arguments, err := valueinput.Arguments(request.Arguments)
	expected := -1
	for _, method := range s.options.Model.Methods {
		if method.Name == request.Method && method.Context == "server" {
			expected = method.ParameterCount
		}
	}
	if err != nil || len(arguments) != expected {
		writeJSON(w, 400, map[string]any{"error": "Invalid function arguments or argument count.", "submitted": false})
		return
	}
	types := map[string]string{}
	for _, attr := range state.Snapshot.Attributes {
		types[strings.ToUpper(attr.Name)] = attr.Type
	}
	editable := map[string]string{}
	for _, name := range state.EditableFields {
		editable[strings.ToUpper(name)] = name
	}
	seen := map[string]bool{}
	changes := make([]onec.FormParameter, 0, len(request.Changes))
	for _, change := range request.Changes {
		key := strings.ToUpper(string(change.Name))
		canonical, ok := editable[key]
		text := string(change.Value)
		if !ok || seen[key] || !utf8.ValidString(text) || utf8.RuneCountInString(text) > 65536 {
			writeJSON(w, 400, map[string]any{"error": "Invalid, read-only or duplicate field change. No call was sent.", "submitted": false})
			return
		}
		seen[key] = true
		value, err := valueinput.Text(types[key], text)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "Invalid value for the field type.", "submitted": false})
			return
		}
		changes = append(changes, onec.FormParameter{Name: canonical, Value: value})
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.options.Timeout)
	defer cancel()
	result, callErr := s.options.CallContext(ctx, request.Method, request.Revision, changes, arguments...)
	if result.Submitted {
		s.attempted.Add(1)
	}
	if callErr == nil {
		s.confirmed.Add(1)
	} else if result.Submitted {
		s.unconfirmed.Add(1)
	}
	if result.Recovered {
		s.recovered.Add(1)
	}
	// Publishing a new revision is part of the response contract. Keep state
	// updates atomic so another tab sees either the old or complete new model.
	s.modelMu.Lock()
	next := s.modelValue
	next.Context = &result.State
	next.Snapshot = result.State.Snapshot
	encoded, encodeErr := json.Marshal(next)
	modelTooLarge := encodeErr != nil || len(encoded) > 4<<20
	if modelTooLarge {
		retired := *state
		retired.Usable = false
		next.Context = &retired
		next.Snapshot = state.Snapshot
		encoded, _ = json.Marshal(next)
	}
	s.modelValue, s.model = next, encoded
	s.modelMu.Unlock()
	if modelTooLarge {
		writeJSON(w, 502, map[string]any{"error": "The result cannot be displayed. Do not repeat the call; close this session.", "submitted": result.Submitted, "execution_confirmed": callErr == nil})
		return
	}
	if callErr != nil {
		message := "The call outcome or form state is unconfirmed. Do not repeat the call; close this session."
		status := http.StatusBadGateway
		if !result.Submitted {
			message = "The input was rejected before the call was sent."
			status = http.StatusBadRequest
		}
		if result.Recovered {
			message = "The server reported an error. Form state was synchronized; the method was not retried."
			status = http.StatusUnprocessableEntity
		}
		writeJSON(w, status, map[string]any{"error": message, "state": result.State, "submitted": result.Submitted, "recovered": result.Recovered})
		return
	}
	data, err := json.Marshal(result)
	if err != nil || len(data) > 4<<20 {
		writeJSON(w, 502, map[string]any{"error": "The server confirmed execution, but the result cannot be displayed. Reload the form state; do not repeat the call.", "execution_confirmed": true, "submitted": result.Submitted})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(data)
}
