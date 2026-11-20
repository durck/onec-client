package webauth

import (
	"context"
	"encoding/json"
)

// About reads the observed informational endpoint using this client's live
// session. The returned application data is private and must not be logged by
// default. It does not request main-form initialization or a module call.
func (c *Client) About(ctx context.Context) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.authenticated {
		return nil, &Error{Operation: "about", Kind: "not_authenticated"}
	}
	r, err := c.request(ctx, "about", "GET", "e1cib/about", nil, nil, true, "")
	if err != nil {
		return nil, err
	}
	defer clear(r.body)
	if r.status != 200 {
		return nil, statusError("about", r)
	}
	obj, err := decode(r)
	if err != nil {
		return nil, err
	}
	if _, ok := obj["exception"]; ok {
		return nil, &Error{Operation: "about", Kind: "server_exception", Status: r.status}
	}
	if raw, ok := obj["response"]; ok && json.Valid(raw) {
		return append(json.RawMessage(nil), raw...), nil
	}
	return nil, &Error{Operation: "about", Kind: "invalid_application_document"}
}
