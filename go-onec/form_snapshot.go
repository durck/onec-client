package onec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"onec/wire"
	"strconv"
	"strings"
)

// FormSnapshotOptions selects the language of server presentation metadata.
// Empty Language uses ru, matching the client's current Accept-Language.
type FormSnapshotOptions struct {
	Language string `json:"language"`
}

// FormSnapshot is a detached, read-only view of a form's initial server state.
// It does not execute client BSL, apply client events, or reproduce 1C layout.
// It contains application data, but no session or remote-context identifiers.
type FormSnapshot struct {
	Title           string                  `json:"title"`
	Elements        []FormElementSnapshot   `json:"elements"`
	Commands        []FormCommandSnapshot   `json:"commands"`
	Attributes      []FormAttributeSnapshot `json:"attributes"`
	Warnings        []string                `json:"warnings"`
	LayoutAvailable bool                    `json:"layout_available"`
	ReadOnly        bool                    `json:"read_only"`
	Lifecycle       *FormLifecyclePlan      `json:"lifecycle,omitempty"`
}

// FormElementSnapshot retains server order and basic presentation. Variant is
// the server's kind string. Unsupported lists behavior not implemented here.
// Render every element read-only, including those marked Enabled by the server.
type FormElementSnapshot struct {
	ID          string                `json:"id"`
	Kind        string                `json:"kind"`
	Variant     string                `json:"variant,omitempty"`
	Name        string                `json:"name"`
	Title       string                `json:"title"`
	DataPath    string                `json:"data_path,omitempty"`
	Visible     bool                  `json:"visible"`
	Enabled     bool                  `json:"enabled"`
	ReadOnly    bool                  `json:"read_only"`
	Value       *Value                `json:"value,omitempty"`
	Children    []FormElementSnapshot `json:"children,omitempty"`
	Unsupported []string              `json:"unsupported,omitempty"`
}

// FormCommandSnapshot is a client command, never a server method invocation.
type FormCommandSnapshot struct {
	Name              string `json:"name"`
	ModifiesData      bool   `json:"modifies_data"`
	UnsupportedReason string `json:"unsupported_reason"`
}

type FormAttributeSnapshot struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	Value             *Value `json:"value,omitempty"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
}

// SnapshotForm fetches elements, data descriptions, and layout metadata for the
// initial form query using the supported metadata schema. GETs do not advance the
// form POST synchronization counter. No client module is fetched or executed.
// Server layout metadata may contain HTML; it is never executed or returned.
func (c *Client) SnapshotForm(ctx context.Context, form Form, options FormSnapshotOptions) (FormSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applicationReady(); err != nil {
		return FormSnapshot{}, err
	}
	if err := c.checkForm(form); err != nil {
		return FormSnapshot{}, err
	}
	docs, undefinedCount, err := c.formSnapshotDocuments(ctx, form, options)
	if err != nil {
		return FormSnapshot{}, err
	}
	snapshot, err := decodeFormSnapshot(form.state.descriptor, docs[0], docs[1], docs[2])
	if err == nil && undefinedCount > 0 {
		snapshot.Warnings = append(snapshot.Warnings, "Bare undefined metadata values were normalized to null; their semantics are not interpreted.")
	}
	return snapshot, err
}

func (c *Client) formSnapshotDocuments(ctx context.Context, form Form, options FormSnapshotOptions) ([]map[string]any, int, error) {
	targets, err := formSnapshotTargets(form, c.cfg.Profile.Version, c.applicationAssemblyVersion, c.applicationRolesID, options)
	if err != nil {
		return nil, 0, err
	}
	docs := make([]map[string]any, len(targets))
	undefinedCount := form.state.undefinedValues
	for i, target := range targets {
		pdu, err := c.pdu("GET", target, nil, "application/json; charset=utf-8", "application/json", c.session.raw, 0)
		if err != nil {
			return nil, 0, err
		}
		h, err := c.exchangeHTTP(ctx, pdu)
		if err != nil {
			return nil, 0, err
		}
		doc, count, err := formSnapshotResponseJSON(h)
		undefinedCount += count
		if err != nil {
			return nil, 0, err
		}
		docs[i], err = applicationResponse(doc)
		if err != nil {
			return nil, 0, err
		}
	}
	return docs, undefinedCount, nil
}

// Build 18 emits JavaScript's bare undefined in otherwise JSON metadata (live
// commandParam regression). The shipped wrapper uses eval; this form-only
// decoder accepts just that one extension. Authentication keeps strictJSON.
func formSnapshotResponseJSON(h *wire.HTTP) (map[string]any, int, error) {
	if h.Status != 200 {
		return nil, 0, &StatusError{Operation: "form metadata response", Status: h.Status}
	}
	types := h.Header("content-type")
	if len(types) != 1 || strings.ToLower(strings.TrimSpace(strings.Split(types[0], ";")[0])) != "application/json" {
		return nil, 0, errors.New("expected application/json form metadata")
	}
	body, err := decodeBody(h, wire.MaxFile)
	if err != nil {
		return nil, 0, err
	}
	normalized, count := normalizeFormUndefined(body)
	doc, err := strictJSON(normalized)
	return doc, count, err
}

func normalizeFormUndefined(body []byte) ([]byte, int) {
	out := make([]byte, 0, len(body))
	quoted := false
	count := 0
	boundary := func(b byte) bool {
		return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == ':' || b == ',' || b == '[' || b == ']' || b == '{' || b == '}'
	}
	for i := 0; i < len(body); i++ {
		ch := body[i]
		if quoted {
			out = append(out, ch)
			if ch == '\\' && i+1 < len(body) {
				i++
				out = append(out, body[i])
			} else if ch == '"' {
				quoted = false
			}
			continue
		}
		if ch == '"' {
			quoted = true
			out = append(out, ch)
			continue
		}
		if ch == 'u' && bytes.HasPrefix(body[i:], []byte("undefined")) && (i == 0 || boundary(body[i-1])) && (i+9 == len(body) || boundary(body[i+9])) {
			out = append(out, "null"...)
			i += 8
			count++
			continue
		}
		out = append(out, ch)
	}
	return out, count
}

func formSnapshotTargets(form Form, version, assembly, roles string, options FormSnapshotOptions) ([]string, error) {
	language := options.Language
	if language == "" {
		language = "ru"
	}
	if len(language) > 32 {
		return nil, errors.New("invalid form snapshot language")
	}
	for _, ch := range language {
		if ch != '-' && ch != '_' && !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') {
			return nil, errors.New("invalid form snapshot language")
		}
	}
	base, err := formMethodsTarget(form, version, assembly, roles)
	if err != nil {
		return nil, err
	}
	elements := strings.Replace(base, "cmd=dataDescrWMethods", "cmd=elements", 1) + "&clang=" + queryEscape(language)
	layout := strings.Replace(base, "cmd=dataDescrWMethods", "cmd=layouter", 1)
	for _, key := range []string{"puKey", "fover", "usver"} {
		if value, ok := form.state.descriptor[key]; ok {
			s, ok := snapshotScalarText(value)
			if !ok || !validValueText(s, 8192) {
				return nil, errors.New("invalid form layout selector")
			}
			layout += "&" + key + "=" + queryEscape(s)
		}
	}
	layout += "&mw=0&mh=0&clang=" + queryEscape(language) + "&cw=0&ch=0&iweb=true"
	if raw, ok := form.state.descriptor["fop"]; ok {
		fop, ok := raw.([]any)
		if !ok || len(fop) > 128 {
			return nil, errors.New("invalid form functional options")
		}
		for _, raw := range fop {
			entry, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid form functional option")
			}
			name, ok := entry["name"].(string)
			value, valid := snapshotScalarText(entry["value"])
			if !ok || !validFormName(name) || !valid || len(value) > 8192 {
				return nil, errors.New("invalid form functional option")
			}
			layout += "&fop." + queryEscape(name) + "=" + queryEscape(value)
		}
	}
	return []string{elements, base, layout}, nil
}

func snapshotScalarText(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64), true
	case json.Number:
		return string(v), true
	}
	return "", false
}

func snapshotString(doc map[string]any, key string) string {
	value, _ := doc[key].(string)
	return value
}
func snapshotBool(doc map[string]any, key string, fallback bool) bool {
	value, ok := doc[key].(bool)
	if ok {
		return value
	}
	return fallback
}
func snapshotNonempty(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case map[string]any:
		return len(v) > 0
	case []any:
		return len(v) > 0
	}
	return true
}

func decodeFormSnapshot(query, elements, metadata, layout map[string]any) (FormSnapshot, error) {
	out := FormSnapshot{ReadOnly: true, Elements: []FormElementSnapshot{}, Commands: []FormCommandSnapshot{}, Attributes: []FormAttributeSnapshot{}, Warnings: []string{
		"Initial server state only; client BSL and client event handlers are not executed.",
		"Presentation is simplified; layout, formatting, and conditional appearance are not reproduced.",
	}}
	out.Title = snapshotString(elements, "title")
	for _, key := range []string{"lfl", "hippo", "html"} {
		if snapshotNonempty(layout[key]) || snapshotNonempty(query[key]) {
			out.LayoutAvailable = true
		}
	}
	if snapshotNonempty(query["pdchs"]) {
		out.Warnings = append(out.Warnings, "Dynamic data-description changes are unsupported; attributes are omitted.")
	} else {
		var err error
		out.Attributes, err = snapshotAttributes(metadata["descr"], query["props"])
		if err != nil {
			return FormSnapshot{}, err
		}
	}
	if snapshotNonempty(query["elchs"]) || snapshotNonempty(query["ucDsc"]) {
		out.Warnings = append(out.Warnings, "Dynamic element changes are unsupported; the stale base element tree is omitted.")
	} else {
		count := 0
		var err error
		out.Elements, err = snapshotChildren(elements, out.Attributes, 0, &count)
		if err != nil {
			return FormSnapshot{}, err
		}
		plan, planErr := decodeFormLifecycle(elements)
		if planErr != nil {
			out.Warnings = append(out.Warnings, "Form lifecycle metadata is ambiguous or unsupported; its plan is omitted.")
		} else {
			out.Lifecycle = &plan
		}
	}
	if snapshotNonempty(elements["event"]) {
		out.Warnings = append(out.Warnings, "Form event metadata is present; no client event dispatch is performed.")
	}
	if raw, exists := query["command"]; exists {
		commands, ok := raw.([]any)
		if !ok || len(commands) > 1024 {
			return FormSnapshot{}, errors.New("invalid form command metadata")
		}
		for _, raw := range commands {
			doc, ok := raw.(map[string]any)
			if !ok {
				return FormSnapshot{}, errors.New("invalid form command")
			}
			out.Commands = append(out.Commands, FormCommandSnapshot{Name: snapshotString(doc, "name"), ModifiesData: snapshotBool(doc, "modifiesData", false), UnsupportedReason: "Client command dispatch and BSL runtime are not implemented."})
		}
	}
	return out, nil
}

func snapshotChildren(doc map[string]any, attrs []FormAttributeSnapshot, depth int, count *int) ([]FormElementSnapshot, error) {
	if depth > 32 {
		return nil, errors.New("form element depth limit")
	}
	out := []FormElementSnapshot{}
	for _, key := range []string{"autoCommandBar", "autoCommandBarRef", "navigator"} {
		if raw, exists := doc[key]; exists {
			child, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid form command bar")
			}
			element, err := snapshotElement("group", child, attrs, depth, count)
			if err != nil {
				return nil, err
			}
			if key == "autoCommandBarRef" {
				element.Unsupported = append(element.Unsupported, "Command bar reference has no definition.")
			}
			out = append(out, element)
		}
	}
	raw, exists := doc["##sequence"]
	if !exists {
		for _, key := range []string{"field", "group", "table", "button", "decoration", "addition"} {
			if snapshotNonempty(doc[key]) {
				return nil, errors.New("form elements are missing their display sequence")
			}
		}
		return out, nil
	}
	sequence, ok := raw.([]any)
	if !ok || len(sequence)%2 != 0 || len(sequence) > 4096 {
		return nil, errors.New("invalid form display sequence")
	}
	for i := 0; i < len(sequence); i += 2 {
		kind, ok := sequence[i].(string)
		if !ok {
			return nil, errors.New("invalid form element kind")
		}
		// The platform's child-construction switch ignores serializer sequence
		// entries for nonvisual metadata; they are not controls.
		if kind == "event" || kind == "predefined" {
			continue
		}
		indexText, ok := snapshotScalarText(sequence[i+1])
		if !ok {
			return nil, errors.New("invalid form element index")
		}
		index, err := strconv.Atoi(indexText)
		if err != nil || index < 0 {
			return nil, errors.New("invalid form element index")
		}
		array, ok := doc[kind].([]any)
		if !ok || index >= len(array) {
			return nil, errors.New("form element index is out of range")
		}
		child, ok := array[index].(map[string]any)
		if !ok {
			return nil, errors.New("invalid form element definition")
		}
		element, err := snapshotElement(kind, child, attrs, depth, count)
		if err != nil {
			return nil, err
		}
		out = append(out, element)
	}
	return out, nil
}

func snapshotElement(kind string, doc map[string]any, attrs []FormAttributeSnapshot, depth int, count *int) (FormElementSnapshot, error) {
	(*count)++
	if *count > 2048 {
		return FormElementSnapshot{}, errors.New("form element count limit")
	}
	out := FormElementSnapshot{Kind: kind, Variant: snapshotString(doc, "kind"), Name: snapshotString(doc, "name"), Title: snapshotString(doc, "title"), DataPath: snapshotString(doc, "propName"), Visible: snapshotBool(doc, "visible", true) && snapshotBool(doc, "userVisible", true), Enabled: snapshotBool(doc, "enabled", true), ReadOnly: true}
	out.ID, _ = snapshotScalarText(doc["id"])
	if title, ok := doc["title"].(map[string]any); ok {
		out.Title = snapshotString(title, "str")
		if snapshotBool(title, "formatted", false) {
			out.Unsupported = append(out.Unsupported, "Formatted title is displayed as plain text.")
		}
	}
	if snapshotNonempty(doc["event"]) {
		out.Unsupported = append(out.Unsupported, "Event metadata is present; no client event dispatch is performed.")
	}
	switch kind {
	case "field":
		out.Unsupported = append(out.Unsupported, "Field editing and client validation are disabled.")
		for _, attr := range attrs {
			if out.DataPath != "" && (strings.EqualFold(out.DataPath, attr.Name) || out.DataPath == attr.ID) {
				out.Value = attr.Value
				break
			}
		}
		if out.Value == nil {
			out.Unsupported = append(out.Unsupported, "Field value is unavailable in the supported scalar snapshot.")
		}
	case "button":
		out.Unsupported = append(out.Unsupported, "Command dispatch requires the client runtime.")
	case "group", "decoration":
	default:
		out.Unsupported = append(out.Unsupported, "This control is not rendered by the snapshot client.")
	}
	if kind == "group" {
		var err error
		out.Children, err = snapshotChildren(doc, attrs, depth+1, count)
		if err != nil {
			return FormElementSnapshot{}, err
		}
	}
	return out, nil
}

func snapshotAttributes(rawDescr, rawProps any) ([]FormAttributeSnapshot, error) {
	out := []FormAttributeSnapshot{}
	descr, ok := rawDescr.(map[string]any)
	if !ok {
		return nil, errors.New("missing form data description")
	}
	structures, ok := descr["structure"].([]any)
	if !ok {
		return nil, errors.New("missing form data structures")
	}
	var root map[string]any
	for _, raw := range structures {
		d, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid form data structure")
		}
		if snapshotString(d, "name") == "root" {
			if root != nil {
				return nil, errors.New("duplicate form root structure")
			}
			root = d
		}
	}
	if root == nil {
		return nil, errors.New("missing form root structure")
	}
	fields, ok := root["field"].([]any)
	if !ok {
		if _, exists := root["field"]; exists {
			return nil, errors.New("invalid form root fields")
		}
		return out, nil
	}
	if len(fields) > 2048 {
		return nil, errors.New("form attribute count limit")
	}
	props, ok := rawProps.(map[string]any)
	if !ok {
		return nil, errors.New("missing form property values")
	}
	values, ok := props["v"].([]any)
	if !ok {
		return nil, errors.New("invalid form property values")
	}
	positions := make([]int, len(fields))
	for i := range positions {
		positions[i] = i
	}
	if raw, exists := props["fields"]; exists {
		s, ok := raw.(string)
		if !ok {
			return nil, errors.New("invalid form property positions")
		}
		parts := strings.Fields(s)
		positions = make([]int, len(parts))
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n >= len(fields) {
				return nil, errors.New("invalid form property position")
			}
			positions[i] = n
		}
	}
	if len(positions) != len(values) {
		return nil, errors.New("form property position/value count mismatch")
	}
	types := []any(nil)
	if raw, exists := props["#v"]; exists {
		types, ok = raw.([]any)
		if !ok || len(types) != len(values) {
			return nil, errors.New("invalid form property type list")
		}
	}
	seen := map[int]bool{}
	for i, pos := range positions {
		if seen[pos] {
			return nil, errors.New("duplicate form property position")
		}
		seen[pos] = true
		field, ok := fields[pos].(map[string]any)
		if !ok {
			return nil, errors.New("invalid form attribute")
		}
		typeInfo, ok := field["type"].(map[string]any)
		if !ok {
			return nil, errors.New("invalid form attribute type")
		}
		attr := FormAttributeSnapshot{Name: snapshotString(field, "name"), Type: snapshotString(typeInfo, "__content")}
		attr.ID, _ = snapshotScalarText(field["id"])
		if snapshotBool(typeInfo, "object", false) {
			attr.Type = snapshotString(typeInfo, "name")
			attr.UnsupportedReason = "Nested form objects and collections are not decoded."
		} else {
			if len(types) > 0 {
				if typ, ok := types[i].(string); ok && typ != "undefined" {
					attr.Type = typ
				}
			}
			typ := strings.ToUpper(attr.Type)
			value, err := decodeFormScalar(typ, values[i])
			if err == nil {
				attr.Value = &value
			} else {
				attr.UnsupportedReason = "This attribute type or value encoding is not supported."
			}
		}
		out = append(out, attr)
	}
	return out, nil
}
