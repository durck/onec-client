package onec

import (
	"context"
	"encoding/json"
	"errors"
	"onec/wire"
	"reflect"
	"strconv"
	"strings"
)

// The bounded tracked-state contract is shared by the inspected 12/17/18/19/22/27
// clients. Actual metadata must pass prepareContext; the advertised build does
// not grant a state capability. This is not a general form graph or BSL runtime.

// FormStateProfile names a validated wire schema, independent of platform build.
type FormStateProfile string

// FormStateScalarTrackedV1 supports the bounded scalar and tracked-state model.
// Unknown structural mutations retire it; no failed method call is replayed.
const FormStateScalarTrackedV1 FormStateProfile = "scalar-tracked-v1"

// FormContextState is a detached view of the bounded, explicitly prepared form
// context. Only EditableFields can be changed; client BSL is never executed.
type FormContextState struct {
	Profile        FormStateProfile `json:"profile"`
	Snapshot       FormSnapshot     `json:"snapshot"`
	EditableFields []string         `json:"editable_fields"`
	Revision       uint64           `json:"revision"`
	Usable         bool             `json:"usable"`
}

// FormContextResult preserves current state even for local validation errors.
// Submitted means an exchange was attempted, not that execution is confirmed.
// Recovered means synchException restored a supported state after a confirmed
// application exception; the original call still returns an error.
type FormContextResult struct {
	Value     Value            `json:"value"`
	Arguments []Value          `json:"arguments,omitempty"`
	State     FormContextState `json:"state"`
	Recovered bool             `json:"recovered"`
	Submitted bool             `json:"submitted"`
}

type contextField struct {
	name              string
	object            bool
	length            int
	fixed             bool
	typeID            string
	digits, precision int
	unsigned          bool
}

func (f contextField) scalarType() string {
	if f.typeID == "" {
		return StringType
	}
	return f.typeID
}

type formContext struct {
	id, fid, callMethod               string
	remoteKey                         any
	query, elements, metadata, layout map[string]any
	fields                            []contextField
	values                            []any
	parameters                        contextParameters
	dd                                map[string]any
	methods                           []FormMethodInfo
	callArgs, returnedArgs            []Value
	editable                          []string
	writable                          map[string]bool
	writableControls                  map[string]bool
	sinDesc, sin, seq, revision       uint64
	usable                            bool
	undefinedValues                   int
}

func prepareContext(query map[string]any, docs []map[string]any) (*formContext, error) {
	if len(docs) != 3 {
		return nil, errors.New("missing context metadata")
	}
	for _, key := range []string{"pdchs", "elchs", "ucDsc"} {
		if snapshotNonempty(query[key]) {
			return nil, errors.New("dynamic form definitions are unsupported")
		}
	}
	key, exists := query["remotekey"]
	if !exists {
		return nil, errors.New("missing form context key")
	}
	switch v := key.(type) {
	case string:
		if !validValueText(v, 8192) {
			return nil, errors.New("invalid form context key")
		}
	case json.Number:
		if _, err := v.Int64(); err != nil {
			return nil, errors.New("invalid form context key")
		}
	default:
		return nil, errors.New("unsupported form context key")
	}
	if _, err := decodeFormSnapshot(query, docs[0], docs[1], docs[2]); err != nil {
		return nil, err
	}
	descr, ok := docs[1]["descr"].(map[string]any)
	if !ok {
		return nil, errors.New("missing form context description")
	}
	fields, err := contextFields(descr, "root", true)
	if err != nil {
		return nil, err
	}
	values, err := contextValues(query["props"], fields, nil, true)
	if err != nil {
		return nil, err
	}
	parameters, err := contextParameterState(query["prms"])
	if err != nil {
		return nil, err
	}
	dd, err := contextDD(query["dd"])
	if err != nil {
		return nil, err
	}
	modules, err := formModules(query)
	if err != nil {
		return nil, err
	}
	methods, err := parseFormMethods(modules, docs[1])
	if err != nil {
		return nil, err
	}
	state := &formContext{remoteKey: key, query: cloneContextMap(query), elements: docs[0], metadata: docs[1], layout: docs[2], fields: fields, values: values, parameters: parameters, dd: dd, methods: methods, revision: 1, usable: true, writable: map[string]bool{}, writableControls: map[string]bool{}, editable: []string{}}
	for _, entry := range []struct {
		key  string
		dest *uint64
	}{{"sinDe", &state.sinDesc}, {"sinUo", &state.sin}, {"seqUo", &state.seq}} {
		if raw, exists := descr[entry.key]; exists {
			n, err := contextNumber(raw)
			if err != nil {
				return nil, err
			}
			*entry.dest = n
		}
	}
	if state.sinDesc == 0 && (state.sin != 0 || state.seq != 0) {
		return nil, errors.New("inconsistent initial form context counters")
	}
	if err := state.collectEditable(docs[0], true, true, false, 0); err != nil {
		return nil, err
	}
	return state, nil
}

func contextFields(descr map[string]any, name string, objects bool) ([]contextField, error) {
	structures, ok := descr["structure"].([]any)
	if !ok || len(structures) > 2048 {
		return nil, errors.New("invalid context structures")
	}
	var root map[string]any
	for _, raw := range structures {
		d, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid context structure")
		}
		if snapshotString(d, "name") == name {
			if root != nil {
				return nil, errors.New("duplicate context root")
			}
			root = d
		}
	}
	if root == nil {
		return nil, errors.New("missing context root")
	}
	raw, exists := root["field"]
	if !exists {
		return []contextField{}, nil
	}
	fields, ok := raw.([]any)
	if !ok || len(fields) > 2048 {
		return nil, errors.New("invalid context fields")
	}
	out := make([]contextField, len(fields))
	seen := map[string]bool{}
	for i, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid context field")
		}
		name := snapshotString(field, "name")
		canonical := strings.ToUpper(name)
		if !validFormName(name) || seen[canonical] {
			return nil, errors.New("invalid or duplicate context field name")
		}
		seen[canonical] = true
		typ, ok := field["type"].(map[string]any)
		if !ok {
			return nil, errors.New("invalid context field type")
		}
		out[i] = contextField{name: name, object: snapshotBool(typ, "object", false), length: 10, fixed: snapshotBool(typ, "fixed", false)}
		if out[i].object {
			if !objects {
				return nil, errors.New("object form parameters are unsupported")
			}
			continue
		}
		out[i].typeID = strings.ToUpper(snapshotString(typ, "__content"))
		if out[i].typeID != StringType {
			if err := contextScalarQualifiers(&out[i], typ); err != nil {
				return nil, err
			}
			continue
		}
		for key := range typ {
			if key != "__content" && key != "length" && key != "fixed" {
				return nil, errors.New("unsupported String qualifier")
			}
		}
		if raw, exists := typ["fixed"]; exists {
			if _, ok := raw.(bool); !ok {
				return nil, errors.New("invalid String qualifier")
			}
		}
		if raw, exists := typ["length"]; exists {
			n, err := contextNumber(raw)
			if err != nil || n > 65536 {
				return nil, errors.New("unsupported String length")
			}
			out[i].length = int(n)
		}
		if out[i].fixed {
			return nil, errors.New("fixed String context fields are unsupported")
		}
	}
	return out, nil
}

func contextParameterState(raw any) (contextParameters, error) {
	var out contextParameters
	doc, ok := raw.(map[string]any)
	if !ok {
		return out, errors.New("missing current form parameters")
	}
	descr, ok := doc["descriptions"].(map[string]any)
	if !ok {
		return out, errors.New("invalid current parameter descriptions")
	}
	out.Type = snapshotString(doc, "type")
	if !validValueText(out.Type, 1024) {
		return out, errors.New("invalid current parameter type")
	}
	for _, key := range []string{"collection", "structureAndCollection", "tree"} {
		if snapshotNonempty(descr[key]) {
			return out, errors.New("complex current parameters are unsupported")
		}
	}
	if snapshotBool(descr, "trackChanges", false) {
		return out, errors.New("tracked current parameters are unsupported")
	}
	fields, err := contextFields(descr, out.Type, false)
	if err != nil {
		return out, err
	}
	values, err := contextValues(doc["data"], fields, nil, true)
	if err != nil {
		return out, err
	}
	remote := descr["remoteKey"]
	if remote == nil {
		remote = ""
	}
	if s, ok := remote.(string); !ok || len(s) > 8192 {
		return out, errors.New("invalid current parameter key")
	}
	out.Descriptions = contextDescriptions{RemoteKey: remote, Structure: descr["structure"].([]any)}
	out.Data = contextProperties{Values: values}
	if _, err := json.Marshal(out); err != nil {
		return out, errors.New("unsupported current parameter metadata")
	}
	return out, nil
}

func contextDD(raw any) (map[string]any, error) {
	if raw == nil {
		return map[string]any{"m": map[string]any{}}, nil
	}
	doc, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("invalid dynamic form state")
	}
	for key, value := range doc {
		if key != "m" && key != "##sequence" && snapshotNonempty(value) {
			return nil, errors.New("dynamic control state is unsupported")
		}
	}
	main, ok := doc["m"].(map[string]any)
	if !ok {
		return nil, errors.New("invalid dynamic main state")
	}
	booleans := map[string]bool{"mdf": true, "dl": true, "coc": true, "cc": true, "spm": true, "mn": true, "dsbl": true, "clpschg": true, "ncrrw": true}
	integers := map[string]bool{"ce": true, "rbt": true, "fpupg": true, "rrw": true}
	for key, value := range main {
		switch {
		case booleans[key]:
			flag, ok := value.(bool)
			if !ok {
				return nil, errors.New("invalid dynamic main flag")
			}
			if flag != (key == "cc") {
				return nil, errors.New("nondefault dynamic main flags are unsupported")
			}
		case integers[key]:
			text, ok := snapshotScalarText(value)
			if !ok {
				return nil, errors.New("invalid dynamic main number")
			}
			number, err := strconv.ParseInt(text, 10, 32)
			if err != nil {
				return nil, errors.New("invalid dynamic main number")
			}
			expected := int64(0)
			if key == "fpupg" || key == "rrw" {
				expected = -1
			}
			if (key == "ce" && number < 0) || (key != "ce" && number != expected) {
				return nil, errors.New("nondefault dynamic main state is unsupported")
			}
		case key == "attl":
			if s, ok := value.(string); !ok || len(s) > 8192 {
				return nil, errors.New("invalid dynamic form title")
			}
		case key == "jobs":
			if snapshotNonempty(value) {
				return nil, errors.New("dynamic jobs are unsupported")
			}
		case key == "##sequence":
		default:
			return nil, errors.New("unsupported dynamic main state")
		}
	}
	return map[string]any{"m": cloneContextMap(main)}, nil
}

func (s *formContext) collectEditable(doc map[string]any, visible, enabled, readOnly bool, depth int) error {
	if depth > 32 {
		return errors.New("context element depth limit")
	}
	if err := contextControlFlags(doc); err != nil {
		return err
	}
	visible = visible && snapshotBool(doc, "visible", true) && snapshotBool(doc, "userVisible", true)
	enabled = enabled && snapshotBool(doc, "enabled", true)
	readOnly = readOnly || snapshotBool(doc, "readOnly", false)
	if raw, exists := doc["field"]; exists {
		array, ok := raw.([]any)
		if !ok {
			return errors.New("invalid context controls")
		}
		for index, raw := range array {
			if !contextSelectedChild(doc, "field", index) {
				continue
			}
			field, ok := raw.(map[string]any)
			if !ok {
				return errors.New("invalid context control")
			}
			if err := contextControlFlags(field); err != nil {
				return err
			}
			kind := snapshotString(field, "kind")
			if !visible || !enabled || readOnly || !snapshotBool(field, "visible", true) || !snapshotBool(field, "userVisible", true) || !snapshotBool(field, "enabled", true) || snapshotBool(field, "readOnly", false) || (kind != "InputField" && kind != "CheckBoxField") {
				continue
			}
			path := snapshotString(field, "propName")
			for _, attr := range s.fields {
				if attr.object || !strings.EqualFold(path, attr.name) {
					continue
				}
				key := strings.ToUpper(attr.name)
				id, _ := snapshotScalarText(field["id"])
				s.writableControls[id+"\x00"+snapshotString(field, "name")] = true
				if !s.writable[key] {
					s.writable[key] = true
					s.editable = append(s.editable, attr.name)
				}
			}
		}
	}
	if raw, exists := doc["group"]; exists {
		array, ok := raw.([]any)
		if !ok {
			return errors.New("invalid context groups")
		}
		for index, raw := range array {
			if !contextSelectedChild(doc, "group", index) {
				continue
			}
			group, ok := raw.(map[string]any)
			if !ok {
				return errors.New("invalid context group")
			}
			if err := s.collectEditable(group, visible, enabled, readOnly, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func contextControlFlags(doc map[string]any) error {
	for _, key := range []string{"visible", "userVisible", "enabled", "readOnly"} {
		if value, exists := doc[key]; exists {
			if _, ok := value.(bool); !ok {
				return errors.New("invalid context control permission")
			}
		}
	}
	return nil
}

func contextSelectedChild(doc map[string]any, kind string, index int) bool {
	sequence, _ := doc["##sequence"].([]any)
	for i := 0; i+1 < len(sequence); i += 2 {
		if sequence[i] == kind {
			value, ok := snapshotScalarText(sequence[i+1])
			if ok && value == strconv.Itoa(index) {
				return true
			}
		}
	}
	return false
}

func cloneContextMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *formContext) view() FormContextState {
	query := cloneContextMap(s.query)
	query["props"] = map[string]any{"v": s.values}
	snapshot, _ := decodeFormSnapshot(query, s.elements, s.metadata, s.layout)
	if s.undefinedValues > 0 {
		snapshot.Warnings = append(snapshot.Warnings, "Bare undefined metadata values were normalized to null; their semantics are not interpreted.")
	}
	snapshot.Warnings = []string{"Bounded server context; client BSL, change handlers, validation, and command handlers are not executed.", "Presentation is simplified; layout, formatting, and conditional appearance are not reproduced."}
	snapshot.ReadOnly = !s.usable || len(s.editable) == 0
	var update func([]FormElementSnapshot)
	update = func(elements []FormElementSnapshot) {
		for i := range elements {
			e := &elements[i]
			if s.usable && e.Kind == "field" && s.writableControls[e.ID+"\x00"+e.Name] && e.Visible && e.Enabled {
				e.ReadOnly = false
				reasons := []string{}
				for _, reason := range e.Unsupported {
					if reason != "Field editing and client validation are disabled." {
						reasons = append(reasons, reason)
					}
				}
				e.Unsupported = reasons
			}
			update(e.Children)
		}
	}
	update(snapshot.Elements)
	return FormContextState{Profile: FormStateScalarTrackedV1, Snapshot: snapshot, EditableFields: append([]string{}, s.editable...), Revision: s.revision, Usable: s.usable}
}

func (c *Client) contextRequest(ctx context.Context, command string, payload any) (map[string]any, bool, bool, error) {
	body, err := json.Marshal(struct {
		Root any `json:"root"`
	}{payload})
	if err != nil {
		return nil, false, false, errors.New("cannot encode form context request")
	}
	n, err := c.nextSync()
	if err != nil {
		return nil, false, false, err
	}
	pdu, err := c.pdu("POST", "/e1cib/logForm?cmd="+command, body, "application/json; charset=utf-8", "application/json", c.session.raw, n)
	if err != nil {
		return nil, false, false, err
	}
	h, err := c.exchangeHTTP(ctx, pdu)
	if err != nil {
		return nil, false, true, errors.New("form context exchange failed")
	}
	if h.Status != 200 && h.Status != 201 && h.Status != 204 {
		return nil, contextApplicationException(h), true, &StatusError{Operation: "form context", Status: h.Status}
	}
	doc, _, err := formSnapshotResponseJSON(h)
	if err != nil {
		return nil, false, true, err
	}
	doc, err = applicationResponse(doc)
	return doc, false, true, err
}

func contextApplicationException(h *wire.HTTP) bool {
	types := h.Header("content-type")
	if len(types) != 1 || strings.ToLower(strings.TrimSpace(strings.Split(types[0], ";")[0])) != "application/json" {
		return false
	}
	body, err := decodeBody(h, wire.MaxFile)
	if err != nil {
		return false
	}
	normalized, _ := normalizeFormUndefined(body)
	doc, err := strictJSON(normalized)
	if err != nil {
		return false
	}
	if inner, ok := doc["exception"].(map[string]any); ok {
		doc = inner
	}
	switch strings.ToUpper(snapshotString(doc, "clsid")) {
	case "F08D92F8-9EB2-4E19-9DD9-977D907CEC2D", "8D366056-4D5A-4D88-A207-0AE535B7D28E", "AFD2B550-0D52-4E03-B448-15ED68D87AC5":
		return true
	}
	return false
}

func contextUnsupported(doc map[string]any, allowed map[string]bool) error {
	for key, value := range doc {
		if key != "##sequence" && !allowed[key] && snapshotNonempty(value) {
			return errors.New("unsupported form context response change; context retired")
		}
	}
	return nil
}

func (s *formContext) apply(doc map[string]any) (Value, error) {
	var result Value
	if err := contextUnsupported(doc, map[string]bool{"prm": true, "pchs": true, "prms": true, "dd": true, "hasdd": true, "id": true, "fid": true, "fover": true, "elchs": true, "hippo": true}); err != nil {
		return result, err
	}
	for _, entry := range []struct {
		key      string
		expected any
	}{{"id", s.id}, {"fid", s.fid}} {
		if value, exists := doc[entry.key]; exists && !reflect.DeepEqual(value, entry.expected) {
			return result, errors.New("context response identity or layout version changed; context retired")
		}
	}
	if err := s.applyPresentation(doc); err != nil {
		return result, err
	}
	if raw, exists := doc["pchs"]; exists && snapshotNonempty(raw) {
		pchs, ok := raw.(map[string]any)
		if !ok {
			return result, errors.New("invalid context acknowledgement; context retired")
		}
		if err := contextUnsupported(pchs, map[string]bool{"structure": true, "sinDesc": true, "sin": true, "seq": true}); err != nil {
			return result, err
		}
		if raw, exists := pchs["structure"]; exists {
			sinDesc, err := contextNumber(pchs["sinDesc"])
			if err != nil {
				return result, err
			}
			sin, err := contextNumber(pchs["sin"])
			if err != nil {
				return result, err
			}
			seq, err := contextNumber(pchs["seq"])
			if err != nil {
				return result, err
			}
			if sinDesc != s.sinDesc || sin != s.sin || seq < s.seq {
				return result, errors.New("context acknowledgement counter mismatch; context retired")
			}
			values, err := contextValues(raw, s.fields, s.values, false)
			if err != nil {
				return result, err
			}
			s.values = values
			s.seq = seq
		}
	}
	if raw, exists := doc["prms"]; exists && snapshotNonempty(raw) {
		params, ok := raw.(map[string]any)
		if !ok {
			return result, errors.New("invalid current parameter update")
		}
		if err := contextUnsupported(params, map[string]bool{"data": true}); err != nil {
			return result, err
		}
		fields, err := contextFields(map[string]any{"structure": s.parameters.Descriptions.Structure}, s.parameters.Type, false)
		if err != nil {
			return result, err
		}
		values, err := contextValues(params["data"], fields, s.parameters.Data.Values, false)
		if err != nil {
			return result, err
		}
		s.parameters.Data = contextProperties{Values: values}
	}
	if raw, exists := doc["dd"]; exists {
		dd, err := contextDD(raw)
		if err != nil {
			return result, err
		}
		if contextTitle(dd) != contextTitle(s.dd) {
			return result, errors.New("changed dynamic form title is unsupported")
		}
		s.dd = dd
	} else if snapshotBool(doc, "hasdd", false) {
		if contextTitle(s.dd) != "" {
			return result, errors.New("changed dynamic form title is unsupported")
		}
		s.dd = map[string]any{"m": map[string]any{}}
	}
	prm, ok := doc["prm"].(map[string]any)
	if !ok {
		return result, errors.New("missing context return envelope; context retired")
	}
	if err := contextUnsupported(prm, map[string]bool{"ret": true, "#ret": true, "name": true, "param": true, "#param": true}); err != nil {
		return result, err
	}
	if name, exists := prm["name"]; exists && name != s.callMethod {
		return result, errors.New("context method response mismatch; context retired")
	}
	returned, err := contextReturnedArguments(prm, len(s.callArgs))
	if err != nil {
		return result, err
	}
	s.returnedArgs = returned
	value, exists := prm["ret"]
	if !exists {
		return result, errors.New("missing context return value; context retired")
	}
	typ, ok := prm["#ret"].(string)
	if !ok {
		return result, errors.New("unsupported context return type; context retired")
	}
	return decodeFormScalar(typ, value)
}
