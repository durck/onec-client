package onec

import (
	"context"
	"encoding/json"
	"errors"
	"onec/wire"
	"strings"
	"unicode"
)

// FormOptions selects a managed form and supplies its opening parameters.
// An empty Name selects the processing's default form. Name is a local form
// name, not a complete path, definition ID, or instance ID.
type FormOptions struct {
	Name       string          `json:"name"`
	Parameters []FormParameter `json:"parameters"`
}

type FormParameter struct {
	Name  string `json:"name"`
	Value Value  `json:"value"`
}

// FormMethodInfo describes metadata exposed for this form and session. It does
// not establish authorization, execute a method, or describe object-module
// exports. Context methods require the bounded PrepareFormContext API.
type FormMethodInfo struct {
	Module         string                    `json:"module"`
	Name           string                    `json:"name"`
	Context        string                    `json:"context"` // "server" or "no-context"
	Kind           string                    `json:"kind"`    // "procedure" or "function"
	Exported       bool                      `json:"exported"`
	Parameters     []FormMethodParameterInfo `json:"parameters"`
	ParameterCount int                       `json:"parameter_count"`
}

// FormMethodParameterInfo preserves the sparse positional direction metadata.
// Missing positions do not imply that a method has no other parameters, and
// this metadata does not establish parameter names, types, or default values.
// An empty Direction means the server omitted it; no direction is inferred.
type FormMethodParameterInfo struct {
	Position  int    `json:"position"`
	Direction string `json:"direction,omitempty"`
}

// State is shared by value copies of the opaque Form handle. Access is protected
// by its owner's mutex, including calls which only inspect cached metadata.
type formState struct {
	descriptor      map[string]any
	context         *formContext
	undefinedValues int
	closeAttempted  bool
	closeErr        error
}

type formQueryParameter struct {
	Name  string `json:"name"`
	Type  string `json:"#val"`
	Value any    `json:"val"`
}

func validFormName(s string) bool {
	if !validValueText(s, 255) {
		return false
	}
	for i, r := range s {
		if r != '_' && !unicode.IsLetter(r) && !(i > 0 && unicode.IsDigit(r)) {
			return false
		}
	}
	return true
}

func buildFormQuery(reference string, options FormOptions) (formQuery, error) {
	payload := formQuery{Key: reference + ".form"}
	if options.Name != "" {
		if !validFormName(options.Name) {
			return formQuery{}, errors.New("invalid local form name")
		}
		payload.Key += "." + options.Name
	}
	if len(options.Parameters) > 32 {
		return formQuery{}, errors.New("form parameter limit")
	}
	payload.Prms.Prm = []any{}
	names := map[string]bool{}
	for _, parameter := range options.Parameters {
		name := strings.ToUpper(parameter.Name)
		if !validFormName(parameter.Name) || names[name] {
			return formQuery{}, errors.New("invalid or duplicate form parameter name")
		}
		names[name] = true
		value, err := encodeFormValue(parameter.Value)
		if err != nil {
			return formQuery{}, err
		}
		payload.Prms.Prm = append(payload.Prms.Prm, formQueryParameter{parameter.Name, parameter.Value.Type, value})
	}
	return payload, nil
}

// OpenFormWithOptions creates the managed-form instance with the observed query
// protocol. It does not execute client-side open handlers or build a form UI.
func (c *Client) OpenFormWithOptions(ctx context.Context, processing Processing, options FormOptions) (Form, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applicationReady(); err != nil {
		return Form{}, err
	}
	if processing.owner != c || !validValueText(processing.reference, 8192) {
		return Form{}, errors.New("processing belongs to another session")
	}
	payload, err := buildFormQuery(processing.reference, options)
	if err != nil {
		return Form{}, err
	}
	undefinedValues := 0
	decode := func(h *wire.HTTP) (map[string]any, error) {
		doc, count, err := formSnapshotResponseJSON(h)
		undefinedValues = count
		return doc, err
	}
	doc, err := c.jsonRequestDecoded(ctx, "/e1cib/logForm?cmd=query", payload, decode)
	if err != nil {
		return Form{}, err
	}
	id, _ := doc["id"].(string)
	fid, _ := doc["fid"].(string)
	if !validValueText(id, 8192) || !validValueText(fid, 8192) {
		return Form{}, errors.New("missing form identifiers")
	}
	// Metadata validation is deferred so a valid instance can still be closed
	// when the server returns an unsupported metadata schema.
	descriptor := map[string]any{}
	for _, key := range []string{"altId", "assemblyVersion", "moduleIds", "props", "pdchs", "elchs", "ucDsc", "command", "fop", "fover", "usver", "puKey", "lfl", "hippo", "remotekey", "prms", "dd", "hasdd"} {
		if value, ok := doc[key]; ok {
			descriptor[key] = value
		}
	}
	return Form{owner: c, id: id, fid: fid, state: &formState{descriptor: descriptor, undefinedValues: undefinedValues}}, nil
}

func (c *Client) checkForm(form Form) error {
	if form.owner != c || form.state == nil || !validValueText(form.id, 8192) || !validValueText(form.fid, 8192) {
		return errors.New("form belongs to another session")
	}
	if form.state.closeAttempted {
		return errors.New("form is closed or its release is unconfirmed")
	}
	return nil
}

// FormMethods returns server-method metadata without executing the client
// module. Embedded methods are identified from moduleIds; otherwise a single
// read-only dataDescrWMethods request obtains the separate aligned method table.
// The result is a new slice and can be changed without modifying the handle.
func (c *Client) FormMethods(ctx context.Context, form Form) ([]FormMethodInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applicationReady(); err != nil {
		return nil, err
	}
	if err := c.checkForm(form); err != nil {
		return nil, err
	}
	version := c.cfg.Profile.Version
	modules, err := formModules(form.state.descriptor)
	if err != nil {
		return nil, err
	}
	embedded, err := embeddedFormMethods(modules)
	if err != nil {
		return nil, err
	}
	var response map[string]any
	if !embedded && len(modules) > 0 {
		target, err := formMethodsTarget(form, version, c.applicationAssemblyVersion, c.applicationRolesID)
		if err != nil {
			return nil, err
		}
		pdu, err := c.pdu("GET", target, nil, "application/json; charset=utf-8", "application/json", c.session.raw, 0)
		if err != nil {
			return nil, err
		}
		h, err := c.exchangeHTTP(ctx, pdu)
		if err != nil {
			return nil, err
		}
		doc, err := responseJSON(h)
		if err != nil {
			return nil, err
		}
		response, err = applicationResponse(doc)
		if err != nil {
			return nil, err
		}
	}
	return parseFormMethods(modules, response)
}

func formMethodsTarget(form Form, version, assemblyVersion, rolesID string) (string, error) {
	if value, ok := form.state.descriptor["assemblyVersion"]; ok {
		var valid bool
		assemblyVersion, valid = value.(string)
		if !valid {
			return "", errors.New("invalid form assembly version")
		}
	}
	if !validValueText(assemblyVersion, 8192) || !validValueText(rolesID, 8192) {
		return "", errors.New("form method discovery requires session assembly and role metadata")
	}
	target := "/e1cib/logForm?cmd=dataDescrWMethods&formId=" + queryEscape(form.id)
	if value, ok := form.state.descriptor["altId"]; ok && value != "" {
		alt, valid := value.(string)
		if !valid || !validValueText(alt, 8192) {
			return "", errors.New("invalid alternate form identifier")
		}
		if alt != form.id {
			target += "&altFormId=" + queryEscape(alt)
		}
	}
	return target + "&sysver=" + queryEscape(version) + "&confver=" + queryEscape(assemblyVersion) + "&rolesId=" + queryEscape(rolesID), nil
}

func formModules(descriptor map[string]any) ([]any, error) {
	value, exists := descriptor["moduleIds"]
	if !exists {
		return nil, errors.New("form query did not include module metadata")
	}
	modules, ok := value.([]any)
	if !ok || len(modules) > 256 {
		return nil, errors.New("invalid or oversized form module metadata")
	}
	return modules, nil
}

// Validate the discriminator before any metadata request. A malformed embedded
// table must never fall back to another interpretation or execute a method.
func embeddedFormMethods(modules []any) (bool, error) {
	embedded := false
	for _, value := range modules {
		module, ok := value.(map[string]any)
		if !ok {
			return false, errors.New("invalid form module metadata")
		}
		if name, ok := module["moduleName"].(string); !ok || !validValueText(name, 1024) {
			return false, errors.New("invalid form module name")
		}
		if methods, exists := module["methods"]; exists {
			if _, ok := methods.(map[string]any); !ok {
				return false, errors.New("invalid embedded form methods")
			}
			embedded = true
		}
	}
	return embedded, nil
}

func parseFormMethods(modules []any, response map[string]any) ([]FormMethodInfo, error) {
	if len(modules) > 256 {
		return nil, errors.New("form module metadata limit")
	}
	embedded, err := embeddedFormMethods(modules)
	if err != nil {
		return nil, err
	}
	var separate []any
	if embedded {
		if _, exists := response["methods"]; exists {
			return nil, errors.New("ambiguous embedded and separate form methods")
		}
	} else if len(modules) > 0 {
		var ok bool
		separate, ok = response["methods"].([]any)
		if !ok || len(separate) != len(modules) {
			return nil, errors.New("form methods and modules do not align")
		}
	}
	out := []FormMethodInfo{}
	for i, value := range modules {
		module, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid form module metadata")
		}
		name, ok := module["moduleName"].(string)
		if !ok || !validValueText(name, 1024) {
			return nil, errors.New("invalid form module name")
		}
		metadata, exists := module["methods"]
		if !embedded {
			metadata, exists = separate[i], true
		}
		if !exists {
			continue
		}
		methods, ok := metadata.(map[string]any)
		if !ok {
			return nil, errors.New("invalid form method metadata")
		}
		for _, group := range []struct{ key, context string }{{"srvMtd", "server"}, {"srvWOCMtd", "no-context"}} {
			value, exists := methods[group.key]
			if !exists {
				continue
			}
			groupMethods, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("invalid server method group")
			}
			for _, kind := range []struct{ key, name string }{{"proc", "procedure"}, {"func", "function"}} {
				value, exists := groupMethods[kind.key]
				if !exists {
					continue
				}
				list, ok := value.([]any)
				if !ok || len(list) > 4096-len(out) {
					return nil, errors.New("invalid or oversized server method list")
				}
				for _, value := range list {
					method, err := parseFormMethod(value)
					if err != nil {
						return nil, err
					}
					method.Module, method.Context, method.Kind = name, group.context, kind.name
					out = append(out, method)
				}
			}
		}
	}
	return out, nil
}

func parseFormMethod(value any) (FormMethodInfo, error) {
	var out FormMethodInfo
	method, ok := value.(map[string]any)
	if !ok {
		return out, errors.New("invalid server method descriptor")
	}
	out.Name, ok = method["name"].(string)
	if !ok || !validValueText(out.Name, 255) {
		return out, errors.New("invalid server method name")
	}
	if exported, exists := method["exp"]; exists {
		out.Exported, ok = exported.(bool)
		if !ok {
			return out, errors.New("invalid server method export flag")
		}
	}
	out.Parameters = []FormMethodParameterInfo{}
	if raw, exists := method["params"]; exists {
		n, err := contextNumber(raw)
		if err != nil || n > 256 {
			return out, errors.New("invalid server parameter count")
		}
		out.ParameterCount = int(n)
	}
	if value, exists := method["param"]; exists {
		parameters, ok := value.([]any)
		if !ok || len(parameters) > 256 {
			return out, errors.New("invalid or oversized server parameter metadata")
		}
		positions := map[int]bool{}
		for _, value := range parameters {
			parameter, ok := value.(map[string]any)
			if !ok {
				return out, errors.New("invalid server parameter descriptor")
			}
			number, ok := parameter["pos"].(json.Number)
			if !ok {
				return out, errors.New("invalid server parameter position")
			}
			position, err := number.Int64()
			if err != nil || position < 0 || position > 255 || positions[int(position)] {
				return out, errors.New("invalid or duplicate server parameter position")
			}
			positions[int(position)] = true
			var direction string
			if value, exists := parameter["dir"]; exists {
				direction, ok = value.(string)
				if !ok || !validValueText(direction, 32) {
					return out, errors.New("invalid server parameter direction")
				}
			}
			out.Parameters = append(out.Parameters, FormMethodParameterInfo{int(position), direction})
		}
	}
	return out, nil
}

// CloseForm releases the server form instance through processFormsClose. It
// does not run client-side before-close/close handlers or prove EPF unloading.
// Copies of the handle are retired once release is attempted. Repeated calls
// return the original result, including an error when release is unconfirmed.
func (c *Client) CloseForm(ctx context.Context, form Form) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if form.owner != c || form.state == nil || !validValueText(form.id, 8192) || !validValueText(form.fid, 8192) {
		return errors.New("form belongs to another session")
	}
	if form.state.closeAttempted {
		return form.state.closeErr
	}
	if err := c.applicationReady(); err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Root struct {
			ID []string `json:"id"`
		} `json:"root"`
	}{Root: struct {
		ID []string `json:"id"`
	}{ID: []string{form.fid}}})
	if err != nil {
		return errors.New("cannot encode form release payload")
	}
	n, err := c.nextSync()
	if err != nil {
		return err
	}
	pdu, err := c.pdu("POST", "/e1cib/logForm?cmd=processFormsClose", body, "application/json; charset=utf-8", "application/json", c.session.raw, n)
	if err != nil {
		return err
	}
	form.state.closeAttempted = true
	h, err := c.exchangeHTTP(ctx, pdu)
	if err == nil {
		if h.Status != 200 && h.Status != 201 && h.Status != 204 {
			err = &StatusError{Operation: "close form", Status: h.Status}
		} else {
			// The shipped caller ignores the response value. Empty 200/204
			// responses are valid; still enforce the normal body size bound.
			_, err = decodeBody(h, wire.MaxFile)
		}
	}
	form.state.closeErr = err
	return err
}
