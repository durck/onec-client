package onec

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// FormModuleImage is a detached client program image. It contains application
// code and constants; protocol envelope identifiers are omitted. The program
// is never executed by FormModuleImages. An absent image is represented by nil.
type FormModuleImage struct {
	Name           string          `json:"name"`
	Image          json.RawMessage `json:"image,omitempty"`
	ImageWOContext json.RawMessage `json:"image_without_context,omitempty"`
}

// FormModuleImages fetches the compiled client images for an existing form.
// The response must match the supported script-array schema. The GET does not
// consume the POST synchronization counter or execute client event handlers.
// Opening the form itself may previously have run server creation handlers.
func (c *Client) FormModuleImages(ctx context.Context, form Form) ([]FormModuleImage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applicationReady(); err != nil {
		return nil, err
	}
	if err := c.checkForm(form); err != nil {
		return nil, err
	}
	modules, err := formModules(form.state.descriptor)
	if err != nil {
		return nil, err
	}
	if len(modules) == 0 {
		return []FormModuleImage{}, nil
	}
	target, err := formModuleTarget(form, c.cfg.Profile.Version, c.applicationAssemblyVersion, c.applicationConfigVersion)
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
	doc, _, err := formSnapshotResponseJSON(h)
	if err != nil {
		return nil, err
	}
	response, err := applicationResponse(doc)
	if err != nil {
		return nil, err
	}
	return decodeFormModuleImages(modules, response)
}

func formModuleTarget(form Form, version, assembly, config string) (string, error) {
	// The embedded-method contract uses the session configuration version for
	// a single configuration module. It is distinct from the form assembly.
	modules, err := formModules(form.state.descriptor)
	if err != nil {
		return "", err
	}
	configurationModule := false
	if len(modules) == 1 {
		module, ok := modules[0].(map[string]any)
		if !ok {
			return "", errors.New("invalid form module metadata")
		}
		if id, ok := module["contextModuleId"].(string); ok && strings.HasPrefix(id, "urn:module:md:") {
			embedded, err := embeddedFormMethods(modules)
			if err != nil {
				return "", err
			}
			configurationModule = embedded
		}
	}
	if value, ok := form.state.descriptor["assemblyVersion"]; ok {
		var valid bool
		assembly, valid = value.(string)
		if !valid {
			return "", errors.New("invalid form assembly version")
		}
	}
	if configurationModule {
		assembly = config
	}
	if !validValueText(assembly, 8192) {
		return "", errors.New("client module discovery requires form assembly metadata")
	}
	return "/e1cib/logForm?cmd=getModule&formId=" + queryEscape(form.id) +
		"&sysver=" + queryEscape(version) + "&confver=" + queryEscape(assembly), nil
}

func decodeFormModuleImages(modules []any, response map[string]any) ([]FormModuleImage, error) {
	scripts, ok := response["scrpt"].([]any)
	if !ok || len(scripts) != len(modules) || len(scripts) > 256 {
		return nil, errors.New("client module images do not match form module metadata")
	}
	result := make([]FormModuleImage, len(scripts))
	for i, raw := range scripts {
		script, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid client module image record")
		}
		module, ok := modules[i].(map[string]any)
		if !ok {
			return nil, errors.New("invalid form module metadata")
		}
		name, ok := module["moduleName"].(string)
		if !ok || !validValueText(name, 8192) {
			return nil, errors.New("invalid client module name")
		}
		result[i].Name = name
		for key, destination := range map[string]*json.RawMessage{
			"image": &result[i].Image, "imageWOContext": &result[i].ImageWOContext,
		} {
			if value, exists := script[key]; exists && value != nil {
				if _, ok := value.(map[string]any); !ok {
					return nil, errors.New("invalid client module image")
				}
				b, err := json.Marshal(value)
				if err != nil {
					return nil, errors.New("invalid client module JSON")
				}
				*destination = b
			}
		}
	}
	return result, nil
}
