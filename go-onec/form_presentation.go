package onec

import (
	"encoding/json"
	"errors"
	"strings"
)

// 18 mainform tw.Ym dispatches elemcs type 3 to an existing element's init.
// This subset deliberately supports only presentation flags and plain titles.
// Structural operations (0 add, 1 remove, 2 move) require separate semantics.
func contextElementChanges(elements map[string]any, raw any) (map[string]any, error) {
	data, err := json.Marshal(elements)
	if err != nil || len(data) > 4<<20 {
		return nil, errors.New("invalid element tree")
	}
	out, err := strictJSON(data)
	if err != nil {
		return nil, err
	}
	delta, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("invalid element changes")
	}
	for key := range delta {
		if key != "elemcs" && key != "##sequence" {
			return nil, errors.New("unsupported element change member")
		}
	}
	changes, ok := delta["elemcs"].([]any)
	if !ok || len(changes) > 2048 {
		return nil, errors.New("invalid element change list")
	}
	for _, raw := range changes {
		change, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid element change")
		}
		op, err := contextNumber(change["type"])
		if err != nil || op != 3 {
			return nil, errors.New("structural element changes are unsupported")
		}
		id, err := contextNumber(change["id"])
		if err != nil {
			return nil, err
		}
		kind := ""
		var patch map[string]any
		for key, value := range change {
			if key == "type" || key == "id" || key == "##sequence" {
				continue
			}
			if kind != "" {
				return nil, errors.New("ambiguous element change")
			}
			if key != "main" && key != "field" && key != "group" && key != "button" && key != "decoration" {
				return nil, errors.New("unsupported element change kind")
			}
			kind = key
			patch, ok = value.(map[string]any)
			if !ok {
				return nil, errors.New("invalid element property changes")
			}
		}
		if kind == "" || (kind == "main" && id != 0) {
			return nil, errors.New("invalid element change target")
		}
		var targets []map[string]any
		if kind == "main" {
			targets = append(targets, out)
		} else if err := findContextElements(out, kind, id, 0, &targets); err != nil {
			return nil, err
		}
		if len(targets) != 1 {
			return nil, errors.New("element change target is missing or ambiguous")
		}
		for key, value := range patch {
			switch key {
			case "title":
				title, ok := value.(string)
				if !ok || !formString(title) {
					return nil, errors.New("unsupported element title")
				}
			case "visible", "userVisible", "enabled", "readOnly":
				if _, ok := value.(bool); !ok {
					return nil, errors.New("invalid element flag")
				}
			case "inputData":
				input, ok := value.(map[string]any)
				if kind != "field" || !ok || len(input) != 0 {
					return nil, errors.New("input behavior changes are unsupported")
				}
				continue
			default:
				return nil, errors.New("unsupported element property change")
			}
			targets[0][key] = value
		}
	}
	return out, nil
}

func findContextElements(doc map[string]any, kind string, id uint64, depth int, out *[]map[string]any) error {
	if depth > 32 {
		return errors.New("element change tree depth limit")
	}
	if entries, ok := doc[kind].([]any); ok {
		for _, entry := range entries {
			element, ok := entry.(map[string]any)
			if !ok {
				return errors.New("invalid element change base")
			}
			got, err := contextNumber(element["id"])
			if err == nil && got == id {
				*out = append(*out, element)
			}
		}
	}
	if groups, ok := doc["group"].([]any); ok {
		for _, entry := range groups {
			group, ok := entry.(map[string]any)
			if !ok {
				return errors.New("invalid element group base")
			}
			if err := findContextElements(group, kind, id, depth+1, out); err != nil {
				return err
			}
		}
	}
	for _, key := range []string{"autoCommandBar", "navigator"} {
		if group, ok := doc[key].(map[string]any); ok {
			if err := findContextElements(group, kind, id, depth+1, out); err != nil {
				return err
			}
		}
	}
	return nil
}

// The simplified renderer uses element definitions, never the server's layout
// code or markup. Admit only the inert title/visibility/read-only layout deltas
// observed alongside our supported element changes. Everything else retires
// the context instead of suggesting a complete layout implementation.
func contextSimpleLayoutDelta(raw any) error {
	doc, ok := raw.(map[string]any)
	if !ok {
		return errors.New("invalid layout delta")
	}
	const ns = "{http://v8.1c.ru/8.3/managed-application/logform/hippo}"
	for key, value := range doc {
		switch key {
		case "key":
			if s, ok := value.(string); !ok || !validValueText(s, 1024) {
				return errors.New("invalid layout delta key")
			}
		case "#pre", "#post":
			if value != ns+"Delta" {
				return errors.New("unsupported layout delta type")
			}
		case "pre", "post":
			phase, ok := value.(map[string]any)
			if !ok || len(phase) != 1 {
				return errors.New("invalid layout phase")
			}
			items, ok := phase["item"].([]any)
			if !ok || len(items) > 4096 {
				return errors.New("invalid layout delta items")
			}
			for _, raw := range items {
				item, ok := raw.(map[string]any)
				if !ok || len(item) != 3 {
					return errors.New("invalid layout delta item")
				}
				name, ok := item["name"].(string)
				if !ok || !formString(name) {
					return errors.New("invalid layout name")
				}
				typ, _ := item["#elem"].(string)
				if !strings.HasPrefix(typ, ns) {
					return errors.New("invalid layout element type")
				}
				switch strings.TrimPrefix(typ, ns) {
				case "Form", "TextBox", "Label", "RichElement":
				default:
					return errors.New("unsupported layout element")
				}
				elem, ok := item["elem"].(map[string]any)
				if !ok || len(elem) != 2 || elem["#e"] != ns+"LayElement" {
					return errors.New("unsupported layout payload")
				}
				props, ok := elem["e"].(map[string]any)
				if !ok {
					return errors.New("invalid layout properties")
				}
				for prop, v := range props {
					switch prop {
					case "title":
						if s, ok := v.(string); !ok || !formString(s) {
							return errors.New("invalid layout title")
						}
					case "readOnly", "visible", "groupVisible":
						if _, ok := v.(bool); !ok {
							return errors.New("invalid layout flag")
						}
					default:
						return errors.New("unsupported layout property")
					}
				}
			}
		default:
			return errors.New("unsupported layout delta member")
		}
	}
	return nil
}

func (s *formContext) applyPresentation(doc map[string]any) error {
	raw, changed := doc["elchs"]
	changed = changed && snapshotNonempty(raw)
	if changed {
		elements, err := contextElementChanges(s.elements, raw)
		if err != nil {
			return err
		}
		s.elements = elements
		s.editable, s.writable, s.writableControls = []string{}, map[string]bool{}, map[string]bool{}
		if err := s.collectEditable(elements, true, true, false, 0); err != nil {
			return err
		}
	}
	if hippo, exists := doc["hippo"]; exists && snapshotNonempty(hippo) {
		if !changed {
			return errors.New("layout-only changes are unsupported")
		}
		if err := contextSimpleLayoutDelta(hippo); err != nil {
			return err
		}
	}
	if raw, exists := doc["fover"]; exists {
		version, ok := raw.(string)
		if !ok || !validValueText(version, 1024) {
			return errors.New("invalid form layout version")
		}
		if !changed && !snapshotNonempty(doc["hippo"]) && s.query["fover"] != version {
			return errors.New("unexplained form layout version change")
		}
		s.query = cloneContextMap(s.query)
		s.query["fover"] = version
	}
	return nil
}
