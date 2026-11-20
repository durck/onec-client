package onec

import (
	"errors"
	"reflect"
)

func (s *formContext) recover(doc map[string]any) error {
	if err := contextUnsupported(doc, map[string]bool{"props": true, "dd": true, "hasdd": true, "descriptions": true, "type": true, "els": true, "hippo": true, "#hippo": true, "picmnf": true}); err != nil {
		return err
	}
	for _, key := range []string{"hippo", "#hippo", "picmnf"} {
		if value, exists := doc[key]; exists && !reflect.DeepEqual(value, s.layout[key]) {
			return errors.New("changed recovered presentation is unsupported")
		}
	}
	if value, exists := doc["els"]; exists {
		elements, ok := value.(map[string]any)
		if !ok || !reflect.DeepEqual(contextClearEvents(elements), contextClearEvents(s.elements)) {
			return errors.New("changed recovered elements are unsupported")
		}
		s.elements = elements
	}
	if raw, exists := doc["descriptions"]; exists && snapshotNonempty(raw) {
		descr, ok := raw.(map[string]any)
		if !ok {
			return errors.New("invalid recovered descriptions")
		}
		if err := contextUnsupported(descr, map[string]bool{"remoteKey": true, "trackChanges": true, "sinDe": true, "seqDe": true, "sinUo": true, "seqUo": true, "structure": true}); err != nil {
			return err
		}
		if key, exists := descr["remoteKey"]; exists && !reflect.DeepEqual(key, s.remoteKey) {
			return errors.New("changed recovered context identity is unsupported")
		}
		if tracked, exists := descr["trackChanges"]; exists && tracked != true {
			return errors.New("invalid recovered change-tracking mode")
		}
		if raw, exists := descr["seqDe"]; exists {
			if _, err := contextNumber(raw); err != nil {
				return err
			}
		}
		original, ok := s.metadata["descr"].(map[string]any)
		before, beforeErr := contextNamedStructures(original["structure"])
		after, afterErr := contextNamedStructures(descr["structure"])
		if !ok || beforeErr != nil || afterErr != nil || snapshotString(doc, "type") != "root" || !reflect.DeepEqual(before, after) {
			return errors.New("changed recovered descriptions are unsupported")
		}
		fields, err := contextFields(descr, snapshotString(doc, "type"), true)
		if err != nil || !reflect.DeepEqual(fields, s.fields) {
			return errors.New("changed recovered descriptions are unsupported")
		}
		for _, entry := range []struct {
			key  string
			dest *uint64
		}{{"sinDe", &s.sinDesc}, {"sinUo", &s.sin}, {"seqUo", &s.seq}} {
			n, err := contextNumber(descr[entry.key])
			if err != nil {
				return err
			}
			*entry.dest = n
		}
	}
	values, err := contextValues(doc["props"], s.fields, s.values, false)
	if err != nil {
		return err
	}
	s.values = values
	if raw, exists := doc["dd"]; exists {
		dd, err := contextDD(raw)
		if err != nil {
			return err
		}
		if contextTitle(dd) != contextTitle(s.dd) {
			return errors.New("changed recovered form title is unsupported")
		}
		s.dd = dd
	} else if snapshotBool(doc, "hasdd", false) {
		if contextTitle(s.dd) != "" {
			return errors.New("changed recovered form title is unsupported")
		}
		s.dd = map[string]any{"m": map[string]any{}}
	}
	return nil
}

func contextTitle(dd map[string]any) string {
	main, _ := dd["m"].(map[string]any)
	return snapshotString(main, "attl")
}

// Structure names are identities; the server may reverse their array order in
// synchException. Field arrays inside each structure remain position-sensitive.
func contextNamedStructures(raw any) (map[string]any, error) {
	list, ok := raw.([]any)
	if !ok || len(list) > 2048 {
		return nil, errors.New("invalid context structures")
	}
	out := map[string]any{}
	for _, raw := range list {
		entry, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid context structure")
		}
		name := snapshotString(entry, "name")
		if !validValueText(name, 1024) || out[name] != nil {
			return nil, errors.New("invalid or duplicate context structure")
		}
		out[name] = entry
	}
	return out, nil
}

// Recovery clears client event registrations and omits default flags even when
// a prior element delta explicitly restored them. Normalize only those proven
// defaults; changed permissions, bindings and event handlers remain unequal.
func contextClearEvents(raw any) any {
	switch value := raw.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, v := range value {
			if flag, ok := v.(bool); ok {
				if (k == "readOnly" && !flag) || ((k == "visible" || k == "userVisible" || k == "enabled") && flag) {
					continue
				}
			}
			if k != "clearEvents" {
				out[k] = contextClearEvents(v)
			}
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, v := range value {
			out[i] = contextClearEvents(v)
		}
		return out
	default:
		return value
	}
}
