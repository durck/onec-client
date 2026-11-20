package onec

import (
	"errors"
	"strings"
)

// FormLifecyclePlan describes form-level metadata, not an executable schedule.
// Element events, module availability and extension capability filters are not
// resolved. An empty Events list does not prove that closing a form is safe.
type FormLifecyclePlan struct {
	Events     []FormLifecycleEvent `json:"events"`
	Unresolved []string             `json:"unresolved"`
}

// FormLifecycleEvent retains the source groups. EntryGroup is the outermost
// group (the last constructed one), or -1 for an event with no groups. An
// Override may choose whether to invoke its inherited chain, so groups cannot
// be flattened into a guaranteed execution order.
type FormLifecycleEvent struct {
	ID            string             `json:"id"`
	CandidateName string             `json:"candidate_name,omitempty"`
	EntryGroup    int                `json:"entry_group"`
	Groups        []FormHandlerGroup `json:"groups"`
}

type FormHandlerGroup struct {
	InheritedGroup int                    `json:"inherited_group"`
	Handlers       []FormLifecycleHandler `json:"handlers"`
}

type FormLifecycleHandler struct {
	Name  string `json:"name"`
	Phase string `json:"phase"`
}

// InspectFormLifecycle inspects a strict JSON elements document already held by
// the caller. It opens no connection and executes no client code. Candidate
// names are inferred from call placement in the inspected 18/27/85 artifacts;
// they do not assert compatibility with arbitrary builds. Ambiguous metadata
// fails without returning a partial plan or echoing its contents in an error.
// Only nonzero UUID event IDs are accepted; redacted or symbolic IDs remain
// unsupported. Input must omit the server response envelope.
func InspectFormLifecycle(elementsJSON []byte) (FormLifecyclePlan, error) {
	doc, err := strictJSON(elementsJSON)
	if err != nil {
		return FormLifecyclePlan{}, err
	}
	if _, wrapped := doc["response"]; wrapped {
		return FormLifecyclePlan{}, errors.New("expected elements object, not a server response envelope")
	}
	return decodeFormLifecycle(doc)
}

func decodeFormLifecycle(elements map[string]any) (FormLifecyclePlan, error) {
	plan := FormLifecyclePlan{Events: []FormLifecycleEvent{}, Unresolved: []string{
		"Client modules and extension capability filters are unresolved; handlers are not executed.",
		"Only form-level events are described; element events and standard close checks are unresolved.",
	}}
	raw, exists := elements["event"]
	if !exists {
		return plan, nil
	}
	events, ok := raw.([]any)
	if !ok || len(events) > 1024 {
		return FormLifecyclePlan{}, errors.New("invalid form lifecycle events")
	}
	seen := make(map[string]bool, len(events))
	budget := 4096 // Bound total groups plus handlers, not just each array.
	for _, rawEvent := range events {
		doc, ok := rawEvent.(map[string]any)
		if !ok {
			return FormLifecyclePlan{}, errors.New("invalid form lifecycle event")
		}
		id, ok := doc["id"].(string)
		folded := strings.ToUpper(id)
		if !ok || !formUUID(id) || seen[folded] {
			return FormLifecyclePlan{}, errors.New("invalid or duplicate form lifecycle event ID")
		}
		seen[folded] = true
		rawGroups, ok := doc["handlers"].([]any)
		if !ok || len(rawGroups) > budget {
			return FormLifecyclePlan{}, errors.New("invalid form lifecycle handler groups")
		}
		budget -= len(rawGroups)
		event := FormLifecycleEvent{ID: id, EntryGroup: len(rawGroups) - 1, Groups: []FormHandlerGroup{}}
		switch folded {
		case "3CCC650E-F631-4CAE-8E33-3EAAC610B5F9":
			event.CandidateName = "OnOpen"
		case "52DBB775-1631-4FD5-8C55-1615B5881DAC":
			event.CandidateName = "BeforeClose"
		case "CA21CD18-35B2-4281-B5C8-016ECC8DA8AC":
			event.CandidateName = "OnClose"
		}
		for index, rawGroup := range rawGroups {
			groupDoc, ok := rawGroup.(map[string]any)
			if !ok {
				return FormLifecyclePlan{}, errors.New("invalid form lifecycle handler group")
			}
			rawHandlers, ok := groupDoc["handler"].([]any)
			if !ok || len(rawHandlers) > budget {
				return FormLifecyclePlan{}, errors.New("invalid form lifecycle handlers")
			}
			budget -= len(rawHandlers)
			group := FormHandlerGroup{InheritedGroup: index - 1, Handlers: []FormLifecycleHandler{}}
			override := false
			for _, rawHandler := range rawHandlers {
				handler, ok := rawHandler.(map[string]any)
				if !ok {
					return FormLifecyclePlan{}, errors.New("invalid form lifecycle handler")
				}
				name, ok := handler["handlerName"].(string)
				if !ok || !validValueText(name, 1024) {
					return FormLifecyclePlan{}, errors.New("invalid form lifecycle handler name")
				}
				phase, ok := handler["callType"].(string)
				if !ok || (phase != "Before" && phase != "After" && phase != "Override") {
					return FormLifecyclePlan{}, errors.New("unsupported form lifecycle handler phase")
				}
				if phase == "Override" {
					if override {
						return FormLifecyclePlan{}, errors.New("ambiguous form lifecycle overrides")
					}
					override = true
				}
				group.Handlers = append(group.Handlers, FormLifecycleHandler{Name: name, Phase: phase})
			}
			event.Groups = append(event.Groups, group)
		}
		plan.Events = append(plan.Events, event)
	}
	return plan, nil
}
