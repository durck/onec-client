package onec

import (
	"encoding/json"
	"errors"
)

type contextProperties struct {
	Fields string `json:"fields,omitempty"`
	Values []any  `json:"v"`
}

type contextProposal struct {
	SinDesc   *uint64            `json:"sinDesc,omitempty"`
	Sin       *uint64            `json:"sin,omitempty"`
	Seq       *uint64            `json:"seq,omitempty"`
	Structure *contextProperties `json:"structure,omitempty"`
}

type contextDescriptions struct {
	RemoteKey    any    `json:"remoteKey"`
	TrackChanges bool   `json:"trackChanges"`
	SinDe        uint64 `json:"sinDe"`
	SeqDe        uint64 `json:"seqDe"`
	SinUo        uint64 `json:"sinUo"`
	SeqUo        uint64 `json:"seqUo"`
	Structure    []any  `json:"structure"`
}

// The platform's JSON-to-XML reader consumes metadata in source order:
// descriptor attributes precede nested fields and __content follows qualifiers.
// Go's sorted map encoding puts field before name and __content before length.
func (d contextDescriptions) MarshalJSON() ([]byte, error) {
	type orderedDescription struct {
		RemoteKey    any             `json:"remoteKey"`
		TrackChanges bool            `json:"trackChanges"`
		SinDe        uint64          `json:"sinDe"`
		SeqDe        uint64          `json:"seqDe"`
		SinUo        uint64          `json:"sinUo"`
		SeqUo        uint64          `json:"seqUo"`
		Structure    contextMetadata `json:"structure"`
	}
	return json.Marshal(orderedDescription{d.RemoteKey, d.TrackChanges, d.SinDe, d.SeqDe, d.SinUo, d.SeqUo, contextMetadata{d.Structure}})
}

type contextMetadata struct{ value any }

func (m contextMetadata) MarshalJSON() ([]byte, error) {
	switch value := m.value.(type) {
	case []any:
		out := make([]contextMetadata, len(value))
		for i, v := range value {
			out[i] = contextMetadata{v}
		}
		return json.Marshal(out)
	case map[string]any:
		keys := []string{}
		for _, key := range []string{"id", "name", "nameRu", "object", "length", "fixed", "digits", "precision", "unsigned", "date", "type", "field", "__content"} {
			if _, exists := value[key]; exists {
				keys = append(keys, key)
			}
		}
		if len(keys) != len(value) {
			return nil, errors.New("unsupported parameter descriptor member")
		}
		out := []byte{'{'}
		for i, key := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			name, _ := json.Marshal(key)
			encoded, err := json.Marshal(contextMetadata{value[key]})
			if err != nil {
				return nil, err
			}
			out = append(out, name...)
			out = append(out, ':')
			out = append(out, encoded...)
		}
		out = append(out, '}')
		return out, nil
	default:
		return json.Marshal(value)
	}
}

type contextParameters struct {
	Descriptions contextDescriptions `json:"descriptions"`
	Type         string              `json:"type"`
	Data         contextProperties   `json:"data"`
}

type contextCall struct {
	RemoteKey  any               `json:"rKey"`
	ID         string            `json:"id"`
	FID        string            `json:"fid"`
	FOP        any               `json:"fop,omitempty"`
	FOver      any               `json:"fover,omitempty"`
	USVer      any               `json:"usver,omitempty"`
	Method     formMethod        `json:"prm"`
	Changes    contextProposal   `json:"pchs"`
	Parameters contextParameters `json:"prms"`
	Dynamic    map[string]any    `json:"dd"`
}
