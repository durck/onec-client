package onec

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"onec/wire"
	"strings"
)

// These values are cache/version selectors, not authentication credentials.
// Missing selectors do not invalidate a login, but form discovery needs them.
type applicationMetadata struct {
	assemblyVersion string
	configVersion   string
	rolesID         string
}

func metadataSelector(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !validValueText(value, 256) {
		return "", errors.New("invalid application metadata selector")
	}
	return value, nil
}

func applicationMetadataXML(h *wire.HTTP) (applicationMetadata, error) {
	var out applicationMetadata
	if err := applicationXML(h); err != nil {
		return out, err
	}
	b, err := decodeBody(h, wire.MaxFile)
	if err != nil {
		return out, err
	}
	d := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(b, []byte{239, 187, 191})))
	depth := 0
	active := ""
	seen := map[string]bool{}
	var text strings.Builder
	for {
		token, err := d.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return applicationMetadata{}, errors.New("invalid application metadata")
		}
		switch x := token.(type) {
		case xml.StartElement:
			depth++
			// Older/minimal application documents may carry an empty or structured
			// config element. Only a scalar selector enables configuration modules.
			if active == "config" {
				active = ""
			}
			if active != "" {
				return applicationMetadata{}, errors.New("non-scalar application metadata selector")
			}
			if depth == 2 && x.Name.Space == "http://v8.1c.ru/8.2/managed-application/core" && (x.Name.Local == "assemblyVersion" || x.Name.Local == "rolesID" || x.Name.Local == "config") {
				active = x.Name.Local
				if seen[active] {
					return applicationMetadata{}, errors.New("duplicate application metadata selector")
				}
				seen[active] = true
				text.Reset()
			}
		case xml.CharData:
			if active != "" {
				if text.Len()+len(x) > 1024 {
					return applicationMetadata{}, errors.New("application metadata selector length limit")
				}
				text.Write(x)
			}
		case xml.EndElement:
			if depth == 2 && active != "" {
				if active == "config" && strings.TrimSpace(text.String()) == "" {
					active = ""
					depth--
					continue
				}
				value, err := metadataSelector(text.String())
				if err != nil {
					return applicationMetadata{}, err
				}
				if active == "assemblyVersion" {
					out.assemblyVersion = value
				} else if active == "config" {
					out.configVersion = value
				} else {
					out.rolesID = value
				}
				active = ""
			}
			depth--
		}
	}
}

func applicationMetadataJSON(app map[string]any) (applicationMetadata, error) {
	var out applicationMetadata
	for _, name := range []string{"assemblyVersion", "rolesID", "config"} {
		raw, exists := app[name]
		if !exists {
			continue
		}
		if name == "config" {
			if value, ok := raw.(string); !ok || strings.TrimSpace(value) == "" {
				continue
			}
		}
		var value string
		switch v := raw.(type) {
		case string:
			value = v
		case json.Number:
			if name != "rolesID" {
				return out, errors.New("invalid application metadata selector type")
			}
			value = v.String()
		default:
			return out, errors.New("invalid application metadata selector type")
		}
		value, err := metadataSelector(value)
		if err != nil {
			return applicationMetadata{}, err
		}
		if name == "assemblyVersion" {
			out.assemblyVersion = value
		} else if name == "config" {
			out.configVersion = value
		} else {
			out.rolesID = value
		}
	}
	return out, nil
}
