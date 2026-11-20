package onec

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"onec/wire"
	"strconv"
	"strings"
	"unicode/utf8"
)

type sessionHeader struct {
	raw string
	sid wire.UUID
}

func parseSession(h *wire.HTTP) (sessionHeader, error) {
	var out sessionHeader
	bad := errors.New("missing or invalid application session")
	values := h.Header("vrs-session")
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 8192 {
		return out, bad
	}
	raw := values[0]
	for _, c := range raw {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_ .\t-", c) {
			return out, bad
		}
	}
	prefix := raw
	id, e := wire.ParseUUID(prefix)
	if e != nil {
		encoded := strings.Map(func(r rune) rune {
			switch r {
			case ' ', '\t':
				return -1
			case '-':
				return '+'
			case '_':
				return '/'
			case '.':
				return '='
			}
			return r
		}, raw)
		if len(encoded)%4 == 1 {
			return out, bad
		}
		encoded += strings.Repeat("=", (4-len(encoded)%4)%4)
		b, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil || len(b) < 36 {
			return out, bad
		}
		id, e = wire.ParseUUID(string(b[:36]))
		if e != nil {
			return out, bad
		}
	}
	if id == (wire.UUID{}) {
		return out, bad
	}
	return sessionHeader{raw, id}, nil
}
func decodeBody(h *wire.HTTP, limit int) ([]byte, error) {
	if len(h.Body) > limit {
		return nil, errors.New("response body limit")
	}
	enc := h.Header("content-encoding")
	if len(enc) == 0 {
		return h.Body, nil
	}
	if len(enc) != 1 || enc[0] != "deflate" {
		return nil, errors.New("unsupported response encoding")
	}
	source := bytes.NewReader(h.Body)
	r := flate.NewReader(source)
	defer r.Close()
	b, e := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if e != nil || len(b) > limit || source.Len() != 0 {
		return nil, errors.New("invalid or oversized deflate response")
	}
	return b, nil
}
func strictJSON(b []byte) (map[string]any, error) {
	if len(b) > wire.MaxFile || !utf8.Valid(b) {
		return nil, errors.New("invalid JSON bytes")
	}
	b = bytes.TrimPrefix(b, []byte{239, 187, 191})
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 64 {
			return nil, errors.New("JSON depth limit")
		}
		token, e := d.Token()
		if e != nil {
			return nil, errors.New("invalid JSON")
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return token, nil
		}
		switch delimiter {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return nil, errors.New("invalid JSON property")
				}
				name, ok := key.(string)
				if !ok {
					return nil, errors.New("invalid JSON property")
				}
				if _, ok = m[name]; ok {
					return nil, errors.New("duplicate JSON property")
				}
				v, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				m[name] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, errors.New("invalid JSON object")
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, errors.New("invalid JSON array")
			}
			return a, nil
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	}
	value, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("JSON trailing data")
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("expected JSON object")
	}
	return m, nil
}
func responseJSON(h *wire.HTTP) (map[string]any, error) {
	if h.Status != 200 {
		return nil, &StatusError{Operation: "JSON response", Status: h.Status}
	}
	types := h.Header("content-type")
	if len(types) != 1 || strings.ToLower(strings.TrimSpace(strings.Split(types[0], ";")[0])) != "application/json" {
		return nil, errors.New("expected application/json response")
	}
	b, e := decodeBody(h, wire.MaxFile)
	if e != nil {
		return nil, e
	}
	return strictJSON(b)
}
func applicationXML(h *wire.HTTP) error {
	b, e := decodeBody(h, wire.MaxFile)
	if e != nil {
		return e
	}
	b = bytes.TrimPrefix(b, []byte{239, 187, 191})
	if bytes.Contains(b, []byte("<!")) {
		return errors.New("unsupported application XML declarations")
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	depth := 0
	roots := 0
	children := map[string]bool{}
	const core = "http://v8.1c.ru/8.2/managed-application/core"
	for {
		token, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return errors.New("invalid application XML")
		}
		switch x := token.(type) {
		case xml.StartElement:
			depth++
			if depth > 64 {
				return errors.New("application XML depth limit")
			}
			if depth == 1 {
				roots++
				if x.Name.Space != "http://v8.1c.ru/8.2/mngsrv/ws" || x.Name.Local != "response" {
					return errors.New("unexpected application XML root")
				}
			}
			if depth == 2 && x.Name.Space == core {
				children[x.Name.Local] = true
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(x)) != "" {
				return errors.New("application XML trailing data")
			}
		}
	}
	if roots != 1 || depth != 0 {
		return errors.New("incomplete application XML")
	}
	for _, name := range []string{"infoBaseInstanceID", "config", "user", "seance"} {
		if !children[name] {
			return errors.New("incomplete application metadata")
		}
	}
	return nil
}

// StatusError exposes only an operation name and status, never server bodies.
type StatusError struct {
	Operation string
	Status    int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d", e.Operation, e.Status)
}
func queryEscape(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
func (c *Client) loginTarget(sid *wire.UUID, passwordMode bool) string {
	target := "/e1cib/login?vl=ru_RU&version=" + queryEscape(c.cfg.Profile.Version) + "&clnId=" + c.clientID.String()
	if sid != nil {
		target += "&sid=" + sid.String()
	}
	if passwordMode {
		target += "&nowa"
	}
	return target
}
func (c *Client) pdu(method, target string, body []byte, contentType, accept, session string, sync uint32) ([]byte, error) {
	headers := []string{method + " " + target + " HTTP/1.1", "1C-BaseLocation: e1c://server/" + c.cfg.ServerName + "/" + c.cfg.Infobase, "User-Agent: " + c.cfg.Profile.Application, "1C-ApplicationName: " + c.cfg.Profile.Application, fmt.Sprintf("1C-ConnectString: Srvr=\"%s\";Ref=\"%s\";", c.cfg.ServerName, c.cfg.Infobase), "Accept-Encoding: deflate", "Accept-Language: ru-RU", "Accept-Charset: utf-8"}
	if contentType != "" {
		headers = append(headers, "Content-Type: "+contentType)
	}
	if accept != "" {
		headers = append(headers, "Accept: "+accept)
	}
	if session != "" {
		headers = append(headers, "vrs-session: "+session)
	}
	if sync > 0 {
		headers = append(headers, "Pragma: sync="+strconv.FormatUint(uint64(sync), 10))
	}
	headers = append(headers, "Content-Length: "+strconv.Itoa(len(body)))
	out := append([]byte(strings.Join(headers, "\r\n")+"\r\n\r\n"), body...)
	if _, e := wire.ParseHTTP(out, false); e != nil {
		return nil, e
	}
	return out, nil
}

// LegacyCredentialField is the observed username/backspace/password Base64 form.
// The result is credential material, not a password hash; do not log it.
func LegacyCredentialField(user, password string) (string, error) {
	if user == "" || utf8.RuneCountInString(user) > 256 || utf8.RuneCountInString(password) > 1024 || !utf8.ValidString(user) || !utf8.ValidString(password) || strings.ContainsAny(user+password, "\x00\x08\r\n") {
		return "", errors.New("invalid legacy credential length or characters")
	}
	s := base64.StdEncoding.EncodeToString([]byte(user + "\b" + password))
	var out strings.Builder
	for len(s) > 0 {
		n := min(1024, len(s))
		block := s[:n]
		s = s[n:]
		if len(block) <= 64 {
			out.WriteString(block)
			continue
		}
		for len(block) > 0 {
			m := min(64, len(block))
			out.WriteString(block[:m])
			if m == 64 {
				out.WriteString("\r\n")
			}
			block = block[m:]
		}
	}
	return out.String(), nil
}
