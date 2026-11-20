package onec

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"onec/wire"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxEPF = 384 * 1024
const StringType = "9B6ABF8B-0173-48E5-B0A0-83B21FCF63C5"
const BinaryType = "87126200-3E98-44E0-B931-CCB1D7EDC497"

type Value struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

func StringValue(v string) Value { return Value{StringType, v} }
func BinaryValue(v []byte) Value { return Value{BinaryType, append([]byte(nil), v...)} }

type Processing struct {
	owner     *Client
	reference string
}

func (Processing) String() string     { return "1C processing handle (redacted)" }
func (p Processing) GoString() string { return p.String() }

type Form struct {
	owner   *Client
	id, fid string
	state   *formState
}

// These field orders match the shipped client. The 1C application reader does
// not necessarily accept the alphabetic order produced by json.Marshal(map).
type formQuery struct {
	Key  string `json:"key"`
	Prms struct {
		Prm []any `json:"prm"`
	} `json:"prms"`
	MW     int  `json:"mw"`
	MH     int  `json:"mh"`
	CW     int  `json:"cw"`
	CH     int  `json:"ch"`
	Pres   bool `json:"pres"`
	Trdata bool `json:"trdata"`
	CF     bool `json:"cf"`
}
type formMethod struct {
	Name   string    `json:"name"`
	Types  *[]string `json:"#param,omitempty"`
	Params *[]any    `json:"param,omitempty"`
}
type formCall struct {
	ID      string     `json:"id"`
	FID     string     `json:"fid"`
	Generic formMethod `json:"generic"`
}

func (Form) String() string     { return "1C form handle (redacted)" }
func (f Form) GoString() string { return f.String() }
func validValueText(s string, max int) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func (c *Client) applicationReady() error {
	if e := c.usable(); e != nil {
		return e
	}
	if !c.authenticated || c.session == nil {
		return errors.New("authenticated application session required")
	}
	return nil
}
func (c *Client) UploadProcessing(ctx context.Context, epf []byte, filename string) (Processing, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out Processing
	if e := c.applicationReady(); e != nil {
		return out, e
	}
	if err := validateEPF(epf, filename); err != nil {
		return out, err
	}
	storage, e := wire.NewUUID()
	if e != nil {
		return out, e
	}
	boundaryID, e := wire.NewUUID()
	if e != nil {
		return out, e
	}
	boundary := "onec-" + hex.EncodeToString(boundaryID[:])
	if bytes.Contains(epf, []byte(boundary)) {
		return out, errors.New("multipart boundary collision")
	}
	var body bytes.Buffer
	for _, field := range [][2]string{{"storageId", storage.String()}, {"docType", "processing"}} {
		fmt.Fprintf(&body, "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n", boundary, field[0], field[1])
	}
	fmt.Fprintf(&body, "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", boundary, filename)
	body.Write(epf)
	fmt.Fprintf(&body, "\r\n--%s--\r\n", boundary)
	p, e := c.pdu("POST", "/e1cib/openDocument?seanceId="+queryEscape(c.session.raw), body.Bytes(), "multipart/form-data; boundary="+boundary, "application/json", "", 0)
	if e != nil {
		return out, e
	}
	h, e := c.exchangeHTTP(ctx, p)
	if e != nil {
		return out, e
	}
	if h.Status != 200 && h.Status != 201 {
		return out, c.processingUploadError(h, epf, "upload processing")
	}
	data, e := decodeBody(h, wire.MaxFile)
	if e != nil {
		return out, e
	}
	reference, e := parseUpload(data)
	if e != nil {
		return out, e
	}
	return Processing{c, reference}, nil
}

var uriEscape = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

// The tuple's delimiter identifies its encoding. Do not URI-decode a raw tuple:
// percent escapes can be literal bytes in the opaque processing reference.
func parseUpload(data []byte) (string, error) {
	if !utf8.Valid(data) {
		return "", errors.New("invalid upload response UTF-8")
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	switch {
	case strings.HasPrefix(text, "processing%08"):
		if strings.ContainsRune(text, '\b') {
			return "", errors.New("mixed upload response encodings")
		}
		protected := uriEscape.ReplaceAllStringFunc(text, func(s string) string {
			v, _ := hex.DecodeString(s[1:])
			if strings.ContainsRune(";/?:@&=+$,#", rune(v[0])) {
				return "%25" + s[1:]
			}
			return s
		})
		var e error
		text, e = url.PathUnescape(protected)
		if e != nil || !utf8.ValidString(text) {
			return "", errors.New("invalid URI upload response")
		}
	case strings.HasPrefix(text, "processing\b"):
	default:
		return "", errors.New("unsupported upload response profile")
	}
	fields := strings.Split(text, "\b")
	if len(fields) < 2 || len(fields) > 4 || fields[0] != "processing" || !validValueText(fields[1], 8192) {
		return "", errors.New("invalid external-processing upload result")
	}
	return fields[1], nil
}
func (c *Client) jsonRequest(ctx context.Context, target string, payload any) (map[string]any, error) {
	return c.jsonRequestDecoded(ctx, target, payload, responseJSON)
}

// Only form metadata callers supply the narrow form dialect decoder.
// Authentication and other application calls retain strict JSON parsing.
func (c *Client) jsonRequestDecoded(ctx context.Context, target string, payload any, decode func(*wire.HTTP) (map[string]any, error)) (map[string]any, error) {
	body, e := json.Marshal(map[string]any{"root": payload})
	if e != nil {
		return nil, errors.New("cannot encode application payload")
	}
	n, e := c.nextSync()
	if e != nil {
		return nil, e
	}
	p, e := c.pdu("POST", target, body, "application/json; charset=utf-8", "application/json", c.session.raw, n)
	if e != nil {
		return nil, e
	}
	h, e := c.exchangeHTTP(ctx, p)
	if e != nil {
		return nil, e
	}
	doc, e := decode(h)
	if e != nil {
		return nil, e
	}
	return applicationResponse(doc)
}

func applicationResponse(doc map[string]any) (map[string]any, error) {
	var out map[string]any
	count := 0
	for k, v := range doc {
		if strings.HasPrefix(k, "#") {
			continue
		}
		count++
		var ok bool
		out, ok = v.(map[string]any)
		if !ok {
			return nil, errors.New("invalid application response envelope")
		}
	}
	if count != 1 {
		return nil, errors.New("ambiguous application response envelope")
	}
	return out, nil
}
func (c *Client) OpenForm(ctx context.Context, processing Processing) (Form, error) {
	return c.OpenFormWithOptions(ctx, processing, FormOptions{})
}

// CallNoContext calls a server no-context function in the opened form.
// The form module's Export flag is not an authorization boundary. Only String,
// Number, Boolean, Date, Null and Binary argument payloads are supported.
// Undefined and reference registries are currently codec-only features.
func (c *Client) CallNoContext(ctx context.Context, form Form, method string, args ...Value) (Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out Value
	if e := c.applicationReady(); e != nil {
		return out, e
	}
	if e := c.checkForm(form); e != nil {
		return out, e
	}
	if !validValueText(method, 255) || len(args) > 32 {
		return out, errors.New("invalid method or argument count")
	}
	generic := formMethod{Name: method}
	if args != nil {
		types := []string{}
		values := []any{}
		for _, arg := range args {
			value, e := encodeFormValue(arg)
			if e != nil {
				return out, e
			}
			values = append(values, value)
			types = append(types, arg.Type)
		}
		generic.Types = &types
		generic.Params = &values
	}
	doc, e := c.jsonRequest(ctx, "/e1cib/logForm?cmd=callWOContext", formCall{form.id, form.fid, generic})
	if e != nil {
		return out, e
	}
	value, exists := doc["ret"]
	if !exists {
		return out, errors.New("missing method return value")
	}
	if marker, exists := doc["#ret"]; exists {
		s, ok := marker.(string)
		if !ok {
			return out, errors.New("invalid method return type")
		}
		id, e := wire.ParseUUID(s)
		if e != nil {
			return out, errors.New("invalid method return type")
		}
		out.Type = strings.ToUpper(id.String())
	}
	if out.Type == StringType {
		if _, ok := value.(string); !ok {
			return out, errors.New("invalid string return value")
		}
	}
	if out.Type == NumberType || out.Type == BooleanType || out.Type == DateType || out.Type == NullType {
		return decodeFormScalar(out.Type, value)
	}
	out.Value = value
	return out, nil
}

func encodeFormValue(arg Value) (any, error) {
	switch arg.Type {
	case StringType:
		s, ok := arg.Value.(string)
		if !ok || !utf8.ValidString(s) || utf8.RuneCountInString(s) > 65536 {
			return nil, errors.New("invalid string argument")
		}
		return s, nil
	case BinaryType:
		b, ok := arg.Value.([]byte)
		if !ok || len(b) > 65536 {
			return nil, errors.New("invalid binary argument")
		}
		return base64.StdEncoding.EncodeToString(b), nil
	case NumberType, BooleanType, DateType, NullType:
		encoded, err := (FormValueCodec{}).Marshal(arg)
		if err != nil {
			return nil, err
		}
		var value any
		if err := json.Unmarshal(encoded, &value); err != nil {
			return nil, errors.New("unsupported JSON argument")
		}
		return value, nil
	default:
		return nil, errors.New("unsupported argument type")
	}
}

func decodeFormScalar(typeID string, payload any) (Value, error) {
	if strings.EqualFold(typeID, NumberType) {
		if _, ok := payload.(float64); ok {
			return Value{}, errors.New("Number payload must retain exact decimal text")
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Value{}, errors.New("invalid scalar payload")
	}
	return (FormValueCodec{}).Unmarshal(typeID, encoded)
}
func (c *Client) ExecuteProcessing(ctx context.Context, epf []byte, filename, method string, args ...Value) (Value, error) {
	p, e := c.UploadProcessing(ctx, epf, filename)
	if e != nil {
		return Value{}, e
	}
	f, e := c.OpenForm(ctx, p)
	if e != nil {
		return Value{}, e
	}
	return c.CallNoContext(ctx, f, method, args...)
}
