package wire

import (
	"bytes"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const MaxFile = 512 * 1024

var HTTPInterface = MustUUID("bc15bd01-10bf-413c-a856-ddc907fcd123")
var HTTPType = MustUUID("bea56fd3-3695-49fc-bbc5-c8bc15f33d41")
var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
var responseLine = regexp.MustCompile(`^HTTP/(1\.[01]) ([0-9]{3})(?: [^\r\n]*)?$`)
var requestLine = regexp.MustCompile(`^([A-Z]+) ([^\x00-\x20]+) HTTP/(1\.[01])$`)

// The native HTTP IFile adapter disables separators inside its chunk stream.
// This is not the grammar used by ordinary RPC lists.
type httpFileChunks [][]byte

type HTTP struct {
	Status         int
	Method, Target string
	Headers        map[string][]string
	Body           []byte
}

func (h *HTTP) Header(name string) []string { return h.Headers[strings.ToLower(name)] }
func ParseHTTP(p []byte, boundedEmpty bool) (*HTTP, error) {
	bad := errors.New("invalid embedded HTTP PDU")
	if len(p) > MaxFile {
		return nil, errors.New("HTTP file limit exceeded")
	}
	sep := bytes.Index(p, []byte("\r\n\r\n"))
	var head, body []byte
	if sep < 0 {
		if !boundedEmpty || !bytes.HasSuffix(p, []byte("\r\n")) {
			return nil, bad
		}
		head = p[:len(p)-2]
	} else {
		head = p[:sep]
		body = p[sep+4:]
	}
	if len(head) > 65536 {
		return nil, bad
	}
	lines := strings.Split(string(head), "\r\n")
	h := &HTTP{Headers: map[string][]string{}, Body: body}
	if m := responseLine.FindStringSubmatch(lines[0]); m != nil {
		h.Status, _ = strconv.Atoi(m[2])
	} else if m := requestLine.FindStringSubmatch(lines[0]); m != nil {
		h.Method, h.Target = m[1], m[2]
		u, e := url.ParseRequestURI(h.Target)
		if e != nil || !strings.HasPrefix(h.Target, "/") || u.Host != "" || u.Scheme != "" || u.Fragment != "" || strings.Contains(h.Target, "#") {
			return nil, bad
		}
	} else {
		return nil, bad
	}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !headerName.MatchString(name) {
			return nil, bad
		}
		for _, c := range []byte(value) {
			if c < 32 && c != '\t' || c == 127 {
				return nil, bad
			}
		}
		key := strings.ToLower(name)
		h.Headers[key] = append(h.Headers[key], strings.Trim(value, " \t"))
	}
	if _, ok := h.Headers["transfer-encoding"]; ok {
		return nil, errors.New("transfer encoding is outside the observed subset")
	}
	lens := h.Header("content-length")
	if len(lens) != 1 || len(lens[0]) == 0 || len(lens[0]) > 20 {
		return nil, bad
	}
	for _, c := range lens[0] {
		if c < '0' || c > '9' {
			return nil, bad
		}
	}
	n, e := strconv.ParseUint(lens[0], 10, 64)
	if e != nil || n != uint64(len(body)) {
		return nil, errors.New("HTTP content length mismatch")
	}
	if sep < 0 && (h.Status == 0 || n != 0) {
		return nil, bad
	}
	return h, nil
}
func HTTPFile(p []byte) ([]any, error) {
	if len(p) == 0 || len(p) > MaxFile {
		return nil, errors.New("HTTP file size limit")
	}
	chunks := httpFileChunks{}
	for i := 0; i < len(p); i += 16384 {
		chunks = append(chunks, p[i:min(i+16384, len(p))])
	}
	if len(p)%16384 == 0 {
		chunks = append(chunks, []byte{})
	}
	return []any{"#", HTTPType, 1, 0, 0, 0, chunks}, nil
}
func HTTPRequest(target UUID, counter uint32, pdu, token []byte, security, continuation bool) ([]byte, error) {
	h, e := ParseHTTP(pdu, false)
	if e != nil {
		return nil, e
	}
	if h.Method == "" {
		return nil, errors.New("expected request PDU")
	}
	f, e := HTTPFile(pdu)
	if e != nil {
		return nil, e
	}
	r := []any{0, target, counter}
	if continuation {
		r = append(r, 0)
	}
	flag := 0
	if security {
		flag = 1
	}
	r = append(r, 4, HTTPInterface, 0, 1, 3, 0, f, 2, SecurityBlob(token), 2, []any{"B", flag})
	return Pack(r)
}
func readBlob(v any) ([]byte, error) {
	bad := errors.New("invalid security blob")
	x, ok := List(v, 3)
	if !ok || !IsString(x[0], "#") || !IsGUID(x[1], BlobType) {
		return nil, bad
	}
	l, ok := List(x[2], 2)
	if !ok {
		return nil, bad
	}
	n, e := Number(l[0])
	if e != nil {
		return nil, bad
	}
	a, ok := l[1].(Atom)
	if !ok || a.Tag&192 != 0 {
		return nil, bad
	}
	b, e := Bytes(a)
	if e != nil || n != uint32(len(b)) || len(b) > 65535 {
		return nil, bad
	}
	return b, nil
}
func readFile(v any) ([]byte, error) {
	if x, ok := List(v, 1); ok && IsString(x[0], "U") {
		return nil, nil
	}
	bad := errors.New("invalid native HTTP file")
	x, ok := List(v, 7)
	if !ok || !IsString(x[0], "#") || !IsGUID(x[1], HTTPType) {
		return nil, bad
	}
	n, e := Number(x[2])
	if e != nil || n == 0 {
		return nil, bad
	}
	for _, v := range x[3:6] {
		if !IsNumber(v, 0) {
			return nil, bad
		}
	}
	chunks, ok := List(x[6], -1)
	if !ok || len(chunks) == 0 {
		return nil, bad
	}
	out := []byte{}
	for i, v := range chunks {
		b, e := Bytes(v)
		if e != nil {
			return nil, e
		}
		if i < len(chunks)-1 && len(b) != 16384 || i == len(chunks)-1 && len(b) >= 16384 || len(out)+len(b) > MaxFile {
			return nil, bad
		}
		out = append(out, b...)
	}
	if _, e := ParseHTTP(out, true); e != nil {
		return nil, e
	}
	return out, nil
}

type HTTPReply struct {
	PDU, Token       []byte
	SecurityComplete bool
}

func ParseHTTPReply(p []byte) (HTTPReply, error) {
	var out HTTPReply
	bad := errors.New("invalid HTTP RPC reply")
	if len(p) > 1024*1024 {
		return out, bad
	}
	top, e := DecodeTree(p)
	if e != nil {
		return out, e
	}
	if len(top) != 2 || !IsNumber(top[1], 2) {
		return out, bad
	}
	if r, ok := List(top[0], -1); ok {
		if native := parseNativeRPCError(r); native != nil {
			return out, native
		}
	}
	r, ok := List(top[0], 11)
	if !ok {
		return out, bad
	}
	for i, n := range map[int]uint32{0: 1, 2: 1, 4: 3, 5: 0, 6: 2, 8: 2, 10: 0} {
		if !IsNumber(r[i], n) {
			return out, bad
		}
	}
	f, ok := List(r[9], 2)
	if !ok || !IsString(f[0], "B") || (!IsNumber(f[1], 0) && !IsNumber(f[1], 1)) {
		return out, bad
	}
	out.SecurityComplete = IsNumber(f[1], 1)
	out.Token, e = readBlob(r[7])
	if e != nil {
		return out, e
	}
	out.PDU, e = readFile(r[3])
	return out, e
}
