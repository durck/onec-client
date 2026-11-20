package inspect

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"encoding/xml"
	"io"
	"mime"
	"net/url"
	"onec/wire"
	"strings"
	"unicode/utf8"
)

const maxBodyBytes = 1024 * 1024
const maxBodyNodes = 100000
const maxFiles = 32
const maxRecordIssues = 64

type Chunk struct {
	Offset int `json:"record_offset"`
	End    int `json:"record_end"`
	Bytes  int `json:"bytes"`
}

type File struct {
	Offset int     `json:"record_offset"`
	Bytes  int     `json:"bytes"`
	Chunks []Chunk `json:"chunks"`
	HTTP   *HTTP   `json:"http,omitempty"`
}

type HTTP struct {
	Direction       string         `json:"direction"`
	Method          string         `json:"method,omitempty"`
	Status          int            `json:"status,omitempty"`
	Endpoint        string         `json:"endpoint,omitempty"`
	HasQuery        bool           `json:"has_query,omitempty"`
	HeaderCount     int            `json:"header_count"`
	KnownHeaders    map[string]int `json:"known_header_counts"`
	ContentType     string         `json:"content_type"`
	ContentEncoding string         `json:"content_encoding"`
	Body            Body           `json:"body"`
}

// Body exposes structure counts, never keys, element names, attributes, string
// values, numeric values, comments, or decoded body bytes.
type Body struct {
	Bytes        int    `json:"bytes"`
	DecodedBytes int    `json:"decoded_bytes"`
	Format       string `json:"format"`
	Valid        *bool  `json:"structure_valid,omitempty"`
	Objects      int    `json:"objects,omitempty"`
	Arrays       int    `json:"arrays,omitempty"`
	Properties   int    `json:"properties,omitempty"`
	Scalars      int    `json:"scalars,omitempty"`
	Elements     int    `json:"elements,omitempty"`
	Attributes   int    `json:"attributes,omitempty"`
	MaxDepth     int    `json:"max_depth,omitempty"`
	Issue        string `json:"issue,omitempty"`
}

func addRecordIssue(r *RPC, issues *[]Issue, issue Issue) {
	if len(*issues) < maxRecordIssues {
		*issues = append(*issues, issue)
	} else {
		r.IssuesOmitted++
	}
}

func walkValues(xs []any, r *RPC, issues *[]Issue) {
	for _, v := range xs {
		x, ok := wire.List(v, -1)
		if !ok {
			continue
		}
		if len(x) >= 2 && wire.IsString(x[0], "#") {
			if wire.IsGUID(x[1], wire.HTTPType) {
				if len(r.Files) == maxFiles {
					r.FilesOmitted++
					// Emit the bound once; traversal can still find security blobs.
					if len(*issues) == 0 || (*issues)[len(*issues)-1].Code != "http_file_limit" {
						addRecordIssue(r, issues, Issue{"http_file", "http_file_limit", int64(summarizeValue(v).Offset)})
					}
					continue
				}
				file, code := inspectFile(x)
				r.Files = append(r.Files, file)
				if code != "" {
					addRecordIssue(r, issues, Issue{"http_file", code, int64(file.Offset)})
				} else if file.HTTP != nil && file.HTTP.Body.Issue != "" {
					addRecordIssue(r, issues, Issue{"body", file.HTTP.Body.Issue, int64(file.Offset)})
				}
				continue
			}
			if wire.IsGUID(x[1], wire.BlobType) {
				r.SecurityBlobs++
				n, ok := blobLength(x)
				if ok {
					r.SecurityBytes += n
				} else {
					addRecordIssue(r, issues, Issue{"rpc", "invalid_security_blob", int64(summarizeValue(v).Offset)})
				}
				continue
			}
		}
		walkValues(x, r, issues)
	}
}

func blobLength(x []any) (int, bool) {
	if len(x) != 3 {
		return 0, false
	}
	l, ok := wire.List(x[2], 2)
	if !ok {
		return 0, false
	}
	n, err := wire.Number(l[0])
	if err != nil {
		return 0, false
	}
	a, ok := l[1].(wire.Atom)
	if !ok || a.Tag&192 != 0 {
		return 0, false
	}
	b, err := wire.Bytes(a)
	return len(b), err == nil && n == uint32(len(b)) && len(b) <= 65535
}

func isHTTPRequestCandidate(top []any) bool {
	if len(top) == 0 {
		return false
	}
	x, ok := wire.List(top[0], -1)
	if !ok || len(x) < 6 || !wire.IsNumber(x[0], 0) {
		return false
	}
	return wire.IsGUID(x[4], wire.HTTPInterface) || wire.IsGUID(x[5], wire.HTTPInterface)
}

func isHTTPRequest(top []any) bool {
	if len(top) != 1 {
		return false
	}
	x, ok := wire.List(top[0], -1)
	if !ok || (len(x) != 14 && len(x) != 15) || !wire.IsNumber(x[0], 0) {
		return false
	}
	if _, err := wire.GUID(x[1]); err != nil {
		return false
	}
	if _, err := wire.Number(x[2]); err != nil {
		return false
	}
	start := 3
	if len(x) == 15 {
		if !wire.IsNumber(x[3], 0) {
			return false
		}
		start++
	}
	if !wire.IsGUID(x[start+1], wire.HTTPInterface) {
		return false
	}
	for i, n := range map[int]uint32{0: 4, 2: 0, 3: 1, 4: 3, 5: 0, 7: 2, 9: 2} {
		if !wire.IsNumber(x[start+i], n) {
			return false
		}
	}
	blob, ok := wire.List(x[start+8], -1)
	if !ok || len(blob) < 2 || !wire.IsString(blob[0], "#") || !wire.IsGUID(blob[1], wire.BlobType) {
		return false
	}
	if _, ok := blobLength(blob); !ok {
		return false
	}
	flag, ok := wire.List(x[start+10], 2)
	if !ok || !wire.IsString(flag[0], "B") || (!wire.IsNumber(flag[1], 0) && !wire.IsNumber(flag[1], 1)) {
		return false
	}
	file, ok := wire.List(x[start+6], -1)
	if !ok || len(file) < 2 || !wire.IsString(file[0], "#") || !wire.IsGUID(file[1], wire.HTTPType) {
		return false
	}
	_, code := inspectFile(file)
	return code == ""
}

func isHTTPReplyCandidate(top []any) bool {
	if len(top) == 0 {
		return false
	}
	x, ok := wire.List(top[0], -1)
	return ok && len(x) >= 5 && wire.IsNumber(x[0], 1) && wire.IsNumber(x[4], 3)
}

func inspectFile(x []any) (File, string) {
	f := File{Offset: summarizeValue(x).Offset, Chunks: []Chunk{}}
	if len(x) != 7 {
		return f, "invalid_http_file"
	}
	n, err := wire.Number(x[2])
	if err != nil || n == 0 {
		return f, "invalid_http_file"
	}
	for _, v := range x[3:6] {
		if !wire.IsNumber(v, 0) {
			return f, "invalid_http_file"
		}
	}
	parts, ok := wire.List(x[6], -1)
	if !ok || len(parts) == 0 || len(parts) > wire.MaxFile/16384+1 {
		return f, "invalid_http_chunks"
	}
	var data []byte
	for i, v := range parts {
		b, err := wire.Bytes(v)
		if err != nil {
			return f, "invalid_http_chunk"
		}
		a, ok := v.(wire.Atom)
		if !ok {
			return f, "invalid_http_chunk"
		}
		f.Chunks = append(f.Chunks, Chunk{Offset: a.Offset, End: a.End, Bytes: len(b)})
		if (i < len(parts)-1 && len(b) != 16384) || (i == len(parts)-1 && len(b) >= 16384) {
			return f, "invalid_http_chunk_boundary"
		}
		if len(b) > wire.MaxFile-len(data) {
			return f, "http_file_limit"
		}
		data = append(data, b...)
		f.Bytes += len(b)
	}
	h, err := wire.ParseHTTP(data, true)
	if err != nil {
		return f, "invalid_embedded_http"
	}
	f.HTTP = summarizeHTTP(h)
	return f, ""
}

func summarizeHTTP(h *wire.HTTP) *HTTP {
	out := &HTTP{Direction: "response", Status: h.Status, KnownHeaders: map[string]int{}, ContentType: "unspecified", ContentEncoding: "identity"}
	if h.Method != "" {
		out.Direction = "request"
		out.Method = "other"
		switch h.Method {
		case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
			out.Method = h.Method
		}
		out.Endpoint = "redacted"
		if u, err := url.ParseRequestURI(h.Target); err == nil {
			out.HasQuery = u.RawQuery != "" || u.ForceQuery
			// A fixed exact-path allowlist: never print arbitrary path segments.
			switch u.Path {
			case "/e1cib/login", "/e1cib/logout", "/e1cib/ibservice", "/e1cib/users", "/e1cib/settings", "/e1cib/authenticationSettings":
				out.Endpoint = u.Path
			}
		}
	}
	for k, values := range h.Headers {
		out.HeaderCount += len(values)
		switch k {
		case "content-type", "content-length", "content-encoding", "authorization", "proxy-authorization", "www-authenticate", "cookie", "set-cookie", "vrs-session":
			out.KnownHeaders[k] = len(values)
		}
	}
	if values := h.Header("content-type"); len(values) > 0 {
		out.ContentType = "other"
		if len(values) == 1 {
			media, _, err := mime.ParseMediaType(values[0])
			if err == nil {
				switch media {
				case "application/json", "application/xml", "text/xml", "application/octet-stream", "text/plain":
					out.ContentType = media
				}
			}
		}
	}
	if values := h.Header("content-encoding"); len(values) > 0 {
		out.ContentEncoding = "other"
		if len(values) == 1 {
			switch strings.ToLower(values[0]) {
			case "identity", "deflate":
				out.ContentEncoding = strings.ToLower(values[0])
			}
		}
	}
	out.Body = summarizeBody(h.Body, out.ContentType, out.ContentEncoding)
	return out
}

func summarizeBody(body []byte, media, encoding string) Body {
	out := Body{Bytes: len(body), DecodedBytes: len(body), Format: "opaque"}
	if encoding == "other" {
		out.DecodedBytes = 0
		out.Issue = "unsupported_content_encoding"
		return out
	}
	if encoding == "deflate" {
		source := bytes.NewReader(body)
		reader := flate.NewReader(source)
		decoded, err := io.ReadAll(io.LimitReader(reader, maxBodyBytes+1))
		reader.Close()
		if len(decoded) > maxBodyBytes {
			out.DecodedBytes = 0
			out.Issue = "decoded_body_limit"
			return out
		}
		if err != nil || source.Len() != 0 {
			out.DecodedBytes = 0
			out.Issue = "invalid_deflate"
			return out
		}
		body = decoded
		out.DecodedBytes = len(body)
	}
	if len(body) > maxBodyBytes {
		out.Issue = "decoded_body_limit"
		return out
	}
	if len(body) == 0 {
		out.Format = "empty"
		return out
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}))
	if media == "application/json" || (len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')) {
		out.Format = "json"
		valid := utf8.Valid(trimmed) && inspectJSON(trimmed, &out)
		out.Valid = &valid
		if !valid && out.Issue == "" {
			out.Issue = "invalid_json"
		}
	} else if media == "application/xml" || media == "text/xml" || (len(trimmed) > 0 && trimmed[0] == '<') {
		out.Format = "xml"
		valid := inspectXML(trimmed, &out)
		out.Valid = &valid
		if !valid && out.Issue == "" {
			out.Issue = "invalid_xml"
		}
	}
	return out
}

func inspectJSON(p []byte, out *Body) bool {
	d := json.NewDecoder(bytes.NewReader(p))
	d.UseNumber()
	nodes := 0
	var read func(int) bool
	read = func(depth int) bool {
		nodes++
		if depth > 64 || nodes > maxBodyNodes {
			out.Issue = "body_structure_limit"
			return false
		}
		out.MaxDepth = max(out.MaxDepth, depth)
		token, err := d.Token()
		if err != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			out.Scalars++
			return true
		}
		switch delim {
		case '{':
			out.Objects++
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return false
				}
				if _, ok := key.(string); !ok {
					return false
				}
				out.Properties++
				if !read(depth + 1) {
					return false
				}
			}
			close, err := d.Token()
			return err == nil && close == json.Delim('}')
		case '[':
			out.Arrays++
			for d.More() {
				if !read(depth + 1) {
					return false
				}
			}
			close, err := d.Token()
			return err == nil && close == json.Delim(']')
		}
		return false
	}
	if !read(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func inspectXML(p []byte, out *Body) bool {
	d := xml.NewDecoder(bytes.NewReader(p))
	depth, roots, nodes := 0, 0, 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			return depth == 0 && roots == 1
		}
		if err != nil {
			return false
		}
		nodes++
		if nodes > maxBodyNodes {
			out.Issue = "body_structure_limit"
			return false
		}
		switch x := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			out.MaxDepth = max(out.MaxDepth, depth)
			if depth > 64 || roots > 1 {
				if depth > 64 {
					out.Issue = "body_structure_limit"
				}
				return false
			}
			out.Elements++
			out.Attributes += len(x.Attr)
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(x)) > 0 {
				return false
			}
		case xml.Directive:
			out.Issue = "xml_directive_unsupported"
			return false
		}
	}
}
