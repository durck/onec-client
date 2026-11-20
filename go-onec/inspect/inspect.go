// Package inspect produces bounded, redacted reports from an offline,
// unidirectional, reassembled native 1C TCP byte stream. It never opens a socket.
package inspect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"onec/wire"
)

const (
	MaxInputBytes  = 64 * 1024 * 1024
	MaxRecordBytes = 16 * 1024 * 1024
	MaxAtoms       = 250000
	MaxEvents      = 16384
)

// Options are local resource limits, not claims about platform limits.
// Zero values select defaults. Values above the hard ceilings are rejected.
type Options struct {
	InputBytes  int `json:"input_bytes"`
	RecordBytes int `json:"record_bytes"`
	Atoms       int `json:"atoms_per_record"`
	Events      int `json:"events"`
}

func (o Options) normalized() (Options, error) {
	if o.InputBytes == 0 {
		o.InputBytes = MaxInputBytes
	}
	if o.RecordBytes == 0 {
		o.RecordBytes = 1024 * 1024
	}
	if o.Atoms == 0 {
		o.Atoms = 100000
	}
	if o.Events == 0 {
		o.Events = 4096
	}
	if o.InputBytes < 1 || o.InputBytes > MaxInputBytes || o.RecordBytes < 1 || o.RecordBytes > MaxRecordBytes || o.Atoms < 1 || o.Atoms > MaxAtoms || o.Events < 1 || o.Events > MaxEvents {
		return o, errors.New("invalid inspector limits")
	}
	return o, nil
}

// Issue messages are fixed vocabulary: never copy error strings from decoders,
// readers, URLs, files, or capture contents into a report.
type Issue struct {
	Layer  string `json:"layer"`
	Code   string `json:"code"`
	Offset int64  `json:"offset"`
}

type Counts struct {
	Records      int `json:"records"`
	Controls     int `json:"controls"`
	Greetings    int `json:"greetings"`
	HTTPFiles    int `json:"http_files"`
	HTTPMessages int `json:"http_messages"`
}

type Report struct {
	Format         string  `json:"format"`
	Redacted       bool    `json:"redacted"`
	InputBytesRead int     `json:"input_bytes_read"`
	BytesExamined  int     `json:"bytes_examined"`
	Complete       bool    `json:"complete"`
	Limits         Options `json:"limits"`
	Counts         Counts  `json:"counts"`
	Events         []Event `json:"events"`
	Issues         []Issue `json:"issues"`
}

type Event struct {
	Index        int    `json:"index"`
	Kind         string `json:"kind"`
	WireStart    int64  `json:"wire_start"`
	WireEnd      int64  `json:"wire_end"`
	PayloadBytes int    `json:"payload_bytes"`
	// Record spans include intervening control events. Offsets are half-open.
	RPC    *RPC    `json:"rpc,omitempty"`
	Issues []Issue `json:"issues,omitempty"`
}

type RPC struct {
	Encoding         string         `json:"encoding"`
	Shape            string         `json:"shape"`
	TopValues        int            `json:"top_values"`
	Atoms            int            `json:"atoms,omitempty"`
	Kinds            map[string]int `json:"atom_kinds,omitempty"`
	Values           []Value        `json:"top_value_summaries,omitempty"`
	SummariesOmitted int            `json:"top_summaries_omitted,omitempty"`
	ReplyTrailer     bool           `json:"reply_trailer_2,omitempty"`
	SecurityBlobs    int            `json:"security_blobs,omitempty"`
	SecurityBytes    int            `json:"security_bytes,omitempty"`
	IssuesOmitted    int            `json:"issues_omitted,omitempty"`
	FilesOmitted     int            `json:"http_files_omitted,omitempty"`
	Files            []File         `json:"http_files,omitempty"`
}

// Value describes a top-level value without serializing its contents.
type Value struct {
	Kind   string `json:"kind"`
	Items  int    `json:"items,omitempty"`
	Offset int    `json:"record_offset"`
	End    int    `json:"record_end"`
}

// Analyze reads at most InputBytes+1 bytes. Input failures and parse failures
// are reported using fixed issue codes; invalid options are the only error.
// Existing captures are never changed, and no capture paths enter the report.
func Analyze(r io.Reader, options Options) (Report, error) {
	o, err := options.normalized()
	if err != nil {
		return Report{}, err
	}
	report := Report{Format: "onec-reassembled-tcp-v1", Redacted: true, Limits: o, Events: []Event{}, Issues: []Issue{}}
	p, readErr := io.ReadAll(io.LimitReader(r, int64(o.InputBytes)+1))
	report.InputBytesRead = len(p)
	if readErr != nil {
		report.Issues = append(report.Issues, Issue{"input", "read_failed", int64(len(p))})
	}
	if len(p) > o.InputBytes {
		report.Issues = append(report.Issues, Issue{"input", "input_limit", int64(o.InputBytes)})
		p = p[:o.InputBytes]
	}
	if len(p) == 0 {
		report.Issues = append(report.Issues, Issue{"input", "empty_input", 0})
		return report, nil
	}
	if isCaptureContainer(p) {
		report.Issues = append(report.Issues, Issue{"input", "pcap_requires_tcp_reassembly", 0})
		return report, nil
	}
	base := 0
	if bytes.HasPrefix(p, wire.Greeting) {
		report.Events = append(report.Events, Event{Index: 1, Kind: "greeting", WireEnd: 5, PayloadBytes: 5})
		report.Counts.Greetings++
		base = len(wire.Greeting)
	} else if len(p) < len(wire.Greeting) && bytes.HasPrefix(wire.Greeting, p) {
		report.BytesExamined = len(p)
		report.Issues = append(report.Issues, Issue{"transport", "incomplete_greeting", 0})
		return report, nil
	}
	d, _ := wire.NewDecoder(o.RecordBytes)
	recordStart := int64(base)
	failed := false
	report.BytesExamined = base
	// Feed one byte at a time so a later limit failure cannot discard completed
	// events: wire.Decoder.Feed intentionally returns nil events on error.
	// Input and record caps bound this linear pass. No per-byte payload copies.
	for i := base; i < len(p); i++ {
		if len(report.Events) >= o.Events {
			report.Issues = append(report.Issues, Issue{"transport", "event_limit", int64(i)})
			failed = true
			break
		}
		events, e := d.Feed(p[i : i+1])
		report.BytesExamined = i + 1
		if e != nil {
			report.Issues = append(report.Issues, Issue{"transport", "record_limit", int64(i)})
			failed = true
			break
		}
		for _, event := range events {
			end := event.WireEnd + int64(base)
			v := Event{Index: len(report.Events) + 1, Kind: event.Kind, WireStart: recordStart, WireEnd: end, PayloadBytes: len(event.Payload)}
			if event.Kind == "record" {
				report.Counts.Records++
				v.RPC, v.Issues = inspectRecord(event.Payload, o)
				if v.RPC != nil {
					for _, file := range v.RPC.Files {
						report.Counts.HTTPFiles++
						if file.HTTP != nil {
							report.Counts.HTTPMessages++
						}
					}
				}
				recordStart = end
			} else {
				report.Counts.Controls++
				v.WireStart = end - int64(4+len(event.Payload))
				if recordStart == v.WireStart {
					recordStart = end
				}
			}
			report.Events = append(report.Events, v)
		}
	}
	if !failed && d.Finish() != nil {
		report.Issues = append(report.Issues, Issue{"transport", "incomplete_stream", recordStart})
	}
	report.Complete = len(report.Issues) == 0
	for _, e := range report.Events {
		if len(e.Issues) > 0 {
			report.Complete = false
		}
	}
	return report, nil
}

func isCaptureContainer(p []byte) bool {
	if len(p) < 4 {
		return false
	}
	for _, marker := range [][]byte{{0x0a, 0x0d, 0x0d, 0x0a}, {0xd4, 0xc3, 0xb2, 0xa1}, {0xa1, 0xb2, 0xc3, 0xd4}, {0x4d, 0x3c, 0xb2, 0xa1}, {0xa1, 0xb2, 0x3c, 0x4d}} {
		if bytes.Equal(p[:4], marker) {
			return true
		}
	}
	return false
}

func inspectRecord(p []byte, o Options) (*RPC, []Issue) {
	issue := func(code string, offset int) (*RPC, []Issue) { return nil, []Issue{{"rpc", code, int64(offset)}} }
	if bytes.HasPrefix(p, []byte("V8IntroTicketReq")) {
		const n = len("V8IntroTicketReq")
		if len(p) < n+3 || int(binary.LittleEndian.Uint16(p[n:])) != len(p)-n-3 || p[len(p)-1] != 0 {
			return issue("invalid_introduction", 0)
		}
		return &RPC{Encoding: "introduction", Shape: "ticket_request"}, nil
	}
	if bytes.HasPrefix(p, []byte("V8IntroTicketAck")) {
		if _, _, err := wire.IntroductionAck(p); err != nil {
			return issue("invalid_introduction", 0)
		}
		return &RPC{Encoding: "introduction", Shape: "ticket_acknowledgement"}, nil
	}
	if bytes.HasPrefix(p, []byte{0xef, 0xbb, 0xbf}) {
		if !boundedText(p, o.Atoms) {
			return issue("value_limit", 0)
		}
		top, err := wire.ParseText(p)
		if err != nil {
			return issue("invalid_text", 0)
		}
		r := &RPC{Encoding: "text", Shape: "unclassified", TopValues: len(top)}
		if _, err := wire.ParseBootstrap(p); err == nil {
			r.Shape = "bootstrap_reply"
		}
		return r, nil
	}
	if code, offset := boundedAtoms(p, o.Atoms); code != "" {
		return issue(code, offset)
	}
	atoms, err := wire.DecodeAtoms(p)
	if err != nil {
		return issue("invalid_binary_atoms", 0)
	}
	top, err := wire.BuildTree(atoms)
	if err != nil {
		return issue("invalid_binary_tree", 0)
	}
	r := &RPC{Encoding: "binary", Shape: "unclassified", TopValues: len(top), Atoms: len(atoms), Kinds: map[string]int{}}
	for _, a := range atoms {
		r.Kinds[a.Kind]++
	}
	if len(top) == 2 && wire.IsNumber(top[1], 2) {
		r.ReplyTrailer = true
	}
	for _, v := range top[:min(len(top), 16)] {
		r.Values = append(r.Values, summarizeValue(v))
	}
	r.SummariesOmitted = max(0, len(top)-16)
	var issues []Issue
	walkValues(top, r, &issues)
	if isHTTPRequestCandidate(top) {
		if isHTTPRequest(top) {
			r.Shape = "http_request"
		} else {
			r.Shape = "invalid_http_request"
			addRecordIssue(r, &issues, Issue{"rpc", "invalid_http_request", 0})
		}
	} else if isHTTPReplyCandidate(top) {
		if _, err := wire.ParseHTTPReply(p); err == nil {
			r.Shape = "http_reply"
		} else {
			r.Shape = "invalid_http_reply"
			addRecordIssue(r, &issues, Issue{"rpc", "invalid_http_reply", 0})
		}
	}
	return r, issues
}

func summarizeValue(v any) Value {
	if a, ok := v.(wire.Atom); ok {
		return Value{Kind: a.Kind, Offset: a.Offset, End: a.End}
	}
	x, _ := wire.List(v, -1)
	out := Value{Kind: "list", Items: len(x), Offset: -1, End: -1}
	// Lists are represented without boundary atoms by wire.BuildTree. Their
	// reported span is the span of descendant scalar atoms, not delimiters.
	for _, child := range x {
		span := summarizeValue(child)
		if span.Offset >= 0 && (out.Offset < 0 || span.Offset < out.Offset) {
			out.Offset = span.Offset
		}
		if span.End > out.End {
			out.End = span.End
		}
	}
	return out
}

// Preflight atom sizes before the allocating decoder. Unsupported tags and
// truncated lengths return bounded offsets without reflecting input data.
func boundedAtoms(p []byte, limit int) (string, int) {
	if len(p) == 0 {
		return "empty_record", 0
	}
	count := 0
	for pos := 0; pos < len(p); {
		start := pos
		count++
		if count > limit {
			return "atom_limit", start
		}
		tag := p[pos]
		pos++
		n := 0
		switch code := tag & 31; {
		case code == 0:
			if tag == 0 {
				return "invalid_binary_atoms", start
			}
		case code <= 10:
		case code == 11:
			n = 1
		case code == 13:
			n = 2
		case code == 15:
			n = 4
		case code == 21:
			n = 16
		case code == 26 || code == 27:
			prefix := int(code) - 25
			if prefix > len(p)-pos {
				return "truncated_atom", start
			}
			n = int(p[pos])
			if prefix == 2 {
				n = int(binary.LittleEndian.Uint16(p[pos:]))
			}
			pos += prefix
		default:
			return "unsupported_atom", start
		}
		if n > len(p)-pos {
			return "truncated_atom", start
		}
		pos += n
	}
	return "", 0
}

func boundedText(p []byte, limit int) bool {
	quoted := false
	count := 1
	for i := 3; i < len(p); i++ {
		if p[i] == '"' {
			if quoted && i+1 < len(p) && p[i+1] == '"' {
				i++
				continue
			}
			quoted = !quoted
		} else if !quoted && (p[i] == '{' || p[i] == ',') {
			count++
		}
		if count > limit {
			return false
		}
	}
	return true
}

// WriteText writes only report fields that are generated from fixed labels
// and numeric measurements; raw protocol values are never formatted.
func WriteText(w io.Writer, r Report) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Offline 1C reassembled TCP inspection (redacted)\nRead: %d bytes; examined: %d; complete: %t\nRecords: %d; controls: %d; greetings: %d; HTTP messages: %d\n", r.InputBytesRead, r.BytesExamined, r.Complete, r.Counts.Records, r.Counts.Controls, r.Counts.Greetings, r.Counts.HTTPMessages)
	for _, e := range r.Events {
		fmt.Fprintf(&b, "[%d] %s wire=[%d,%d) payload=%d", e.Index, e.Kind, e.WireStart, e.WireEnd, e.PayloadBytes)
		if e.RPC != nil {
			fmt.Fprintf(&b, " %s %s top=%d atoms=%d", e.RPC.Encoding, e.RPC.Shape, e.RPC.TopValues, e.RPC.Atoms)
		}
		fmt.Fprintln(&b)
		if e.RPC != nil {
			for _, f := range e.RPC.Files {
				fmt.Fprintf(&b, "  HTTPFile bytes=%d chunks=%d", f.Bytes, len(f.Chunks))
				if f.HTTP != nil {
					fmt.Fprintf(&b, " %s status=%d endpoint=%s body=%d (%s)", f.HTTP.Method, f.HTTP.Status, f.HTTP.Endpoint, f.HTTP.Body.Bytes, f.HTTP.Body.Format)
				}
				fmt.Fprintln(&b)
			}
		}
		for _, i := range e.Issues {
			fmt.Fprintf(&b, "  issue %s/%s record-offset=%d\n", i.Layer, i.Code, i.Offset)
		}
	}
	for _, i := range r.Issues {
		fmt.Fprintf(&b, "issue %s/%s wire-offset=%d\n", i.Layer, i.Code, i.Offset)
	}
	_, err := w.Write(b.Bytes())
	return err
}
