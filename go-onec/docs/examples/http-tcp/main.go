// This offline documentation example never opens a socket or supplies credentials.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"onec/wire"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func save(dir, name string, data []byte) {
	must(os.WriteFile(filepath.Join(dir, name), data, 0644))
}

func describeAtoms(p []byte) []byte {
	atoms, err := wire.DecodeAtoms(p)
	must(err)
	var out strings.Builder
	fmt.Fprintln(&out, "offset..end(exclusive)  tag  low5  flags  kind       value")
	for _, a := range atoms {
		value := fmt.Sprint(a.Value)
		if b, ok := a.Value.([]byte); ok {
			value = fmt.Sprintf("%q", b)
		}
		fmt.Fprintf(&out, "%04x..%04x             %02x   %02x    %02x    %-10s %s\n", a.Offset, a.End, a.Tag, a.Tag&31, a.Tag&224, a.Kind, value)
	}
	return []byte(out.String())
}

func recoverRecord(record, expected []byte) int {
	for split := 0; split <= len(record); split++ {
		d, err := wire.NewDecoder(1024 * 1024)
		must(err)
		a, err := d.Feed(record[:split])
		must(err)
		b, err := d.Feed(record[split:])
		must(err)
		events := append(a, b...)
		if len(events) != 1 || events[0].Kind != "record" || !bytes.Equal(events[0].Payload, expected) {
			panic(fmt.Sprintf("transport split %d failed", split))
		}
		must(d.Finish())
	}
	return len(record) + 1
}

func check(condition bool, message string) {
	if !condition {
		panic(message)
	}
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run ./docs/examples/http-tcp <output-directory>")
	}
	dir := os.Args[1]
	must(os.MkdirAll(dir, 0755))
	target := wire.MustUUID("12345678-1234-5678-9abc-123456789abc")
	body := []byte(`{"cred":"demo"}`)
	pdu := append([]byte(fmt.Sprintf("POST /e1cib/login HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	h, err := wire.ParseHTTP(pdu, false)
	must(err)
	check(bytes.Equal(h.Body, body), "request HTTP body changed")
	rpc, err := wire.HTTPRequest(target, 1007, pdu, nil, false, false)
	must(err)
	continued, err := wire.HTTPRequest(target, 1008, pdu, nil, false, true)
	must(err)
	stream := wire.EncodeRecord(rpc)
	requestSplits := recoverRecord(stream, rpc)
	tree, err := wire.DecodeTree(rpc)
	must(err)
	root, ok := wire.List(tree[0], 14)
	check(ok && len(tree) == 1, "unexpected request tree")
	file, ok := wire.List(root[9], 7)
	check(ok, "missing native file")
	chunks, ok := wire.List(file[6], 1)
	check(ok, "expected one short chunk")
	chunk, err := wire.Bytes(chunks[0])
	must(err)
	check(bytes.Equal(chunk, pdu), "HTTP PDU altered inside request RPC")

	responsePDU := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	responseFile, err := wire.HTTPFile(responsePDU)
	must(err)
	responseRPC, err := wire.Pack([]any{1, uint32(1007), 1, responseFile, 3, 0, 2, wire.SecurityBlob(nil), 2, []any{"B", 1}, 0})
	must(err)
	// The reply has two top-level values: the list and a trailing small integer 2.
	responseRPC = append(responseRPC, 0x83)
	responseStream := wire.EncodeRecord(responseRPC)
	responseSplits := recoverRecord(responseStream, responseRPC)
	reply, err := wire.ParseHTTPReply(responseRPC)
	must(err)
	check(reply.SecurityComplete && len(reply.Token) == 0 && bytes.Equal(reply.PDU, responsePDU), "response RPC round trip")
	response, err := wire.ParseHTTP(reply.PDU, true)
	must(err)
	check(response.Status == 200 && bytes.Equal(response.Body, []byte("{}")), "HTTP response round trip")

	boundaryRows := []map[string]any{}
	expectedLengths := map[int]string{16383: "[16383]", 16384: "[16384 0]", 16385: "[16384 1]", 32768: "[16384 16384 0]"}
	for _, total := range []int{16383, 16384, 16385, 32768} {
		prefix := []byte("POST /e1cib/login HTTP/1.1\r\nContent-Length: 00000\r\n\r\n")
		count := total - len(prefix)
		boundaryPDU := append([]byte(fmt.Sprintf("POST /e1cib/login HTTP/1.1\r\nContent-Length: %05d\r\n\r\n", count)), bytes.Repeat([]byte{'x'}, count)...)
		check(len(boundaryPDU) == total, "boundary PDU size")
		_, err := wire.ParseHTTP(boundaryPDU, false)
		must(err)
		f, err := wire.HTTPFile(boundaryPDU)
		must(err)
		parts := f[6].([]any)
		lengths := []int{}
		for _, part := range parts {
			lengths = append(lengths, len(part.([]byte)))
		}
		check(fmt.Sprint(lengths) == expectedLengths[total], "boundary chunk lengths")
		boundaryRPC, err := wire.Pack([]any{1, uint32(1007), 1, f, 3, 0, 2, wire.SecurityBlob(nil), 2, []any{"B", 1}, 0})
		must(err)
		boundaryReply, err := wire.ParseHTTPReply(append(boundaryRPC, 0x83))
		must(err)
		check(bytes.Equal(boundaryReply.PDU, boundaryPDU), "boundary native-file extraction")
		boundaryRows = append(boundaryRows, map[string]any{"http_pdu_bytes": total, "http_body_bytes": count, "chunk_lengths": lengths})
	}
	markerPayload := append([]byte{'A'}, wire.End...)
	markerPayload = append(markerPayload, 'B')
	markerStream := wire.EncodeRecord(markerPayload)
	expectedMarker, err := hex.DecodeString("416552b1a56653b2a6426653b2a6")
	must(err)
	check(bytes.Equal(markerStream, expectedMarker), "independent escape example mismatch")
	markerSplits := recoverRecord(markerStream, markerPayload)

	for name, data := range map[string][]byte{
		"request.http": pdu, "request.rpc.bin": rpc, "request.tcp-payload.bin": stream,
		"request-continuation.rpc.bin": continued, "response.http": responsePDU,
		"response.rpc.bin": responseRPC, "response.tcp-payload.bin": responseStream,
	} {
		save(dir, name, data)
		save(dir, name+".hex.txt", []byte(hex.Dump(data)))
	}
	save(dir, "request.atoms.txt", describeAtoms(rpc))
	save(dir, "response.atoms.txt", describeAtoms(responseRPC))
	summary := map[string]any{
		"status": "PASS", "network_used": false,
		"request_http_bytes": len(pdu), "request_body_bytes": len(body),
		"request_rpc_bytes": len(rpc), "request_tcp_payload_bytes": len(stream),
		"request_http_offset_in_rpc": bytes.Index(rpc, pdu),
		"response_http_bytes":        len(responsePDU), "response_rpc_bytes": len(responseRPC),
		"response_tcp_payload_bytes": len(responseStream), "response_http_offset_in_rpc": bytes.Index(responseRPC, responsePDU),
		"request_split_checks": requestSplits, "response_split_checks": responseSplits,
		"escape_split_checks": markerSplits, "escape_example_hex": hex.EncodeToString(markerStream),
		"boundary_cases": boundaryRows,
		"scope":          "Synthetic encoding examples. The abbreviated HTTP request is not a complete valid 1C login; demo is not a real credential. No live exchange occurs.",
	}
	result, err := json.MarshalIndent(summary, "", "  ")
	must(err)
	save(dir, "verification.json", append(result, '\n'))
	fmt.Println(string(result))
}
