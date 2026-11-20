package transportpolicy27

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
)

const chunkSize = 0x2000
const maxHeaderSize = 64 << 10 // Local resource limit, not a native validation claim.

// rtrsrvc 01ad10/01a9a0: full chunks followed by one short (possibly zero) chunk.
func frameHeader(header []byte) []byte {
	out := make([]byte, 0, len(header)+2*(len(header)/chunkSize+1))
	for len(header) >= chunkSize {
		out = append(out, 0, 0x20)
		out = append(out, header[:chunkSize]...)
		header = header[chunkSize:]
	}
	out = binary.LittleEndian.AppendUint16(out, uint16(len(header)))
	return append(out, header...)
}

// rtrsrvc 01ab60. Truncation and the budget are deliberately strict local bounds.
// The returned body aliases record; header is a separate allocation.
func splitHeader(record []byte) (header, body []byte, err error) {
	for {
		if len(record) < 2 {
			clear(header)
			return nil, nil, errPolicy
		}
		n := int(binary.LittleEndian.Uint16(record))
		record = record[2:]
		if n > chunkSize || n > len(record) || n > maxHeaderSize-len(header) {
			clear(header)
			return nil, nil, errPolicy
		}
		header = append(header, record[:n]...)
		record = record[n:]
		if n < chunkSize {
			if len(header) == 0 {
				return nil, nil, errPolicy
			}
			return header, record, nil
		}
	}
}

// core83 27fbc0/233edf/233f21: width 64, UTF-8 CRCRLF, including an
// exact final full line when the wrapping loop was entered.
func binaryField(data []byte) []byte {
	s := base64.StdEncoding.EncodeToString(data)
	out := []byte("{#base64:")
	if len(s) > 64 {
		for len(s) >= 64 {
			out = append(out, s[:64]...)
			out = append(out, '\r', '\r', '\n')
			s = s[64:]
		}
	}
	out = append(out, s...)
	return append(out, '}')
}

// core83 281240 recognizes #base64. #data and nonempty identifiers are outside
// this implementation. CR/LF variation is accepted by the standard decoder;
// all other whitespace and noncanonical trailing bits are rejected.
func readBinaryField(input []byte, size int) (data, rest []byte, err error) {
	if !bytes.HasPrefix(input, []byte("{#base64:")) {
		return nil, nil, errPolicy
	}
	end := bytes.IndexByte(input[9:], '}')
	if end < 0 {
		return nil, nil, errPolicy
	}
	end += 9
	if end > 1024 { // Every supported field is at most 128 bytes.
		return nil, nil, errPolicy
	}
	data = make([]byte, base64.StdEncoding.DecodedLen(end-9))
	n, decodeErr := base64.StdEncoding.Strict().Decode(data, input[9:end])
	if decodeErr != nil || n != size {
		clear(data)
		return nil, nil, errPolicy
	}
	return data[:n], input[end+1:], nil
}
