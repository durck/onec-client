package security

import (
	"encoding/binary"
	"errors"
)

const anonymousTokenLimit = 65535
const ntlmLocalCall = 0x4000
const ntlmVersion = 0x02000000
const anonymousNullSession = 0x40000

// Only the bounded raw NTLM exchange used by the anonymous provider is accepted.
// These helpers return no identity, response, session-key or token bytes.
func anonymousHeader(b []byte, message uint32, minimum int, flagOffset int) error {
	if len(b) < minimum || len(b) > anonymousTokenLimit || string(b[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(b[8:12]) != message {
		return errors.New("invalid anonymous NTLM message")
	}
	flags := binary.LittleEndian.Uint32(b[flagOffset : flagOffset+4])
	if flags&ntlmLocalCall != 0 {
		return errors.New("local-call NTLM is not accepted for anonymous authentication")
	}
	if flags&ntlmVersion != 0 && len(b) < minimum+8 {
		return errors.New("truncated anonymous NTLM version")
	}
	return nil
}

func anonymousBuffer(b []byte, at, minimum int) ([]byte, error) {
	n := uint64(binary.LittleEndian.Uint16(b[at : at+2]))
	capacity := uint64(binary.LittleEndian.Uint16(b[at+2 : at+4]))
	offset := uint64(binary.LittleEndian.Uint32(b[at+4 : at+8]))
	if n > capacity || offset > uint64(len(b)) || n > uint64(len(b))-offset || n > 0 && offset < uint64(minimum) {
		return nil, errors.New("invalid anonymous NTLM security buffer")
	}
	return b[offset : offset+n], nil
}

func validateAnonymousNegotiate(b []byte) error {
	if err := anonymousHeader(b, 1, 32, 12); err != nil {
		return err
	}
	minimum := 32
	if binary.LittleEndian.Uint32(b[12:16])&ntlmVersion != 0 {
		minimum += 8
	}
	for _, at := range []int{16, 24} {
		if _, err := anonymousBuffer(b, at, minimum); err != nil {
			return err
		}
	}
	return nil
}

func validateAnonymousChallenge(b []byte) error {
	if err := anonymousHeader(b, 2, 48, 20); err != nil {
		return err
	}
	minimum := 48
	if binary.LittleEndian.Uint32(b[20:24])&ntlmVersion != 0 {
		minimum += 8
	}
	for _, at := range []int{12, 40} {
		if _, err := anonymousBuffer(b, at, minimum); err != nil {
			return err
		}
	}
	return nil
}

func validateAnonymousAuthenticate(b []byte) error {
	if err := anonymousHeader(b, 3, 64, 60); err != nil {
		return err
	}
	var fields [6][]byte
	minimum := 64
	if binary.LittleEndian.Uint32(b[60:64])&ntlmVersion != 0 {
		minimum += 8
	}
	for i := range fields {
		var err error
		fields[i], err = anonymousBuffer(b, 12+i*8, minimum)
		if err != nil {
			return err
		}
	}
	// Require the exact single-zero LM response seen in the supported exchange.
	// A domain, user or NT response would mean account authentication instead.
	if len(fields[0]) != 1 || fields[0][0] != 0 || len(fields[1]) != 0 || len(fields[2]) != 0 || len(fields[3]) != 0 {
		return errors.New("non-anonymous NTLM authenticate blocked")
	}
	return nil
}

func validateAnonymousStep(started bool, status, attributes uint32, token []byte) (bool, error) {
	if !started {
		if status != 0x90312 && status != 0x90314 {
			return false, errors.New("unexpected anonymous SSPI initial completion")
		}
		return false, validateAnonymousNegotiate(token)
	}
	if status != 0 && status != 0x90313 {
		return false, errors.New("anonymous SSPI exchange did not complete")
	}
	if err := validateAnonymousAuthenticate(token); err != nil {
		return false, err
	}
	if attributes&anonymousNullSession == 0 {
		return false, errors.New("anonymous SSPI completion lacks NULL_SESSION")
	}
	return true, nil
}
