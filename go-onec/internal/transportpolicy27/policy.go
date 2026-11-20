package transportpolicy27

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
)

// Level is the numeric policy value. Only None and Encrypted are selectable.
type Level byte

const (
	None      Level = 0 // n: initial reply encrypted, subsequent records plain.
	Encrypted Level = 2 // c: initial reply and subsequent records encrypted.
)

var (
	errPolicy = errors.New("unsupported or invalid transport policy")
	errState  = errors.New("transport policy exchange is not synchronized")
	errLimit  = errors.New("transport policy record limit exceeded")
)

func supported(level Level) bool { return level == None || level == Encrypted }

// rtrsrvc 0198a0, plus fresh-state RSA parameters at 016ea0/0179c0.
func requestHeader(level Level, pub *rsa.PublicKey) []byte {
	c := byte('n')
	if level == Encrypted {
		c = 'c'
	}
	header := []byte{0xef, 0xbb, 0xbf, '"', c, '"', ',', '\r', '\n'}
	header = append(header, binaryField(pub.N.Bytes())...)
	header = append(header, ',', '\r', '\n')
	header = append(header, binaryField([]byte{1, 0, 1})...)
	return frameHeader(append(header, ',')) // Empty known-key identifier.
}

type material struct {
	level Level
	key   [24]byte
	iv    [8]byte
	step  [8]byte
}

func (m *material) clear() {
	clear(m.key[:])
	clear(m.iv[:])
	clear(m.step[:])
	m.level = None
}

// rtrsrvc 01a2c0 and 0191e0: map level, reject u/refusal and below minimum,
// then configure key/IV. y is recognized but not implemented by this subset.
func readMaterial(header []byte, minimum Level) (m material, err error) {
	if len(header) < 6 || !bytes.Equal(header[:4], []byte("\xef\xbb\xbf\"")) || header[5] != '"' {
		return m, errPolicy
	}
	switch header[4] {
	case 'n':
		m.level = None
	case 'c':
		m.level = Encrypted
	default:
		return m, errPolicy
	}
	if m.level < minimum {
		return m, errPolicy
	}
	rest := header[6:]
	for _, destination := range [][]byte{m.key[:], m.iv[:], m.step[:]} {
		if !bytes.HasPrefix(rest, []byte(",\r\n")) {
			m.clear()
			return m, errPolicy
		}
		var data []byte
		data, rest, err = readBinaryField(rest[3:], len(destination))
		if err != nil {
			m.clear()
			return m, err
		}
		copy(destination, data)
		clear(data)
	}
	if len(rest) != 0 {
		m.clear()
		return m, errPolicy
	}
	return m, nil
}

// inet 021e80: random filler, followed by its removal count; always a final block.
func (m *material) encrypt(data []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(m.key[:])
	if err != nil {
		return nil, errPolicy
	}
	count := 8 - len(data)%8
	out := make([]byte, len(data)+count)
	copy(out, data)
	if _, err := rand.Read(out[len(data) : len(out)-1]); err != nil {
		clear(out)
		return nil, errors.New("transport policy random generation failed")
	}
	out[len(out)-1] = byte(count)
	cipher.NewCBCEncrypter(block, m.iv[:]).CryptBlocks(out, out)
	return out, nil
}

// inet 021410 accepts 0..8, without checking filler bytes. The zero case is
// source-derived only; the ordinary native writer emits 1..8.
func (m *material) decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%8 != 0 {
		return nil, errPolicy
	}
	block, err := des.NewTripleDESCipher(m.key[:])
	if err != nil {
		return nil, errPolicy
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, m.iv[:]).CryptBlocks(out, data)
	count := int(out[len(out)-1])
	if count > 8 {
		clear(out)
		return nil, errPolicy
	}
	clear(out[len(out)-count:])
	return out[:len(out)-count], nil
}

// rtrsrvc 019750: little-endian addition with final carry discarded.
func (m *material) advance() {
	binary.LittleEndian.PutUint64(m.iv[:], binary.LittleEndian.Uint64(m.iv[:])+binary.LittleEndian.Uint64(m.step[:]))
}
