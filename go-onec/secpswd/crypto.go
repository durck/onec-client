// Package secpswd implements the observed V1, V2 and V3 credential exchanges.
// Interoperability with a live server is separate from codec correctness.
package secpswd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"hash/crc32"
	"io"
	"strings"
	"unicode/utf8"
)

const MaxText = 1024 * 1024
const MaxEncoded = 2 * 1024 * 1024
const MaxBinary = MaxEncoded * 3 / 4

var messageIV = unhex("9d7b9a206965bb28067a483db26c718e")
var envelopeIV = unhex("126bafea20772e4211cc2197f85ef32f")

// This public protocol envelope key is not a user credential.
var envelopeKey = unhex("a3aeb390acbc1580aebf118dd5629be42e0e07adb134356a831053c5718109cd")

func unhex(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func validText(s string) error {
	if len(s) > MaxText || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return errors.New("invalid credential text or length")
	}
	return nil
}
func encode(b []byte) (string, error) {
	if len(b) > MaxBinary {
		return "", errors.New("credential size limit")
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
func decode(s string) ([]byte, error) {
	if len(s) > MaxEncoded {
		return nil, errors.New("credential size limit")
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("noncanonical credential Base64")
	}
	return b, nil
}
func addCRC(b []byte) []byte {
	out := append([]byte(nil), b...)
	return binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(b))
}
func checkCRC(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, errors.New("missing credential checksum")
	}
	body := b[:len(b)-4]
	expected := binary.LittleEndian.AppendUint32(nil, crc32.ChecksumIEEE(body))
	if subtle.ConstantTimeCompare(expected, b[len(b)-4:]) != 1 {
		return nil, errors.New("credential checksum mismatch")
	}
	return body, nil
}
func random(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}
func encrypt(key, plain, iv []byte, r io.Reader) ([]byte, error) {
	if len(key) != 32 || len(iv) != 16 || len(plain) > MaxBinary-16 {
		return nil, errors.New("invalid encryption parameters")
	}
	n := 16 - len(plain)%16
	pad, e := random(r, n-1)
	if e != nil {
		return nil, e
	}
	p := append(append(append([]byte(nil), plain...), pad...), byte(n))
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	out := make([]byte, len(p))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, p)
	clear(p)
	clear(pad)
	return out, nil
}
func decrypt(key, encrypted, iv []byte) ([]byte, error) {
	if len(key) != 32 || len(iv) != 16 || len(encrypted) == 0 || len(encrypted)%16 != 0 || len(encrypted) > MaxBinary {
		return nil, errors.New("invalid encrypted credential length")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	out := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, encrypted)
	n := int(out[len(out)-1])
	if n < 1 || n > 16 {
		clear(out)
		return nil, errors.New("invalid random padding length")
	}
	return out[:len(out)-n], nil
}

// PasswordHash implements all four observed modes. Modes are protocol choices,
// not recommendations for new password-storage systems.
func PasswordHash(password string, mode int, salt []byte, sensitive bool) (string, error) {
	if e := validText(password); e != nil {
		return "", e
	}
	if mode < 0 || mode > 3 || len(salt) > 255 {
		return "", errors.New("invalid password hash parameters")
	}
	if !sensitive {
		password = cases.Upper(language.Und).String(password)
	}
	data := []byte(password)
	if mode != 0 {
		data = append(data, []byte(base64.StdEncoding.EncodeToString(salt))...)
	}
	defer clear(data)
	var digest []byte
	switch mode {
	case 0:
		d := sha1.Sum(data)
		digest = d[:]
	case 1:
		d := sha256.Sum256(data)
		digest = d[:]
	case 2:
		d := sha512.Sum512(data)
		digest = d[:]
	case 3:
		var e error
		digest, e = pbkdf2.Key(sha256.New, string(data), []byte{}, 16000, 64)
		if e != nil {
			return "", e
		}
	}
	return base64.StdEncoding.EncodeToString(digest), nil
}
func PasswordKey(password string, mode int, salt []byte, sensitive bool) ([]byte, error) {
	h, e := PasswordHash(password, mode, salt, sensitive)
	if e != nil {
		return nil, e
	}
	d := sha256.Sum256([]byte(h))
	return d[:], nil
}
func b8(b []byte) []byte  { return append([]byte{byte(len(b))}, b...) }
func b32(b []byte) []byte { return append(binary.LittleEndian.AppendUint32(nil, uint32(len(b))), b...) }

type reader struct {
	data []byte
	pos  int
	err  error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.data)-r.pos {
		r.err = errors.New("truncated credential field")
		return nil
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b
}
func (r *reader) u8() byte {
	b := r.take(1)
	if len(b) != 1 {
		return 0
	}
	return b[0]
}
func (r *reader) b8() []byte { return r.take(int(r.u8())) }
func (r *reader) finish() error {
	if r.err != nil {
		return r.err
	}
	if r.pos != len(r.data) {
		return errors.New("unexpected credential tail")
	}
	return nil
}
func encryptedReader(key, packet, iv []byte) (*reader, error) {
	p, e := decrypt(key, packet, iv)
	if e != nil {
		return nil, e
	}
	b, e := checkCRC(p)
	if e != nil {
		clear(p)
		return nil, e
	}
	return &reader{data: b}, nil
}
func equal(a, b []byte) bool   { return subtle.ConstantTimeCompare(a, b) == 1 }
func sameKey(a, b []byte) bool { return bytes.Equal(a, b) }
