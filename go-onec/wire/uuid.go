// Package wire implements the bounded native wire subset observed in the lab.
package wire

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type UUID [16]byte

func ParseUUID(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, errors.New("invalid UUID")
	}
	b, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if e != nil || len(b) != 16 {
		return u, errors.New("invalid UUID")
	}
	copy(u[:], b)
	return u, nil
}
func MustUUID(s string) UUID {
	u, e := ParseUUID(s)
	if e != nil {
		panic(e)
	}
	return u
}
func NewUUID() (UUID, error) {
	var u UUID
	if _, e := rand.Read(u[:]); e != nil {
		return u, e
	}
	u[6] = (u[6] & 15) | 64
	u[8] = (u[8] & 63) | 128
	return u, nil
}
func (u UUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[:4], u[4:6], u[6:8], u[8:10], u[10:])
}
func (u UUID) LittleEndian() []byte {
	b := append([]byte(nil), u[:]...)
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	b[4], b[5] = b[5], b[4]
	b[6], b[7] = b[7], b[6]
	return b
}
func UUIDFromLE(b []byte) (UUID, error) {
	var u UUID
	if len(b) != 16 {
		return u, errors.New("invalid GUID length")
	}
	copy(u[:], b)
	u[0], u[1], u[2], u[3] = u[3], u[2], u[1], u[0]
	u[4], u[5] = u[5], u[4]
	u[6], u[7] = u[7], u[6]
	return u, nil
}
