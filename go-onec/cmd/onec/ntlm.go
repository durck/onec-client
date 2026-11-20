package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"onec"
	"onec/ntlmauth"
	"os"

	"golang.org/x/term"
)

// Invoked only after preview and option validation, shared by root and epf.
// The returned cleanup owns credentials even if Dial or an EPF read fails.
func (o *commandOptions) prepareSecurity(cfg *onec.Config, diagnostic io.Writer) (func(), error) {
	if o.ntlm == "" {
		return func() {}, nil
	}
	var secret []byte
	var err error
	if o.ntlmSecretStdin {
		secret, err = readNTLMSecret(os.Stdin)
	} else {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, errors.New("explicit NTLM needs a terminal or --ntlm-secret-stdin")
		}
		label := "NTLM account password: "
		if o.ntlm == "hash" {
			label = "NT hash (32 hexadecimal characters): "
		}
		fmt.Fprint(diagnostic, label)
		secret, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(diagnostic)
		if err != nil {
			err = errors.New("could not read hidden NTLM secret")
		}
	}
	defer clear(secret)
	if err != nil {
		return nil, err
	}
	credentials, err := o.explicitCredentials(secret)
	if err != nil {
		return nil, err
	}
	cfg.NTLM = credentials
	return func() { _ = credentials.Close() }, nil
}

func readNTLMSecret(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, 4099))
	if err != nil || len(b) > 4098 {
		clear(b)
		return nil, errors.New("NTLM secret input limit or read error")
	}
	// Remove one line terminator, not whitespace belonging to a password.
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if len(b) > 4096 || bytes.ContainsAny(b, "\r\n") {
		clear(b)
		return nil, errors.New("NTLM stdin requires a single line of at most 4096 bytes")
	}
	return b, nil
}

func (o *commandOptions) explicitCredentials(secret []byte) (*ntlmauth.Credentials, error) {
	id := ntlmauth.Identity{Domain: o.ntlmDomain, User: o.ntlmUser}
	switch o.ntlm {
	case "password":
		return ntlmauth.NewPassword(id, secret)
	case "hash":
		var hash [16]byte
		defer clear(hash[:])
		if len(secret) != 32 {
			return nil, errors.New("NT hash must be exactly 32 hexadecimal characters; LM:NT and NetNTLM responses are not accepted")
		}
		if _, err := hex.Decode(hash[:], secret); err != nil {
			return nil, errors.New("invalid NT hash encoding")
		}
		return ntlmauth.NewHash(id, hash[:])
	default:
		return nil, errors.New("unsupported explicit NTLM secret type")
	}
}
