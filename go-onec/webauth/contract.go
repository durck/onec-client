package webauth

import "strings"

// Recognize narrow shipped-source contracts without evaluating JavaScript.
// Comments, strings, regular expressions and template literals cannot supply
// executable proof-field tokens. The selected codec still validates server proof.
func detectAuthMethod(source []byte) (string, error) {
	l := authLexer{source: string(source)}
	var recent []authToken
	legacyRoute, loginRoute, legacyCredential := false, false, false
	proofMethod := ""
	bad := func(kind string) (string, error) { return "", &Error{Operation: "auth_contract", Kind: kind} }
	for {
		t, ok := l.next()
		if !ok {
			if l.invalid {
				return bad("unsupported_authentication_contract")
			}
			break
		}
		if t.kind == 's' {
			legacyRoute = legacyRoute || t.text == "e1cib/login?version="
			loginRoute = loginRoute || t.text == "e1cib/login"
		}
		recent = append(recent, t)
		if len(recent) > 12 {
			recent = recent[1:]
		}
		n := len(recent)
		if n >= 4 {
			r := recent[n-4:]
			legacyCredential = legacyCredential || (r[0].kind == 'i' && r[1].text == "+=" && r[2].kind == 's' && r[2].text == "&cred=" && r[3].text == "+")
		}
		if n != 12 {
			continue
		}
		pattern := []string{"JSON", ".", "parse", "(", "", ".", "responseText", ")", ".", "response", ".", ""}
		matches := true
		for i, want := range pattern {
			if recent[i].kind == 's' || recent[i].kind == 'x' || (want != "" && recent[i].text != want) {
				matches = false
				break
			}
		}
		if !matches || recent[4].kind != 'i' || recent[11].kind != 'i' || !strings.HasPrefix(t.text, "credAns") {
			continue
		}
		method := ""
		switch t.text {
		case "credAns4":
			method = "v1"
		case "credAns6":
			method = "v3"
		default:
			return bad("unsupported_authentication_contract")
		}
		if proofMethod != "" && method != proofMethod {
			return bad("ambiguous_authentication_contract")
		}
		proofMethod = method
	}
	legacy := legacyRoute && legacyCredential
	if proofMethod != "" {
		if legacy || !loginRoute {
			return bad("ambiguous_authentication_contract")
		}
		return proofMethod, nil
	}
	if legacy {
		return "legacy", nil
	}
	return bad("unsupported_authentication_contract")
}

type authToken struct {
	kind byte
	text string
}
type authLexer struct {
	source        string
	pos           int
	previous      authToken
	invalid       bool
	controlParens []bool
	afterControl  bool
}

func authIdentifier(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$' || c >= '0' && c <= '9'
}

func (l *authLexer) next() (t authToken, ok bool) {
	defer func() {
		if ok {
			l.afterControl = false
			if t.kind == 'p' && t.text == "(" {
				control := false
				switch l.previous.text {
				case "if", "while", "for", "with", "switch", "catch":
					control = l.previous.kind == 'i'
				}
				l.controlParens = append(l.controlParens, control)
			} else if t.kind == 'p' && t.text == ")" && len(l.controlParens) > 0 {
				last := len(l.controlParens) - 1
				l.afterControl = l.controlParens[last]
				l.controlParens = l.controlParens[:last]
			}
			l.previous = t
		}
	}()
	s := l.source
	for l.pos < len(s) {
		start := l.pos
		c := s[l.pos]
		l.pos++
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if c == '/' && l.pos < len(s) {
			if s[l.pos] == '/' {
				for l.pos < len(s) && s[l.pos] != '\n' && s[l.pos] != '\r' {
					l.pos++
				}
				continue
			}
			if s[l.pos] == '*' {
				end := strings.Index(s[l.pos+1:], "*/")
				if end < 0 {
					l.invalid = true
					return t, false
				}
				l.pos += end + 3
				continue
			}
			if l.regexAllowed() {
				p, inClass := l.pos, false
				for p < len(s) && s[p] != '\r' && s[p] != '\n' {
					switch s[p] {
					case '\\':
						p += 2
						continue
					case '[':
						inClass = true
					case ']':
						inClass = false
					case '/':
						if !inClass {
							p++
							for p < len(s) && authIdentifier(s[p]) {
								p++
							}
							l.pos = p
							return authToken{kind: 'x'}, true
						}
					}
					p++
				}
				l.invalid = true
				return t, false
			}
		}
		if c == '\'' || c == '"' || c == '`' {
			for l.pos < len(s) {
				ch := s[l.pos]
				l.pos++
				// Interpolated templates require full JavaScript grammar. The
				// inspected loaders do not need it; do not expose nested literals
				// as executable code in an unfamiliar loader.
				if c == '`' && ch == '$' && l.pos < len(s) && s[l.pos] == '{' {
					l.invalid = true
					return t, false
				}
				if ch == '\\' {
					if l.pos < len(s) {
						l.pos++
					}
					continue
				}
				if ch == c {
					if c == '`' {
						return authToken{kind: 'x'}, true
					}
					return authToken{kind: 's', text: s[start+1 : l.pos-1]}, true
				}
			}
			l.invalid = true
			return t, false
		}
		if authIdentifier(c) {
			for l.pos < len(s) && authIdentifier(s[l.pos]) {
				l.pos++
			}
			return authToken{kind: 'i', text: s[start:l.pos]}, true
		}
		if c == '+' && l.pos < len(s) && s[l.pos] == '=' {
			l.pos++
		}
		return authToken{kind: 'p', text: s[start:l.pos]}, true
	}
	return t, false
}

func (l *authLexer) regexAllowed() bool {
	if l.afterControl {
		return true
	}
	p := l.previous
	if p.kind == 'i' {
		switch p.text {
		case "return", "throw", "case", "typeof", "void", "delete", "new", "in", "instanceof", "yield", "await":
			return true
		}
		return false
	}
	return p.kind != 's' && p.kind != 'x' && p.text != ")" && p.text != "]"
}
