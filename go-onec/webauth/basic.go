package webauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type BasicResult struct {
	InitialStatus             int  `json:"initial_status"`
	FinalStatus               int  `json:"final_status"`
	CredentialsSubmitted      bool `json:"credentials_submitted"`
	ChallengeSatisfied        bool `json:"challenge_satisfied"`
	AuthenticationNotRequired bool `json:"authentication_not_required"`
	ApplicationSession        bool `json:"application_session"`
	ResponseBytes             int  `json:"response_bytes"`
}

var basicChallenge = regexp.MustCompile(`(?i)(?:^|,)\s*Basic(?:\s|$)`)

// ValidateBasicResource restricts the check to known description/root requests.
// Business service methods, entity queries and SOAP operations are not called.
func ValidateBasicResource(resource string) error {
	u, err := url.Parse(resource)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(u.Path, "%\\") || strings.HasPrefix(u.Path, "/") {
		return errors.New("basic resource must be a relative service-description path")
	}
	if (u.Path == "odata/standard.odata/" || u.Path == "odata/standard.odata/$metadata" || u.Path == "hs/" || u.Path == "ws/") && u.RawQuery == "" {
		return nil
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) == 2 && parts[0] == "ws" && parts[1] != "" && parts[1] != "." && parts[1] != ".." && u.RawQuery == "wsdl" {
		return nil
	}
	return errors.New("basic check supports OData service/$metadata, hs/, ws/, or ws/<name>?wsdl")
}

// CheckBasic makes one anonymous request and, only after a Basic challenge,
// one credentialed request to the exact same URL. No web-client session is made.
// A non-challenged 2xx response does not establish password validity.
func CheckBasic(ctx context.Context, cfg Config, credentials Credentials, resource string) (BasicResult, error) {
	result := BasicResult{}
	if err := ValidateBasicResource(resource); err != nil {
		return result, err
	}
	if err := ValidateCredentials(Credentials{Username: credentials.Username, Password: credentials.Password, Method: "legacy"}); err != nil {
		return result, err
	}
	if strings.Contains(credentials.Username, ":") {
		return result, errors.New("Basic username must not contain a colon")
	}
	c, err := newTransport(ctx, cfg)
	if err != nil {
		return result, err
	}
	defer c.Close()
	// Basic is tested per request; an anonymous response cookie must not make a
	// later 2xx look like verification of the supplied password.
	c.http.Jar = nil
	u, _ := url.Parse(resource)
	r, err := c.request(ctx, "basic challenge", "GET", u.Path, u.Query(), nil, false, "")
	if err != nil {
		return result, err
	}
	clear(r.body)
	result.InitialStatus = r.status
	result.FinalStatus = r.status
	if r.status >= 200 && r.status < 300 {
		result.AuthenticationNotRequired = true
		return result, nil
	}
	if r.status != http.StatusUnauthorized {
		return result, statusError("basic challenge", r)
	}
	matched := false
	for _, h := range r.header.Values("WWW-Authenticate") {
		if basicChallenge.MatchString(h) {
			matched = true
		}
	}
	if !matched {
		return result, &Error{Operation: "basic challenge", Kind: "basic_not_offered", Status: r.status}
	}
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials.Username+":"+credentials.Password))
	result.CredentialsSubmitted = true
	r, err = c.request(ctx, "basic authentication", "GET", u.Path, u.Query(), nil, false, header)
	header = ""
	if err != nil {
		return result, err
	}
	result.FinalStatus = r.status
	result.ResponseBytes = len(r.body)
	clear(r.body)
	if r.status < 200 || r.status >= 300 {
		return result, statusError("basic authentication", r)
	}
	result.ChallengeSatisfied = true
	return result, nil
}
