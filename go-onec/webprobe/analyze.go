package webprobe

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

func clean(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	r := []rune(s)
	if len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return s
}

func safeLocation(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" {
		return "<unparseable redirect>"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return clean(u.String(), 1024)
}

// Only schemes and a bounded Basic realm are retained, never challenge tokens.
var schemePattern = regexp.MustCompile(`(?i)(?:^|,)\s*(Basic|Digest|Negotiate|NTLM|Bearer)(?:\s|$)`)
var realmPattern = regexp.MustCompile(`(?i)(?:^|,)\s*Basic\s+realm="([^"\\]*)"`)

func authentication(headers []string) ([]string, string) {
	set := map[string]bool{}
	realm := ""
	for _, h := range headers {
		for _, m := range schemePattern.FindAllStringSubmatch(h, -1) {
			set[strings.ToLower(m[1])] = true
		}
		if m := realmPattern.FindStringSubmatch(h); len(m) > 1 {
			realm = clean(m[1], 256)
		}
	}
	out := []string{}
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, realm
}

func authMaterial(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			switch strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(k)) {
			case "cred", "credans6", "token", "accesstoken", "refreshtoken", "idtoken", "password", "clientsecret", "sessionid", "seanceid":
				return true
			}
			if authMaterial(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if authMaterial(child) {
				return true
			}
		}
	}
	return false
}

var versionPattern = regexp.MustCompile(`\bvar\s+VERSION\s*=\s*["'](8\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,6})["']`)
var bootstrapPattern = regexp.MustCompile(`\bvar\s+(BASE|LANG|E1CIB|VENDORPREFIX)\s*=\s*"([^"\r\n]{0,512})"`)
var dllPattern = regexp.MustCompile(`(?i)\b[a-z0-9_]+\.dll\b`)

func analyze(report *Report, x *Result, body []byte) {
	id := x.Request.ID
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}))
	x.Kind = "text"
	if len(trimmed) == 0 {
		x.Kind = "empty"
	}
	var decoded any
	isJSON := json.Unmarshal(trimmed, &decoded) == nil
	obj, _ := decoded.(map[string]any)
	if isJSON {
		x.Kind = "json"
	}
	if bytes.HasPrefix(bytes.ToLower(trimmed), []byte("<!doctype html")) || bytes.HasPrefix(bytes.ToLower(trimmed), []byte("<html")) || strings.Contains(strings.ToLower(x.ContentType), "text/html") {
		x.Kind = "html"
		inspectHTML(x, trimmed)
	}
	if len(trimmed) > 0 && trimmed[0] == '<' && x.Kind != "html" {
		inspectXML(x, trimmed)
	}
	if x.Status >= 300 && x.Status < 400 {
		report.finding("info", "redirect_not_followed", id, "Redirect recorded without following it; query and fragment omitted")
	}
	if x.Status >= 500 {
		report.finding("warn", "server_error", id, "Server returned an HTTP 5xx response")
	}
	if x.Status == 401 && len(x.AuthSchemes) == 0 {
		report.finding("warn", "missing_auth_challenge", id, "HTTP 401 has no recognized WWW-Authenticate scheme")
	}
	if _, ok := x.Summary["iis_details"]; ok {
		report.finding("warn", "detailed_iis_error", id, "Detailed IIS error exposes handler/request information; inspect selected fields")
	}
	if isJSON && authMaterial(decoded) {
		x.Summary = map[string]any{"authentication_fields_omitted": true}
		report.finding("warn", "authentication_payload_omitted", id, "Recognized authentication fields in JSON; no body fields retained")
		return
	}
	if exception, ok := obj["exception"].(map[string]any); ok {
		x.Kind = "json_exception"
		if code, ok := exception["reason"].(float64); ok {
			x.Summary["exception_reason"] = code
		}
		if stack, ok := exception["creationStack"].(string); ok && stack != "" {
			set := map[string]bool{}
			for _, name := range dllPattern.FindAllString(stack, -1) {
				set[strings.ToLower(name)] = true
			}
			names := []string{}
			for name := range set {
				names = append(names, name)
			}
			sort.Strings(names)
			x.Summary["stack_modules"] = names[:min(len(names), 32)]
			report.finding("warn", "exception_stack_disclosed", id, "JSON exception includes a native creation stack; module names retained, offsets omitted")
		}
		if x.Status >= 200 && x.Status < 300 {
			report.finding("warn", "success_with_exception", id, "HTTP success status carries a 1C exception")
		}
		return
	}
	if x.Status != 200 {
		return
	}
	switch id {
	case "entry":
		if m := versionPattern.FindSubmatch(trimmed); len(m) > 1 {
			x.Summary["web_version"] = string(m[1])
		}
		for _, m := range bootstrapPattern.FindAllSubmatch(trimmed, -1) {
			x.Summary[strings.ToLower(string(m[1]))] = clean(string(m[2]), 512)
		}
		if x.Summary["e1cib"] != "e1cib" {
			report.finding("info", "publication_unconfirmed", id, "Expected 1C bootstrap marker absent; supplied path may be a gateway or another page")
		}
	case "manifest":
		if _, ok := obj["name"].(string); !ok {
			unexpected(report, x, "a JSON web-app manifest")
			break
		}
		for _, key := range []string{"name", "short_name", "display", "background_color", "theme_color"} {
			if s, ok := obj[key].(string); ok {
				x.Summary[key] = clean(s, 256)
			}
		}
		if s, ok := obj["start_url"].(string); ok {
			x.Summary["start_url"] = safeLocation(s)
		}
		if icons, ok := obj["icons"].([]any); ok {
			x.Summary["icon_count"] = len(icons)
		}
	case "users":
		if x.Kind == "empty" {
			x.Summary["users_observation"] = "empty response (including BOM-only); does not establish that no accounts exist"
			break
		}
		if x.Kind == "html" {
			unexpected(report, x, "a user-list payload, not HTML")
			break
		}
		x.Summary["users_observation"] = "nonempty payload; account names are not retained and format is not fully validated"
		report.finding("warn", "nonempty_users_payload", id, "Anonymous users endpoint returned a payload; review user-list publication settings")
	case "auth-settings":
		if obj == nil {
			unexpected(report, x, "JSON authentication settings")
			break
		}
		authSettings(x.Summary, obj, "")
		if lc, ok := obj["lcinfo"].(map[string]any); ok {
			if auth, ok := lc["auth"].(map[string]any); ok {
				authSettings(x.Summary, auth, "lcinfo.auth.")
			}
			if types, ok := lc["authTypes"].([]any); ok {
				values := []string{}
				for _, v := range types[:min(len(types), 16)] {
					if s, ok := v.(string); ok {
						values = append(values, clean(s, 64))
					}
				}
				x.Summary["auth_types"] = values
			}
		}
		if len(x.Summary) == 0 {
			unexpected(report, x, "recognized authentication settings")
		}
	case "locale":
		if obj == nil || obj["response"] == nil {
			unexpected(report, x, "a JSON locale response")
			break
		}
		x.Summary["locale_response_present"] = true
	case "about", "types", "sysenums", "module-defs", "syspics":
		if x.Kind == "html" || x.Kind == "empty" {
			unexpected(report, x, "a metadata payload")
			break
		}
		report.finding("warn", "anonymous_metadata_payload", id, "Metadata route returned HTTP 200 with a non-HTML payload; completeness and application access are unproven")
	case "odata-service", "odata-metadata", "catalogue-wsdl", "distribution-wsdl":
		if x.Kind == "odata_schema" || x.Kind == "odata_service" || x.Kind == "wsdl" {
			report.finding("warn", "anonymous_service_description", id, "Recognized service/schema document is readable anonymously; this does not establish operation or record access")
		} else {
			unexpected(report, x, "a recognized OData or WSDL document")
		}
	}
}

func unexpected(r *Report, x *Result, expected string) {
	r.finding("warn", "unexpected_representation", x.Request.ID, "Expected "+expected+"; got "+x.Kind+" with HTTP 200")
}

func authSettings(out map[string]any, obj map[string]any, prefix string) {
	for _, key := range []string{"enablePasswordRecovery", "allowSaveForReauthentication", "saveForReauthenticationByDefault"} {
		if v, ok := obj[key].(bool); ok {
			out[prefix+key] = v
		}
	}
	for _, key := range []string{"passwordRecoveryMethod", "savedAuthenticationParametersLifeTime", "inactivityTimeForTerminateSession", "inactivityTimeForTerminateSessionNotification"} {
		if v, ok := obj[key].(float64); ok {
			out[prefix+key] = v
		}
	}
	if s, ok := obj["passwordRecoveryURL"].(string); ok {
		out[prefix+"passwordRecoveryURL_present"] = s != ""
	}
}

func inspectHTML(x *Result, body []byte) {
	// Parse text from table cells; never retain scripts, hidden inputs or cookies.
	z := html.NewTokenizer(bytes.NewReader(body))
	inCell := false
	var cell strings.Builder
	cells := []string{}
	for {
		t := z.Next()
		if t == html.ErrorToken {
			break
		}
		if t == html.StartTagToken {
			name, _ := z.TagName()
			if string(name) == "td" || string(name) == "th" {
				inCell = true
				cell.Reset()
			}
		}
		if t == html.TextToken && inCell {
			cell.Write(z.Text())
		}
		if t == html.EndTagToken {
			name, _ := z.TagName()
			if (string(name) == "td" || string(name) == "th") && inCell {
				cells = append(cells, strings.TrimSpace(cell.String()))
				inCell = false
			}
		}
	}
	details := map[string]string{}
	for i := 0; i+1 < len(cells); i++ {
		label := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(cells[i], ":")))
		switch label {
		case "module", "notification", "handler", "physical path", "logon method":
			details[label] = clean(cells[i+1], 512)
		}
	}
	if len(details) >= 2 {
		x.Summary["iis_details"] = details
	}
}

func inspectXML(x *Result, body []byte) {
	d := xml.NewDecoder(bytes.NewReader(body))
	root := xml.Name{}
	count := 0
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
		if e, ok := t.(xml.StartElement); ok {
			if root.Local == "" {
				root = e.Name
			}
			if e.Name.Local == "EntitySet" || e.Name.Local == "operation" {
				count++
			}
		}
	}
	x.Kind = "xml"
	switch {
	case root.Local == "definitions" && root.Space == "http://schemas.xmlsoap.org/wsdl/":
		x.Kind = "wsdl"
	case root.Local == "Edmx" && (root.Space == "http://schemas.microsoft.com/ado/2007/06/edmx" || root.Space == "http://docs.oasis-open.org/odata/ns/edmx"):
		x.Kind = "odata_schema"
	case root.Local == "service" && root.Space == "http://www.w3.org/2007/app":
		x.Kind = "odata_service"
	}
	x.Summary["xml_root"] = clean(root.Local, 128)
	x.Summary["xml_namespace"] = clean(root.Space, 256)
	if x.Kind != "xml" {
		x.Summary["entity_set_or_operation_elements"] = count
	}
}

func compareControl(r *Report) {
	var control Result
	for _, x := range r.Results {
		if x.Request.ID == "control" {
			control = x
		}
	}
	if control.Status != 200 || control.Truncated || control.Error != "" {
		return
	}
	r.finding("info", "control_returns_200", "control", "The unlikely missing-path control returns 200; inspect fallback routing before treating 200 as route existence")
	for _, x := range r.Results {
		if x.Request.ID != "control" && x.Status == 200 && !x.Truncated && x.Error == "" && x.SHA256 == control.SHA256 {
			r.finding("warn", "matches_missing_control", x.Request.ID, "Response bytes match the missing-path control; endpoint-specific availability is unproven")
		}
	}
}

// Compare adds semantic changes, ignoring timestamps, body hashes, lengths,
// remote IP, TLS certificate rotation and volatile headers. Both reports must
// be complete and use the same publication/profile/options. It never declares
// a previous report secure or treats absence of differences as a security verdict.
func Compare(current *Report, baseline Report) error {
	if err := CompatibleBaseline(current.Plan, baseline); err != nil {
		return err
	}
	if err := CompatibleBaseline(current.Plan, *current); err != nil {
		return err
	}
	for i, x := range current.Results {
		old := baseline.Results[i]
		b := semanticSignature(old)
		a := semanticSignature(x)
		if !bytes.Equal(a, b) {
			current.finding("warn", "baseline_changed", x.Request.ID, "Status, representation, authentication challenge, redirect or selected metadata differs from baseline")
		}
	}
	if current.TLSVerificationDisabled != baseline.TLSVerificationDisabled || (current.TLS != nil && baseline.TLS != nil && current.TLS.Verified != baseline.TLS.Verified) {
		current.finding("warn", "baseline_tls_changed", "", "TLS verification state differs from baseline")
	}
	return nil
}

func semanticSignature(x Result) []byte {
	// JSON omitempty normalizes empty maps/slices after a saved-report round trip.
	if len(x.AuthSchemes) == 0 {
		x.AuthSchemes = nil
	}
	if len(x.Summary) == 0 {
		x.Summary = nil
	}
	b, _ := json.Marshal([]any{x.Status, x.Kind, x.ContentType, x.AuthSchemes, x.BasicRealm, x.Redirect, x.Summary})
	return b
}

var errIncompleteBaseline = errors.New("baseline comparison requires complete reports from the same URL, profile and asset option")

func CompatibleBaseline(p Plan, b Report) error {
	if !b.Complete || !reflect.DeepEqual(p, b.Plan) || len(b.Results) != len(p.Requests) {
		return errIncompleteBaseline
	}
	for i, x := range b.Results {
		if x.Request.ID != p.Requests[i].ID || x.Request.Method != p.Requests[i].Method || x.Error != "" || x.Truncated {
			return errIncompleteBaseline
		}
	}
	return nil
}
