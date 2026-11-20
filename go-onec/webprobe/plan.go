// Package webprobe inventories a bounded, anonymous 1C web-publication profile.
// It does not authenticate, execute downloaded code, or enumerate other sites.
package webprobe

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Profile = "onec-web-v1"

type Config struct {
	URL      string
	Assets   bool
	Insecure bool
	Timeout  time.Duration
}

type Request struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
}

type Plan struct {
	Profile     string    `json:"profile"`
	URL         string    `json:"url"`
	Publication string    `json:"publication"`
	Assets      bool      `json:"assets"`
	Requests    []Request `json:"requests"`
}

var localeSuffix = regexp.MustCompile(`^[a-z]{2}_[A-Z]{2}$`)

// NewPlan validates without DNS or network access. URL is a known publication
// directory, optionally ending in a locale (for example /demo/ru_RU/).
func NewPlan(c Config) (Plan, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return Plan{}, errors.New("url must be an HTTP(S) publication URL without credentials, query or fragment")
	}
	if c.Timeout < 0 || c.Timeout > 3*time.Minute {
		return Plan{}, errors.New("timeout must be positive and at most 3m (zero selects 3m in the API)")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return Plan{}, errors.New("URL port must be in 1..65535")
		}
	}
	if strings.ContainsAny(u.Path, "%\\") || strings.Contains(u.Path, "//") || strings.IndexFunc(c.URL+u.Path, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 {
		return Plan{}, errors.New("url contains an ambiguous path or whitespace/control characters")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return Plan{}, errors.New("provide a known publication path, not just the web-server origin")
		}
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/"
	u.RawPath = ""
	entry := u.String()
	locale := ""
	if localeSuffix.MatchString(parts[len(parts)-1]) {
		locale = strings.ToUpper(parts[len(parts)-1])
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return Plan{}, errors.New("publication path is missing before the locale")
	}
	u.Path = "/" + strings.Join(parts, "/") + "/"
	p := Plan{Profile: Profile, URL: entry, Publication: u.String(), Assets: c.Assets}
	add := func(id, method, base, tail string) { p.Requests = append(p.Requests, Request{id, method, base + tail}) }
	add("entry", "GET", entry, "")
	add("manifest", "GET", entry, "manifest.json")
	add("users", "GET", entry, "e1cib/users")
	add("auth-settings", "POST", entry, "e1cib/additionalAuthSettings?version=1")
	for _, r := range [][2]string{{"about", "about"}, {"types", "types"}, {"sysenums", "sysenums"}, {"module-defs", "modules/defs"}, {"syspics", "syspics"}} {
		add(r[0], "GET", entry, "e1cib/"+r[1])
	}
	if locale != "" {
		add("locale", "GET", entry, "e1cib/misc?cmd=localeInfo&locale="+locale)
	}
	for _, r := range [][2]string{{"soap-root", "ws/"}, {"http-root", "hs/"}, {"odata-service", "odata/standard.odata/"}, {"odata-metadata", "odata/standard.odata/$metadata"}, {"catalogue-wsdl", "ws/WebCommonInfoBases?wsdl"}, {"distribution-wsdl", "ws/WebDistributiveLocation?wsdl"}} {
		add(r[0], "GET", p.Publication, r[1])
	}
	// A fixed, unlikely missing route is a comparison control, not proof of absence.
	add("control", "GET", entry, "__onec_web_probe_missing_ae7092b1__")
	if c.Assets {
		for _, r := range [][2]string{{"mainform", "mainform.html"}, {"authform", "authform.html"}, {"strings", "resourceStrings"}, {"bootstrap", "scripts/mod_bootstrap_bootstrap.js"}, {"service-worker", "scripts/mod_sw_sw.js"}, {"loader", "scripts/mod_main_loader.js"}, {"mainform-code", "scripts/mod_main_mainform.js"}} {
			add(r[0], "GET", entry, r[1])
		}
	}
	return p, nil
}

func versioned(r Request, version string) Request {
	if version == "" || r.ID == "entry" || r.ID == "users" || r.ID == "about" || r.ID == "control" {
		return r
	}
	u, _ := url.Parse(r.URL)
	if strings.Contains(u.Path, "/ws/") || strings.Contains(u.Path, "/hs/") || strings.Contains(u.Path, "/odata/") {
		return r
	}
	q := u.Query()
	q.Set("sysver", version)
	u.RawQuery = q.Encode()
	r.URL = u.String()
	return r
}
