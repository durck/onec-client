package main

import (
	"bytes"
	"encoding/json"
	"io"
	"runtime"
	"testing"
)

func TestNativePlatformDefaults(t *testing.T) {
	flags, o := newCommandFlags("onec login", io.Discard)
	if _, err := parseCommandFlags(flags, nil); err != nil {
		t.Fatal(err)
	}
	cfg, err := o.config(true)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if o.auth != "windows" || o.transportIdentity() != "windows" {
			t.Fatal("Windows defaults changed")
		}
	} else {
		if o.auth != "legacy" || o.transportIdentity() != "anonymous" || cfg.SecurityFactory == nil {
			t.Fatal("portable defaults missing")
		}
		provider, err := cfg.SecurityFactory()
		if err != nil {
			t.Fatal(err)
		}
		defer provider.Close()
		if name, err := provider.Name(); name != "ANONYMOUS LOGON" || err != nil {
			t.Fatal("OS credentials selected")
		}
	}
	var out bytes.Buffer
	if err = run([]string{"admin", "clusters"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err = json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	want := "anonymous"
	if runtime.GOOS == "windows" {
		want = "windows"
	}
	if report["transport"] != want || report["network_requests_sent"] != false {
		t.Fatal("incorrect admin default", report)
	}
}

func TestAnonymousIdentityCannotAuthenticateWindowsAccount(t *testing.T) {
	for _, args := range [][]string{
		{"login", "--auth", "windows", "--transport", "anonymous"},
		{"login", "--auth", "windows", "--ntlm", "password", "--ntlm-user", "fixture", "--ntlm-domain", "EXAMPLE", "--transport", "anonymous"},
	} {
		var out bytes.Buffer
		if err := run(args, &out, io.Discard); err == nil || out.Len() != 0 {
			t.Fatal("mixed identities accepted")
		}
	}
}
