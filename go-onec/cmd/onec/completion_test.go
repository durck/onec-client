package main

import (
	"slices"
	"testing"
)

func TestCompletionUsesRealScopedFlags(t *testing.T) {
	for _, tc := range []struct {
		words                 []string
		current, want, absent string
	}{
		{nil, "wi", "wizard", "--file"},
		{[]string{"epf"}, "r", "run", "login"},
		{[]string{"login"}, "--", "--database", "--file"},
		{[]string{"epf", "run"}, "--", "--file", "--cluster"},
		{[]string{"admin", "sessions"}, "--", "--cluster", "--file"},
		{[]string{"login", "--auth"}, "l", "legacy", "windows"},
		{[]string{"login"}, "--auth=l", "--auth=legacy", "--auth=windows"},
		{[]string{"web", "login", "--auth"}, "a", "auto", "windows"},
		{[]string{"--output", "text", "login"}, "--dat", "--database", "--file"},
		{[]string{"--output"}, "j", "json", "text"},
		{nil, "--output=j", "--output=json", "--output=text"},
		{[]string{"help"}, "lo", "login", "--file"},
		{[]string{"help", "epf"}, "r", "run", "--file"},
	} {
		got := completionCandidates(tc.words, tc.current)
		if !slices.Contains(got, tc.want) || slices.Contains(got, tc.absent) {
			t.Fatalf("%v %q: %v", tc.words, tc.current, got)
		}
	}
	if got := completionCandidates([]string{"epf", "run", "--arg"}, "--"); len(got) != 0 {
		t.Fatal("flag-looking argument was completed as an option", got)
	}
}
