// SPDX-License-Identifier: GPL-3.0-only

package lists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	ok := map[string]string{
		"Example.COM":           "example.com",
		"example.com.":          "example.com",
		"  a-b.example.com  ":   "a-b.example.com",
		"_dmarc.example.com":    "_dmarc.example.com",
		"bücher.example":        "xn--bcher-kva.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
	}
	for in, want := range ok {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", ".", "com", "localhost", "1.2.3.4", "::1",
		"exa mple.com", "example..com", "ex*ample.com", "example.com/path",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 127) + "com",
	}
	for _, in := range bad {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q; want error", in, got)
		}
	}
}

func TestParseWildcard(t *testing.T) {
	in := `# Title: HaGeZi's Threat Intelligence Feeds
! adblock-style comment

*.pcxrl.com
*.PCXRLBACK.com
pcxrl.org
*.
||bad.example^
`
	rules, st, err := Parse(strings.NewReader(in), Wildcard)
	if err != nil {
		t.Fatal(err)
	}
	want := []Rule{{Suffix, "pcxrl.com"}, {Suffix, "pcxrlback.com"}}
	if !slices.Equal(rules, want) {
		t.Errorf("rules = %v; want %v", rules, want)
	}
	if st.Lines != 5 || st.Rules != 2 || st.Invalid != 3 {
		t.Errorf("stats = %+v; want 5 lines, 2 rules, 3 invalid", st)
	}
}

func TestParseDomains(t *testing.T) {
	in := `### An exact-match domain list
# https://www.humansecurity.com/learn/blog/satori-threat-intelligence-disruption-badbox-2-0/
# Added on: 2025-06-06
pcxrl.com
pcxrlback.com

0.0.0.0 hosts-style.example
*.wildcard.example
`
	rules, st, err := Parse(strings.NewReader(in), Domains)
	if err != nil {
		t.Fatal(err)
	}
	want := []Rule{{Exact, "pcxrl.com"}, {Exact, "pcxrlback.com"}}
	if !slices.Equal(rules, want) {
		t.Errorf("rules = %v; want %v", rules, want)
	}
	if st.Invalid != 2 || len(st.InvalidSamples) != 2 {
		t.Errorf("stats = %+v; want 2 invalid with samples", st)
	}
}

func TestFetch(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch r.URL.Path {
		case "/flaky":
			if n == 1 {
				http.Error(w, "busy", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte("*.example.com\n"))
		case "/missing":
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	f := &Fetcher{Attempts: 3, Backoff: time.Millisecond, UserAgent: "test"}

	d, err := f.Fetch(context.Background(), srv.URL+"/flaky")
	if err != nil {
		t.Fatalf("flaky: %v", err)
	}
	if string(d.Body) != "*.example.com\n" || len(d.SHA256) != 64 {
		t.Errorf("flaky: got body %q sha %q", d.Body, d.SHA256)
	}
	if calls.Load() != 2 {
		t.Errorf("flaky: %d calls; want a retry after 503", calls.Load())
	}

	calls.Store(0)
	if _, err := f.Fetch(context.Background(), srv.URL+"/missing"); err == nil {
		t.Error("missing: want error for 404")
	}
	if calls.Load() != 1 {
		t.Errorf("missing: %d calls; a 404 must not be retried", calls.Load())
	}
}
