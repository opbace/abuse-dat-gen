// SPDX-License-Identifier: GPL-3.0-only

package build

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opbace/abuse-dat-gen/internal/geosite"
	"github.com/opbace/abuse-dat-gen/internal/lists"
)

func rules(specs ...string) []lists.Rule {
	var out []lists.Rule
	for _, s := range specs {
		kind, v, _ := strings.Cut(s, ":")
		k := lists.Suffix
		if kind == "full" {
			k = lists.Exact
		}
		out = append(out, lists.Rule{Kind: k, Value: v})
	}
	return out
}

func setOf(specs ...string) *ruleSet {
	s := newRuleSet()
	for _, r := range rules(specs...) {
		s.add(r)
	}
	return s
}

func TestCompact(t *testing.T) {
	s := setOf(
		"domain:example.com",
		"domain:a.example.com", // covered
		"full:example.com",     // covered
		"full:b.example.com",   // covered
		"domain:x.y.other.org",
		"domain:y.other.org", // covers the previous one
		"full:other.org",     // not covered: suffix is below it
		"full:solo.net",
		"full:solo.net", // duplicate
	)
	got, dropped := s.compact()
	want := rules("domain:example.com", "full:other.org", "full:solo.net", "domain:y.other.org")
	if !slices.Equal(got, want) {
		t.Errorf("compact = %v; want %v", got, want)
	}
	if dropped != 4 {
		t.Errorf("dropped = %d; want 4", dropped)
	}
}

func TestMatches(t *testing.T) {
	s := setOf("domain:example.com", "full:exact.org")
	for name, want := range map[string]bool{
		"example.com": true, "deep.a.example.com": true, "notexample.com": false,
		"exact.org": true, "sub.exact.org": false,
	} {
		if got := s.matches(name); got != want {
			t.Errorf("matches(%q) = %v; want %v", name, got, want)
		}
	}
}

func TestRemovePublicSuffixes(t *testing.T) {
	s := setOf(
		"domain:github.io",                           // explicit PSL entry: removed
		"domain:co.uk",                               // explicit: removed
		"domain:evil.github.io",                      // one site under it: kept
		"full:github.io",                             // exact rules never removed
		"domain:x1y2z3.localto.net",                  // public suffix only via *.localto.net: kept
		"domain:ec2-1-2-3-4.compute-1.amazonaws.com", // via a wildcard: kept
		"domain:pcxrl.com",
	)
	removed := s.removePublicSuffixes()
	slices.SortFunc(removed, func(a, b lists.Rule) int { return strings.Compare(a.Value, b.Value) })
	if want := rules("domain:co.uk", "domain:github.io"); !slices.Equal(removed, want) {
		t.Errorf("removed = %v; want %v", removed, want)
	}
	for _, keep := range []string{"evil.github.io", "x1y2z3.localto.net", "ec2-1-2-3-4.compute-1.amazonaws.com", "pcxrl.com"} {
		if !s.matches(keep) {
			t.Errorf("%s should still be blocked", keep)
		}
	}
	if _, ok := s.exact["github.io"]; !ok {
		t.Error("full:github.io should be kept")
	}
}

func TestAllowlist(t *testing.T) {
	a := newAllowlist([]string{"google.com", "mail.example.org"})
	for spec, want := range map[string]bool{
		"domain:google.com":        true, // the name itself
		"full:google.com":          true,
		"domain:ads.google.com":    true, // below an allowlisted name
		"full:x.ads.google.com":    true,
		"domain:example.org":       true,  // above: would cover mail.example.org
		"full:example.org":         false, // exact apex does not cover mail.
		"domain:other.example.org": false,
		"domain:notgoogle.com":     false,
	} {
		if got := a.conflicts(rules(spec)[0]); got != want {
			t.Errorf("conflicts(%s) = %v; want %v", spec, got, want)
		}
	}
}

type fakeFetcher map[string]string

func (f fakeFetcher) Fetch(_ context.Context, url string) (*lists.Download, error) {
	body, ok := f[url]
	if !ok {
		return nil, errors.New("not found")
	}
	sum := sha256.Sum256([]byte(body))
	return &lists.Download{Body: []byte(body), SHA256: hex.EncodeToString(sum[:]), FetchedAt: time.Unix(0, 0)}, nil
}

func testOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		OutDir: filepath.Join(t.TempDir(), "dist"),
		Sources: []Source{
			{Name: "tif", URL: "u:tif", Format: lists.Wildcard, Attribution: "TIF attribution", MinRules: 2},
			{Name: "ch", URL: "u:ch", Format: lists.Domains, Attribution: "CH attribution", MinRules: 1},
		},
		Categories: []Category{
			{Code: "ABUSE", Sources: []string{"tif", "ch"}, MinRules: 2},
			{Code: "CH", Sources: []string{"ch"}, MinRules: 1},
		},
		Allowlist: []string{"google.com"},
		Fetcher: fakeFetcher{
			"u:tif": "*.pcxrl.com\n*.a.pcxrl.com\n*.pages.dev\n*.ads.google.com\n*.evil.example\n",
			"u:ch":  "# comment\npcxrl.com\npcxrlback.com\n",
		},
		Version:    "test",
		MaxDrop:    0.25,
		MaxInvalid: 0.01,
		Now:        func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) },
	}
}

func TestRun(t *testing.T) {
	o := testOptions(t)
	m, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(o.OutDir, DatFile))
	if err != nil {
		t.Fatal(err)
	}
	sites, err := geosite.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []geosite.Site{
		{Code: "ABUSE", Rules: rules("domain:evil.example", "domain:pcxrl.com", "full:pcxrlback.com")},
		{Code: "CH", Rules: rules("full:pcxrl.com", "full:pcxrlback.com")},
	}
	if !geosite.Equal(sites, want) {
		t.Errorf("abuse.dat = %+v; want %+v", sites, want)
	}

	abuse := m.Categories[0]
	if !slices.Equal(abuse.RemovedPublicSuffix, []string{"domain:pages.dev"}) {
		t.Errorf("removed_public_suffix = %v", abuse.RemovedPublicSuffix)
	}
	if !slices.Equal(abuse.RemovedByAllowlist, []string{"domain:ads.google.com"}) {
		t.Errorf("removed_by_allowlist = %v", abuse.RemovedByAllowlist)
	}

	txt, err := os.ReadFile(filepath.Join(o.OutDir, "abuse.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"TIF attribution", "CH attribution", "GPL-3.0-only", "\ndomain:pcxrl.com\n", "\nfull:pcxrlback.com\n"} {
		if !strings.Contains(string(txt), s) {
			t.Errorf("abuse.txt lacks %q", s)
		}
	}
	chTxt, _ := os.ReadFile(filepath.Join(o.OutDir, "ch.txt"))
	if strings.Contains(string(chTxt), "TIF attribution") {
		t.Error("ch.txt credits a source it does not use")
	}

	var onDisk Manifest
	mj, _ := os.ReadFile(filepath.Join(o.OutDir, "manifest.json"))
	if err := json.Unmarshal(mj, &onDisk); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(o.OutDir, "sha256sums.txt"))
	for _, f := range onDisk.Files {
		b, _ := os.ReadFile(filepath.Join(o.OutDir, f.Name))
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != f.SHA256 || !strings.Contains(string(sums), f.SHA256+"  "+f.Name) {
			t.Errorf("checksum mismatch for %s", f.Name)
		}
	}
	if _, err := os.Stat(o.OutDir + ".staging"); !os.IsNotExist(err) {
		t.Error("staging directory left behind")
	}
}

func TestRunGates(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Options)
		want   string
	}{
		"source below floor": {
			func(o *Options) { o.Sources[0].MinRules = 100 },
			"source tif: 5 rules, below the floor of 100",
		},
		"format drift": {
			func(o *Options) { o.Fetcher.(fakeFetcher)["u:ch"] = "pcxrl.com\n||not-a-domain^\n" },
			"source ch: 1 of 2 lines invalid",
		},
		"download failure": {
			func(o *Options) { delete(o.Fetcher.(fakeFetcher), "u:ch") },
			"source ch: not found",
		},
		"shrank": {
			func(o *Options) { o.Previous = &Manifest{Categories: []CategoryReport{{Code: "ABUSE", Rules: 10}}} },
			"category ABUSE: shrank 70.0%",
		},
		"bad code": {
			func(o *Options) { o.Categories[1].Code = "lower" },
			`code "lower"`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			o := testOptions(t)
			o.Fetcher = cloneFetcher(o.Fetcher.(fakeFetcher))
			tc.mutate(&o)
			_, err := Run(context.Background(), o)
			var ge *GateError
			if !errors.As(err, &ge) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want gate failure containing %q", err, tc.want)
			}
			if _, statErr := os.Stat(o.OutDir); !os.IsNotExist(statErr) {
				t.Error("output directory written despite failed gate")
			}
		})
	}
}

func cloneFetcher(f fakeFetcher) fakeFetcher {
	c := fakeFetcher{}
	for k, v := range f {
		c[k] = v
	}
	return c
}

func TestLoadAllowlist(t *testing.T) {
	p := filepath.Join(t.TempDir(), "allow.txt")
	os.WriteFile(p, []byte("# c\nGoogle.com  # trailing\n\nexample.org.\n"), 0o644)
	got, err := LoadAllowlist(p)
	if err != nil || !slices.Equal(got, []string{"google.com", "example.org"}) {
		t.Errorf("LoadAllowlist = %v, %v", got, err)
	}
	os.WriteFile(p, []byte("not a domain\n"), 0o644)
	if _, err := LoadAllowlist(p); err == nil {
		t.Error("want error for invalid entry")
	}
}

func TestRepoAllowlistParses(t *testing.T) {
	names, err := LoadAllowlist("../../allowlist.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if isExplicitPublicSuffix(n) {
			t.Errorf("allowlist.txt: %s is a shared public suffix; allowlisting it would protect abuse hosted under it", n)
		}
	}
	t.Logf("%d allowlist entries", len(names))
}
