// SPDX-License-Identifier: GPL-3.0-only

// Package build turns upstream lists into geosite .dat files, text lists and a
// manifest, and refuses to publish anything that fails a quality gate.
package build

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/opbace/abuse-dat-gen/internal/geosite"
	"github.com/opbace/abuse-dat-gen/internal/lists"
)

// Fetcher downloads a list.
type Fetcher interface {
	Fetch(ctx context.Context, url string) (*lists.Download, error)
}

// Options configures a build.
type Options struct {
	OutDir     string
	Sources    []Source
	Categories []Category
	Allowlist  []string // normalized
	Fetcher    Fetcher
	Version    string

	// Previous is the manifest of the last published release, if any.
	Previous *Manifest
	// MaxDrop fails the build when a category shrinks by more than this
	// fraction compared with Previous.
	MaxDrop float64
	// MaxInvalid fails the build when more than this fraction of a list's
	// lines cannot be parsed, which usually means upstream changed format.
	MaxInvalid float64

	Now func() time.Time
}

// Manifest describes one build. It is published next to the .dat files.
type Manifest struct {
	Generator   string           `json:"generator"`
	Version     string           `json:"version"`
	GeneratedAt time.Time        `json:"generated_at"`
	Sources     []SourceReport   `json:"sources"`
	Categories  []CategoryReport `json:"categories"`
	Files       []FileReport     `json:"files"`
}

type SourceReport struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Homepage    string    `json:"homepage"`
	License     string    `json:"license"`
	LicenseURL  string    `json:"license_url"`
	Attribution string    `json:"attribution"`
	FetchedAt   time.Time `json:"fetched_at"`
	Bytes       int       `json:"bytes"`
	SHA256      string    `json:"sha256"`
	lists.Stats
}

type CategoryReport struct {
	File        string   `json:"file"`
	Code        string   `json:"code"`
	Description string   `json:"description"`
	Sources     []string `json:"sources"`
	Rules       int      `json:"rules"`
	DomainRules int      `json:"domain_rules"`
	FullRules   int      `json:"full_rules"`
	// Collapsed counts rules dropped because a broader rule already covers them.
	Collapsed           int      `json:"collapsed"`
	RemovedPublicSuffix []string `json:"removed_public_suffix"`
	RemovedByAllowlist  []string `json:"removed_by_allowlist"`
	PreviousRules       int      `json:"previous_rules,omitempty"`
}

type FileReport struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// GateError collects every failed quality gate so one run reports all of
// them.
type GateError struct{ Failures []string }

func (e *GateError) Error() string {
	return "quality gates failed:\n  - " + strings.Join(e.Failures, "\n  - ")
}

// Run fetches, builds and verifies everything, then writes the outputs to
// OutDir. Nothing is written to OutDir unless every gate passes.
func Run(ctx context.Context, o Options) (*Manifest, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	m := &Manifest{Generator: "abuse-dat-gen", Version: o.Version, GeneratedAt: now().UTC()}
	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }

	// 1. Fetch and parse every source.
	parsed := map[string][]lists.Rule{}
	for _, src := range o.Sources {
		d, err := o.Fetcher.Fetch(ctx, src.URL)
		if err != nil {
			fail("source %s: %v", src.Name, err)
			continue
		}
		rules, st, err := lists.Parse(bytes.NewReader(d.Body), src.Format)
		if err != nil {
			fail("source %s: %v", src.Name, err)
			continue
		}
		m.Sources = append(m.Sources, SourceReport{
			Name: src.Name, URL: src.URL, Homepage: src.Homepage,
			License: src.License, LicenseURL: src.LicenseURL, Attribution: src.Attribution,
			FetchedAt: d.FetchedAt, Bytes: len(d.Body), SHA256: d.SHA256, Stats: st,
		})
		if st.Rules < src.MinRules {
			fail("source %s: %d rules, below the floor of %d", src.Name, st.Rules, src.MinRules)
		}
		if st.Lines > 0 && float64(st.Invalid)/float64(st.Lines) > o.MaxInvalid {
			fail("source %s: %d of %d lines invalid (limit %.2f%%), samples %q",
				src.Name, st.Invalid, st.Lines, o.MaxInvalid*100, st.InvalidSamples)
		}
		parsed[src.Name] = rules
	}
	if len(failures) > 0 {
		return m, &GateError{failures}
	}

	// 2. Build each category.
	allow := newAllowlist(o.Allowlist)
	previous := map[string]int{}
	if o.Previous != nil {
		for _, c := range o.Previous.Categories {
			previous[c.File] = c.Rules
		}
	}
	files := map[string][]byte{}
	seen := map[string]bool{}
	for _, cat := range o.Categories {
		if !validFileName(cat.File) {
			fail("category %q: file name must be 1-64 characters of a-z, 0-9 and '-'", cat.File)
			continue
		}
		if seen[cat.File] {
			fail("category %s: duplicate file name", cat.File)
			continue
		}
		seen[cat.File] = true
		if err := geosite.ValidateCode(cat.Code); err != nil {
			fail("category %s: %v", cat.File, err)
			continue
		}
		set := newRuleSet()
		for _, name := range cat.Sources {
			rules, ok := parsed[name]
			if !ok {
				fail("category %s: unknown source %q", cat.File, name)
				continue
			}
			for _, r := range rules {
				set.add(r)
			}
		}
		psl := set.removePublicSuffixes()
		allowed := set.removeAllowlisted(allow)
		rules, collapsed := set.compact()

		rep := CategoryReport{
			File: cat.File, Code: cat.Code, Description: cat.Description, Sources: cat.Sources,
			Rules: len(rules), Collapsed: collapsed,
			RemovedPublicSuffix: ruleStrings(psl), RemovedByAllowlist: ruleStrings(allowed),
			PreviousRules: previous[cat.File],
		}
		for _, r := range rules {
			if r.Kind == lists.Exact {
				rep.FullRules++
			} else {
				rep.DomainRules++
			}
		}
		m.Categories = append(m.Categories, rep)

		if len(rules) < cat.MinRules {
			fail("category %s: %d rules, below the floor of %d", cat.File, len(rules), cat.MinRules)
		}
		if prev := previous[cat.File]; prev > 0 {
			if drop := 1 - float64(len(rules))/float64(prev); drop > o.MaxDrop {
				fail("category %s: shrank %.1f%% since the previous release (%d -> %d, limit %.0f%%)",
					cat.File, drop*100, prev, len(rules), o.MaxDrop*100)
			}
		}
		// By construction nothing allowlisted survives; this guards the
		// construction.
		final := newRuleSet()
		for _, r := range rules {
			final.add(r)
		}
		for name := range allow.names {
			if final.matches(name) {
				fail("category %s: still matches allowlisted %s", cat.File, name)
			}
		}

		// 3. Encode, then decode the bytes back and compare.
		site := []geosite.Site{{Code: cat.Code, Rules: rules}}
		var dat bytes.Buffer
		if err := geosite.Write(&dat, site); err != nil {
			return m, fmt.Errorf("encode %s.dat: %w", cat.File, err)
		}
		decoded, err := geosite.Read(dat.Bytes())
		if err != nil {
			fail("%s.dat does not decode: %v", cat.File, err)
			continue
		}
		if !geosite.Equal(site, decoded) {
			fail("%s.dat decodes to different content than was encoded", cat.File)
			continue
		}
		files[cat.File+".dat"] = dat.Bytes()
		files[cat.File+".txt"] = textList(rep, rules, m)
	}
	if len(failures) > 0 {
		return m, &GateError{failures}
	}

	// 4. Write everything to a staging directory and swap it in.
	stage := o.OutDir + ".staging"
	if err := os.RemoveAll(stage); err != nil {
		return m, err
	}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return m, err
	}
	// Flat layout: GitHub release assets cannot live in subdirectories, and
	// sha256sums.txt has to verify against a plain download of the release.
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		data := files[name]
		if err := os.WriteFile(filepath.Join(stage, name), data, 0o644); err != nil {
			return m, err
		}
		sum := sha256.Sum256(data)
		hexSum := hex.EncodeToString(sum[:])
		m.Files = append(m.Files, FileReport{Name: name, Bytes: int64(len(data)), SHA256: hexSum})
		fmt.Fprintf(&sums, "%s  %s\n", hexSum, name)
	}
	if err := os.WriteFile(filepath.Join(stage, "sha256sums.txt"), []byte(sums.String()), 0o644); err != nil {
		return m, err
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, err
	}
	if err := os.WriteFile(filepath.Join(stage, "manifest.json"), append(mj, '\n'), 0o644); err != nil {
		return m, err
	}
	if err := os.RemoveAll(o.OutDir); err != nil {
		return m, err
	}
	if err := os.Rename(stage, o.OutDir); err != nil {
		return m, err
	}
	return m, nil
}

// textList renders a category in the same "domain:" / "full:" syntax Xray
// accepts in routing rules. These files are also the preferred form for
// modifying the data, which the GPL asks to be available.
func textList(c CategoryReport, rules []lists.Rule, m *Manifest) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s.txt (category %s) - generated by abuse-dat-gen %s at %s\n",
		c.File, c.Code, m.Version, m.GeneratedAt.Format(time.RFC3339))
	b.WriteString("# License: GPL-3.0-only. Provided without warranty; see DISCLAIMER.md.\n")
	b.WriteString("# Contains data from:\n")
	for _, src := range m.Sources {
		if slices.Contains(c.Sources, src.Name) {
			fmt.Fprintf(&b, "#   - %s\n", src.Attribution)
		}
	}
	for _, r := range rules {
		b.WriteString(r.Kind.String())
		b.WriteByte(':')
		b.WriteString(r.Value)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func validFileName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func ruleStrings(rules []lists.Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.Kind.String() + ":" + r.Value
	}
	sort.Strings(out)
	return out
}

// LoadAllowlist reads one domain per line; '#' starts a comment.
func LoadAllowlist(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var names []string
	for i, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n, err := lists.Normalize(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %q: %w", path, i+1, line, err)
		}
		names = append(names, n)
	}
	if len(names) == 0 {
		return nil, errors.New(path + ": allowlist is empty")
	}
	return names, nil
}
