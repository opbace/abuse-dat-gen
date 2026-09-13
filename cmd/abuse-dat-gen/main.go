// SPDX-License-Identifier: GPL-3.0-only

// Command abuse-dat-gen builds V2Ray/Xray geosite files of malware, phishing
// and other abuse domains from HaGeZi's Threat Intelligence Feeds.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/opbace/abuse-dat-gen/internal/build"
	"github.com/opbace/abuse-dat-gen/internal/lists"
)

func main() {
	var (
		outDir     = flag.String("out", "dist", "output directory (replaced on success)")
		allowPath  = flag.String("allowlist", "allowlist.txt", "domains that must never be blocked")
		previous   = flag.String("previous-manifest", "", "URL or path of the last release's manifest.json; a 404 is treated as no previous release")
		maxDrop    = flag.Float64("max-drop", 0.25, "fail if a category shrinks by more than this fraction versus the previous release")
		maxInvalid = flag.Float64("max-invalid", 0.01, "fail if more than this fraction of a list's lines are invalid")
		notesPath  = flag.String("release-notes", "", "also write Markdown release notes to this path")
		version    = flag.String("version", "", "version string recorded in the manifest (default: VCS revision)")
		timeout    = flag.Duration("timeout", 20*time.Minute, "overall time limit")
	)
	flag.Parse()

	if err := run(*outDir, *allowPath, *previous, *maxDrop, *maxInvalid, *notesPath, versionString(*version), *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "abuse-dat-gen:", err)
		os.Exit(1)
	}
}

func run(outDir, allowPath, previous string, maxDrop, maxInvalid float64, notesPath, version string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	allow, err := build.LoadAllowlist(allowPath)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	prev, err := loadPrevious(ctx, client, previous)
	if err != nil {
		return fmt.Errorf("previous manifest: %w", err)
	}

	m, err := build.Run(ctx, build.Options{
		OutDir:     outDir,
		Sources:    build.DefaultSources,
		Categories: build.DefaultCategories,
		Allowlist:  allow,
		Fetcher: &lists.Fetcher{
			Client:    client,
			UserAgent: "abuse-dat-gen/" + version,
			Attempts:  3,
			Backoff:   20 * time.Second,
		},
		Version:    version,
		Previous:   prev,
		MaxDrop:    maxDrop,
		MaxInvalid: maxInvalid,
	})
	summary := renderSummary(m, err)
	fmt.Print(summary)
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if f, ferr := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); ferr == nil {
			f.WriteString(summary)
			f.Close()
		}
	}
	if err != nil {
		return err
	}
	if notesPath != "" {
		if err := os.WriteFile(notesPath, []byte(renderNotes(m)), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func loadPrevious(ctx context.Context, client *http.Client, loc string) (*build.Manifest, error) {
	if loc == "" {
		return nil, nil
	}
	var data []byte
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			fmt.Println("no previous release manifest; skipping the shrink check")
			return nil, nil
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: %s", loc, resp.Status)
		}
		if data, err = io.ReadAll(io.LimitReader(resp.Body, 16<<20)); err != nil {
			return nil, err
		}
	} else {
		var err error
		data, err = os.ReadFile(loc)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
	var m build.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func versionString(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return s.Value[:12]
			}
		}
	}
	return "dev"
}

func renderSummary(m *build.Manifest, err error) string {
	var b strings.Builder
	b.WriteString("## abuse-dat-gen\n\n")
	if m != nil && len(m.Sources) > 0 {
		b.WriteString("| Source | Rules | Invalid | Bytes |\n|---|---:|---:|---:|\n")
		for _, s := range m.Sources {
			fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", s.Name, s.Rules, s.Invalid, s.Bytes)
		}
		b.WriteString("\n")
	}
	if m != nil && len(m.Categories) > 0 {
		b.WriteString("| File | Rules | domain | full | Previous | Collapsed | Public suffix removed | Allowlist removed |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
		for _, c := range m.Categories {
			fmt.Fprintf(&b, "| %s.dat | %d | %d | %d | %d | %d | %d | %d |\n",
				c.File, c.Rules, c.DomainRules, c.FullRules, c.PreviousRules, c.Collapsed,
				len(c.RemovedPublicSuffix), len(c.RemovedByAllowlist))
		}
		b.WriteString("\n")
	}
	if err != nil {
		fmt.Fprintf(&b, "**Build failed; nothing was published.**\n\n```\n%v\n```\n", err)
	}
	return b.String()
}

func renderNotes(m *build.Manifest) string {
	var b strings.Builder
	b.WriteString("Automated build. Use at your own risk: see DISCLAIMER.md.\n\n")
	b.WriteString("| File | Xray rule | Rules |\n|---|---|---:|\n")
	for _, c := range m.Categories {
		fmt.Fprintf(&b, "| `%s.dat` | `ext:%s.dat:%s` | %d |\n", c.File, c.File, strings.ToLower(c.Code), c.Rules)
	}
	b.WriteString("\n### Attribution\n\n")
	for _, s := range m.Sources {
		fmt.Fprintf(&b, "- **%s** (sha256 `%s`): %s\n", s.Name, s.SHA256, s.Attribution)
	}
	b.WriteString("\nLicensed under GPL-3.0-only; the license texts are attached to this release.\n")
	return b.String()
}
