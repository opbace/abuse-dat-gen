// SPDX-License-Identifier: GPL-3.0-only

// Package compat checks generated geosite files against Xray itself.
package compat

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/infra/conf"
)

// matcher loads ext:<file>:<code> exactly the way an Xray routing rule
// does and builds Xray's domain matcher from it.
func matcher(t testing.TB, dir, file, code string) (*router.DomainMatcher, int) {
	t.Helper()
	t.Setenv("xray.location.asset", dir)

	raw := fmt.Sprintf(`{"rules":[{"type":"field","outboundTag":"block","domain":["ext:%s:%s"]}]}`, file, code)
	var rc conf.RouterConfig
	if err := json.Unmarshal([]byte(raw), &rc); err != nil {
		t.Fatal(err)
	}
	cfg, err := rc.Build()
	if err != nil {
		t.Fatalf("xray could not load ext:%s:%s: %v", file, code, err)
	}
	domains := cfg.Rule[0].GetDomain()
	m, err := router.NewMphMatcherGroup(domains)
	if err != nil {
		t.Fatalf("xray could not build a matcher for %s: %v", code, err)
	}
	return m, len(domains)
}

func expect(t *testing.T, m *router.DomainMatcher, code string, cases map[string]bool) {
	t.Helper()
	for name, want := range cases {
		if got := m.ApplyDomain(name); got != want {
			t.Errorf("%s: xray matches %q = %v; want %v", code, name, got, want)
		}
	}
}

// TestGolden mirrors the fixture in internal/geosite/geosite_test.go.
func TestGolden(t *testing.T) {
	dir, err := filepath.Abs("../testdata")
	if err != nil {
		t.Fatal(err)
	}

	abuse, n := matcher(t, dir, "golden.dat", "abuse") // lower case, as users write it
	if n != 3 {
		t.Errorf("ABUSE: xray loaded %d rules; want 3", n)
	}
	expect(t, abuse, "ABUSE", map[string]bool{
		"pcxrl.com":              true,
		"api.pcxrl.com":          true, // domain: covers subdomains
		"pcxrlback.com":          true,
		"exact-only.example":     true,
		"sub.exact-only.example": false, // full: does not
		"google.com":             false,
	})
}

// TestRelease loads a real build. It runs when ABUSE_DAT_DIR points at the
// generator's output directory, as the release workflow does, and reports
// what loading each file costs.
func TestRelease(t *testing.T) {
	dir := os.Getenv("ABUSE_DAT_DIR")
	if dir == "" {
		t.Skip("set ABUSE_DAT_DIR to the directory holding the generated .dat files")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}

	report := "\n| File | Rules loaded by Xray | Load + matcher time | Heap retained |\n|---|---:|---:|---:|\n"
	for _, file := range []string{"abuse.dat", "abuse-medium.dat", "abuse-mini.dat"} {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()

		m, n := matcher(t, dir, file, "abuse")

		elapsed := time.Since(start)
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)

		for _, name := range []string{"google.com", "www.google.com", "apple.com", "github.com", "cloudflare.com", "whatsapp.net"} {
			if m.ApplyDomain(name) {
				t.Errorf("%s blocks %s", file, name)
			}
		}
		// Canary from the incident this project grew out of: a BadBox 2.0
		// command-and-control domain listed in every TIF size.
		if !m.ApplyDomain("pcxrl.com") {
			t.Logf("warning: %s no longer contains pcxrl.com (upstream may have delisted it)", file)
		}
		runtime.KeepAlive(m)
		report += fmt.Sprintf("| %s | %d | %s | %.0f MiB |\n", file, n, elapsed.Round(time.Millisecond), float64(retained)/(1<<20))
	}

	t.Log(report)
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
			f.WriteString("### Xray compatibility" + report)
			f.Close()
		}
	}
}
