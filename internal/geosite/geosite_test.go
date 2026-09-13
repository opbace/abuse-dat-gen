// SPDX-License-Identifier: GPL-3.0-only

package geosite

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/opbace/abuse-dat-gen/internal/lists"
)

var update = flag.Bool("update", false, "rewrite testdata/golden.dat")

// goldenPath is shared with the compat module, which loads the same bytes
// through Xray itself.
const goldenPath = "../../testdata/golden.dat"

// goldenSites is the fixture behind testdata/golden.dat. compat/xray_test.go
// asserts the same expectations; keep the two in sync.
var goldenSites = []Site{
	{Code: "ABUSE", Rules: []lists.Rule{
		{Kind: lists.Suffix, Value: "pcxrl.com"},
		{Kind: lists.Suffix, Value: "pcxrlback.com"},
		{Kind: lists.Exact, Value: "exact-only.example"},
	}},
}

func TestGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, goldenSites); err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(goldenPath, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/geosite -update)", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatal("encoder output differs from testdata/golden.dat; if intended, rerun with -update and re-run the compat tests")
	}
}

func TestRoundTrip(t *testing.T) {
	sites := []Site{
		{Code: "FIRST", Rules: []lists.Rule{
			{Kind: lists.Suffix, Value: "a.example"},
			{Kind: lists.Exact, Value: "b.example"},
		}},
		{Code: "SECOND", Rules: []lists.Rule{{Kind: lists.Exact, Value: "c.example"}}},
		{Code: "EMPTY"},
	}
	var buf bytes.Buffer
	if err := Write(&buf, sites); err != nil {
		t.Fatal(err)
	}
	got, err := Read(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(got, sites) {
		t.Fatalf("round trip = %+v; want %+v", got, sites)
	}
}

func TestCodeIsFirstFieldWithSingleByteLength(t *testing.T) {
	// Xray finds a category by matching 0x0a <len> <code> at the start of the
	// entry body, so these bytes must be exactly there.
	var buf bytes.Buffer
	if err := Write(&buf, []Site{{Code: "ABUSE", Rules: []lists.Rule{{Kind: lists.Suffix, Value: "a.example"}}}}); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	// b[0] = entry tag, b[1] = entry length (small here), then the body.
	if !bytes.HasPrefix(b[2:], append([]byte{0x0a, 5}, "ABUSE"...)) {
		t.Fatalf("entry body starts with % x; want 0a 05 'ABUSE'", b[2:9])
	}
}

func TestValidateCode(t *testing.T) {
	for _, c := range []string{"ABUSE", "A-B", "A_1"} {
		if err := ValidateCode(c); err != nil {
			t.Errorf("ValidateCode(%q) = %v", c, err)
		}
	}
	for _, c := range []string{"", "abuse", "ABUSE!", strings.Repeat("A", MaxCodeLen+1)} {
		if err := ValidateCode(c); err == nil {
			t.Errorf("ValidateCode(%q) = nil; want error", c)
		}
	}
}

func TestReadRejectsForeignData(t *testing.T) {
	cases := map[string][]byte{
		"truncated":          {0x0a, 0x10, 0x0a},
		"domain before code": {0x0a, 0x06, 0x12, 0x04, 0x08, 0x02, 0x12, 0x00},
		"regex type":         {0x0a, 0x0b, 0x0a, 0x01, 'A', 0x12, 0x06, 0x08, 0x01, 0x12, 0x02, 'a', 'b'},
	}
	for name, data := range cases {
		if _, err := Read(data); err == nil {
			t.Errorf("%s: Read succeeded; want error", name)
		}
	}
}
