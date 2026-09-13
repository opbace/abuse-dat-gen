// SPDX-License-Identifier: GPL-3.0-only

package build

import (
	"cmp"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/opbace/abuse-dat-gen/internal/lists"
)

// ruleSet is a deduplicated set of suffix and exact rules.
type ruleSet struct {
	suffix map[string]struct{}
	exact  map[string]struct{}
}

func newRuleSet() *ruleSet {
	return &ruleSet{suffix: map[string]struct{}{}, exact: map[string]struct{}{}}
}

func (s *ruleSet) add(r lists.Rule) {
	if r.Kind == lists.Exact {
		s.exact[r.Value] = struct{}{}
	} else {
		s.suffix[r.Value] = struct{}{}
	}
}

func (s *ruleSet) remove(r lists.Rule) {
	if r.Kind == lists.Exact {
		delete(s.exact, r.Value)
	} else {
		delete(s.suffix, r.Value)
	}
}

func (s *ruleSet) rules() []lists.Rule {
	out := make([]lists.Rule, 0, len(s.suffix)+len(s.exact))
	for v := range s.suffix {
		out = append(out, lists.Rule{Kind: lists.Suffix, Value: v})
	}
	for v := range s.exact {
		out = append(out, lists.Rule{Kind: lists.Exact, Value: v})
	}
	return out
}

// matches reports whether name would be blocked: an exact rule for name, or
// a suffix rule for name or any of its parents.
func (s *ruleSet) matches(name string) bool {
	if _, ok := s.exact[name]; ok {
		return true
	}
	for p := range selfAndParents(name) {
		if _, ok := s.suffix[p]; ok {
			return true
		}
	}
	return false
}

// selfAndParents yields "a.b.c", "b.c", "c".
func selfAndParents(name string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for {
			if !yield(name) {
				return
			}
			i := strings.IndexByte(name, '.')
			if i < 0 {
				return
			}
			name = name[i+1:]
		}
	}
}

// properParents yields "b.c", "c" for "a.b.c".
func properParents(name string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for p := range selfAndParents(name) {
			if p != name && !yield(p) {
				return
			}
		}
	}
}

// compact drops rules already covered by a broader suffix rule and returns
// the rest sorted, so the output is reproducible:
//
//   - suffix "a.example.com" is redundant under suffix "example.com";
//   - exact "example.com" or "a.example.com" is redundant under suffix
//     "example.com".
//
// It returns the number of rules dropped.
func (s *ruleSet) compact() ([]lists.Rule, int) {
	dropped := 0
	for v := range s.suffix {
		for p := range properParents(v) {
			if _, ok := s.suffix[p]; ok {
				delete(s.suffix, v)
				dropped++
				break
			}
		}
	}
	for v := range s.exact {
		for p := range selfAndParents(v) {
			if _, ok := s.suffix[p]; ok {
				delete(s.exact, v)
				dropped++
				break
			}
		}
	}
	out := s.rules()
	slices.SortFunc(out, func(a, b lists.Rule) int {
		return cmp.Or(cmp.Compare(a.Value, b.Value), cmp.Compare(a.Kind, b.Kind))
	})
	return out, dropped
}

// removePublicSuffixes deletes suffix rules on a shared namespace that the
// Public Suffix List names explicitly: "co.uk", "github.io", "pages.dev", or
// dynamic-DNS providers such as "camdvr.org". A suffix rule there blocks every
// unrelated customer of that namespace. Their individual subdomains
// ("evil.github.io") stay blockable.
//
// Two kinds of rule are deliberately kept:
//
//   - Exact rules. They match one host and cannot spill onto neighbours.
//   - Names that are public suffixes only through a PSL wildcard, e.g.
//     "x1y2z3.localto.net" under "*.localto.net" or an EC2 hostname under
//     "*.compute-1.amazonaws.com". Each of those is a single tenant, which is
//     exactly the granularity abuse lists want to block.
func (s *ruleSet) removePublicSuffixes() []lists.Rule {
	var removed []lists.Rule
	for v := range s.suffix {
		if isExplicitPublicSuffix(v) {
			removed = append(removed, lists.Rule{Kind: lists.Suffix, Value: v})
		}
	}
	for _, r := range removed {
		s.remove(r)
	}
	return removed
}

// wildcardProbe is a label no real registry uses, substituted for a name's
// first label to tell wildcard PSL entries from explicit ones.
const wildcardProbe = "psl-wildcard-probe-7f3c9a"

func isExplicitPublicSuffix(name string) bool {
	if ps, _ := publicsuffix.PublicSuffix(name); ps != name {
		return false
	}
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return true
	}
	// Under a wildcard entry "*.parent", any first label is a public suffix
	// too; under an explicit entry it is not.
	probe := wildcardProbe + name[i:]
	ps, _ := publicsuffix.PublicSuffix(probe)
	return ps != probe
}

// allowlist holds names that must never be blocked. An entry covers the name
// and everything below it: allowlisting "google.com" also protects
// "mail.google.com". Shared-hosting suffixes do not belong here; they are
// handled by removePublicSuffixes so that individual abusive sites under
// them stay blockable.
type allowlist struct {
	names   map[string]struct{}
	parents map[string]struct{} // proper parents of allowlisted names
}

func newAllowlist(names []string) *allowlist {
	a := &allowlist{names: map[string]struct{}{}, parents: map[string]struct{}{}}
	for _, n := range names {
		a.names[n] = struct{}{}
		for p := range properParents(n) {
			a.parents[p] = struct{}{}
		}
	}
	return a
}

// conflicts reports whether keeping r would block an allowlisted name.
func (a *allowlist) conflicts(r lists.Rule) bool {
	// r is an allowlisted name or lies below one.
	for p := range selfAndParents(r.Value) {
		if _, ok := a.names[p]; ok {
			return true
		}
	}
	// A suffix rule above an allowlisted name would cover it.
	if r.Kind == lists.Suffix {
		if _, ok := a.parents[r.Value]; ok {
			return true
		}
	}
	return false
}

func (s *ruleSet) removeAllowlisted(a *allowlist) []lists.Rule {
	var removed []lists.Rule
	for _, r := range s.rules() {
		if a.conflicts(r) {
			s.remove(r)
			removed = append(removed, r)
		}
	}
	return removed
}
