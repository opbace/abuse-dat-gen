// SPDX-License-Identifier: GPL-3.0-only

package lists

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Format names an upstream list syntax.
type Format string

const (
	// Wildcard is one "*.example.com" per line, meaning the domain and all of
	// its subdomains. This is HaGeZi's "wildcard" flavour.
	Wildcard Format = "wildcard"
	// Domains is one bare "example.com" per line, meaning exactly that name.
	// CyberHost documents its list entries as exact matches.
	Domains Format = "domains"
)

// Stats describes how a list parsed. A sudden rise in Invalid is the signal
// that upstream changed its format, so the build gates on it.
type Stats struct {
	Lines          int      `json:"lines"`
	Rules          int      `json:"rules"`
	Invalid        int      `json:"invalid"`
	InvalidSamples []string `json:"invalid_samples,omitempty"`
}

const maxInvalidSamples = 10

// Parse reads a list in the given format. Comment lines start with '#' or
// '!'; blank lines are skipped. Lines that do not fit the format are counted
// as invalid rather than guessed at.
func Parse(r io.Reader, format Format) ([]Rule, Stats, error) {
	var (
		rules []Rule
		st    Stats
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		st.Lines++

		rule, ok := parseLine(line, format)
		if !ok {
			st.Invalid++
			if len(st.InvalidSamples) < maxInvalidSamples {
				st.InvalidSamples = append(st.InvalidSamples, line)
			}
			continue
		}
		rules = append(rules, rule)
	}
	if err := sc.Err(); err != nil {
		return nil, st, fmt.Errorf("read %s list: %w", format, err)
	}
	st.Rules = len(rules)
	return rules, st, nil
}

func parseLine(line string, format Format) (Rule, bool) {
	switch format {
	case Wildcard:
		name, ok := strings.CutPrefix(line, "*.")
		if !ok {
			return Rule{}, false
		}
		v, err := Normalize(name)
		if err != nil {
			return Rule{}, false
		}
		return Rule{Kind: Suffix, Value: v}, true
	case Domains:
		if strings.ContainsAny(line, " \t*/") {
			return Rule{}, false
		}
		v, err := Normalize(line)
		if err != nil {
			return Rule{}, false
		}
		return Rule{Kind: Exact, Value: v}, true
	default:
		return Rule{}, false
	}
}
