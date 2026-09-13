// SPDX-License-Identifier: GPL-3.0-only

// Package lists fetches upstream blocklists and turns their lines into
// normalized domain rules.
package lists

import (
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// Kind is how a rule matches, mirroring the geosite Domain.Type values that
// matter here.
type Kind uint8

const (
	// Suffix matches the domain itself and every subdomain (geosite "domain:").
	Suffix Kind = iota
	// Exact matches only the domain itself (geosite "full:").
	Exact
)

func (k Kind) String() string {
	if k == Exact {
		return "full"
	}
	return "domain"
}

// Rule is one normalized domain rule.
type Rule struct {
	Kind  Kind
	Value string
}

var (
	errEmpty   = errors.New("empty")
	errLength  = errors.New("longer than 253 octets")
	errLabel   = errors.New("empty or over-long label")
	errNoDot   = errors.New("not a multi-label name")
	errIP      = errors.New("IP literal")
	errChar    = errors.New("invalid character")
	errUnicode = errors.New("cannot convert to ASCII")
)

// idnaProfile converts internationalized names to their A-label form.
// It is deliberately lenient about underscores and hyphen placement:
// blocklists contain real-world names that DNS resolves but that strict
// hostname rules would reject, and dropping those would silently weaken the
// list.
var idnaProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(false))

// Normalize lower-cases a domain name, strips a trailing root dot, converts
// Unicode to ASCII and validates the result.
func Normalize(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" {
		return "", errEmpty
	}
	if !isASCII(s) {
		a, err := idnaProfile.ToASCII(s)
		if err != nil {
			return "", errUnicode
		}
		s = a
	}
	s = strings.ToLower(s)

	if len(s) > 253 {
		return "", errLength
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", errIP
	}
	labels := 0
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", errLabel
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", errChar
			}
		}
		labels++
	}
	if labels < 2 {
		return "", errNoDot
	}
	return s, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
