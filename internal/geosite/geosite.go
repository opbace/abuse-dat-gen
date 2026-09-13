// SPDX-License-Identifier: GPL-3.0-only

// Package geosite reads and writes V2Ray/Xray geosite .dat files.
//
// The file is a serialized GeoSiteList protobuf:
//
//	message Domain      { Type type = 1; string value = 2; }   // Domain=2, Full=3
//	message GeoSite     { string code = 1; repeated Domain domain = 2; }
//	message GeoSiteList { repeated GeoSite entry = 1; }
//
// It is encoded with protowire instead of Xray's generated types on purpose:
// Xray has moved these types between packages across releases
// (app/router, later common/geodata) while the wire format stayed the same,
// so depending on the generated code would tie this tool to one Xray layout
// for no benefit. Compatibility with Xray's real loader is checked by the
// separate module in compat/.
package geosite

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/opbace/abuse-dat-gen/internal/lists"
)

// Wire values of Domain.Type.
const (
	typeDomain = 2 // lists.Suffix
	typeFull   = 3 // lists.Exact
)

// Site is one category in the file.
type Site struct {
	Code  string
	Rules []lists.Rule
}

// MaxCodeLen is the longest code Xray can find. Xray locates a category by
// scanning each entry's first bytes for `0x0a <len> <code>` with <len> read
// as a single byte, so a code of 128 bytes or more (a two-byte varint) is
// silently never found.
const MaxCodeLen = 127

// ValidateCode reports whether code is usable. Xray upper-cases the code in
// a rule before comparing raw bytes, so codes must be stored upper-case.
func ValidateCode(code string) error {
	if code == "" || len(code) > MaxCodeLen {
		return fmt.Errorf("code %q: length must be 1..%d", code, MaxCodeLen)
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return fmt.Errorf("code %q: only A-Z, 0-9, '-' and '_' are allowed", code)
		}
	}
	return nil
}

// Write encodes sites to w in order.
//
// The code field must be the first field of each GeoSite; Xray's lookup
// depends on it (see MaxCodeLen). Rules are written in the order given, so
// callers that want reproducible output must sort them first.
func Write(w io.Writer, sites []Site) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	var buf []byte
	for _, s := range sites {
		if err := ValidateCode(s.Code); err != nil {
			return err
		}
		body := protowire.SizeTag(1) + protowire.SizeBytes(len(s.Code))
		for _, r := range s.Rules {
			body += protowire.SizeTag(2) + protowire.SizeBytes(domainSize(r))
		}

		buf = protowire.AppendTag(buf[:0], 1, protowire.BytesType)
		buf = protowire.AppendVarint(buf, uint64(body))
		buf = protowire.AppendTag(buf, 1, protowire.BytesType)
		buf = protowire.AppendString(buf, s.Code)
		if _, err := bw.Write(buf); err != nil {
			return err
		}
		for _, r := range s.Rules {
			buf = protowire.AppendTag(buf[:0], 2, protowire.BytesType)
			buf = protowire.AppendVarint(buf, uint64(domainSize(r)))
			buf = protowire.AppendTag(buf, 1, protowire.VarintType)
			buf = protowire.AppendVarint(buf, wireType(r.Kind))
			buf = protowire.AppendTag(buf, 2, protowire.BytesType)
			buf = protowire.AppendString(buf, r.Value)
			if _, err := bw.Write(buf); err != nil {
				return err
			}
		}
	}
	return bw.Flush()
}

func wireType(k lists.Kind) uint64 {
	if k == lists.Exact {
		return typeFull
	}
	return typeDomain
}

func domainSize(r lists.Rule) int {
	return protowire.SizeTag(1) + protowire.SizeVarint(wireType(r.Kind)) +
		protowire.SizeTag(2) + protowire.SizeBytes(len(r.Value))
}

var errMalformed = errors.New("malformed geosite data")

// Read decodes a whole file. It accepts only the Domain and Full types this
// tool writes, so reading back our own output is a strict round-trip check.
func Read(data []byte) ([]Site, error) {
	var sites []Site
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 || num != 1 || typ != protowire.BytesType {
			return nil, fmt.Errorf("%w: list entry tag", errMalformed)
		}
		data = data[n:]
		entry, n := protowire.ConsumeBytes(data)
		if n < 0 {
			return nil, fmt.Errorf("%w: list entry length", errMalformed)
		}
		data = data[n:]
		site, err := readSite(entry)
		if err != nil {
			return nil, err
		}
		sites = append(sites, site)
	}
	return sites, nil
}

func readSite(b []byte) (Site, error) {
	var s Site
	first := true
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 || typ != protowire.BytesType {
			return s, fmt.Errorf("%w: site field", errMalformed)
		}
		b = b[n:]
		v, n := protowire.ConsumeBytes(b)
		if n < 0 {
			return s, fmt.Errorf("%w: site field length", errMalformed)
		}
		b = b[n:]
		switch {
		case num == 1 && first:
			s.Code = string(v)
		case num == 2 && !first:
			r, err := readDomain(v)
			if err != nil {
				return s, fmt.Errorf("site %s: %w", s.Code, err)
			}
			s.Rules = append(s.Rules, r)
		default:
			return s, fmt.Errorf("%w: unexpected field %d (code must come first)", errMalformed, num)
		}
		first = false
	}
	return s, nil
}

func readDomain(b []byte) (lists.Rule, error) {
	var (
		r       lists.Rule
		typ     uint64
		haveVal bool
	)
	for len(b) > 0 {
		num, wt, n := protowire.ConsumeTag(b)
		if n < 0 {
			return r, errMalformed
		}
		b = b[n:]
		switch {
		case num == 1 && wt == protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return r, errMalformed
			}
			typ, b = v, b[n:]
		case num == 2 && wt == protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return r, errMalformed
			}
			r.Value, haveVal, b = string(v), true, b[n:]
		default:
			return r, fmt.Errorf("%w: unexpected domain field %d", errMalformed, num)
		}
	}
	switch typ {
	case typeDomain:
		r.Kind = lists.Suffix
	case typeFull:
		r.Kind = lists.Exact
	default:
		return r, fmt.Errorf("%w: unsupported domain type %d", errMalformed, typ)
	}
	if !haveVal {
		return r, fmt.Errorf("%w: domain without value", errMalformed)
	}
	return r, nil
}

// Equal reports whether two decoded files have the same categories and rules
// in the same order.
func Equal(a, b []Site) bool {
	return slices.EqualFunc(a, b, func(x, y Site) bool {
		return x.Code == y.Code && slices.Equal(x.Rules, y.Rules)
	})
}
