// SPDX-License-Identifier: GPL-3.0-only

package build

import "github.com/opbace/abuse-dat-gen/internal/lists"

// Source is an upstream list.
type Source struct {
	Name       string
	URL        string
	Format     lists.Format
	Homepage   string
	License    string // SPDX identifier
	LicenseURL string
	// Attribution is copied verbatim into the manifest, the text outputs and
	// the release notes.
	Attribution string
	// MinRules fails the build when a download parses to fewer rules. The
	// floors sit well below today's sizes; they exist to catch an empty or
	// truncated download, not ordinary churn.
	MinRules int
}

// Category is one output: <File>.dat holding a single geosite category named
// Code, plus <File>.txt with the same rules as text.
type Category struct {
	File        string
	Code        string
	Description string
	Sources     []string
	MinRules    int
}

const hagezi = "HaGeZi DNS Blocklists (https://github.com/hagezi/dns-blocklists), GPL-3.0."

// DefaultSources are the lists fetched on every build: the three sizes of
// HaGeZi's Threat Intelligence Feeds. Each smaller size is a subset of the
// next larger one.
var DefaultSources = []Source{
	{
		Name:        "hagezi-tif",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.txt",
		Format:      lists.Wildcard,
		Homepage:    "https://github.com/hagezi/dns-blocklists",
		License:     "GPL-3.0",
		LicenseURL:  "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE",
		Attribution: "Threat Intelligence Feeds (full) from " + hagezi,
		MinRules:    1_000_000,
	},
	{
		Name:        "hagezi-tif-medium",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium.txt",
		Format:      lists.Wildcard,
		Homepage:    "https://github.com/hagezi/dns-blocklists",
		License:     "GPL-3.0",
		LicenseURL:  "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE",
		Attribution: "Threat Intelligence Feeds (medium) from " + hagezi,
		MinRules:    200_000,
	},
	{
		Name:        "hagezi-tif-mini",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini.txt",
		Format:      lists.Wildcard,
		Homepage:    "https://github.com/hagezi/dns-blocklists",
		License:     "GPL-3.0",
		LicenseURL:  "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE",
		Attribution: "Threat Intelligence Feeds (mini) from " + hagezi,
		MinRules:    50_000,
	},
}

// DefaultCategories are the published files. All of them use the code ABUSE,
// so switching sizes only changes the file name in an Xray rule
// (ext:abuse-medium.dat:abuse).
var DefaultCategories = []Category{
	{
		File:        "abuse",
		Code:        "ABUSE",
		Description: "HaGeZi Threat Intelligence Feeds, full size.",
		Sources:     []string{"hagezi-tif"},
		MinRules:    1_000_000,
	},
	{
		File:        "abuse-medium",
		Code:        "ABUSE",
		Description: "HaGeZi Threat Intelligence Feeds, medium size.",
		Sources:     []string{"hagezi-tif-medium"},
		MinRules:    200_000,
	},
	{
		File:        "abuse-mini",
		Code:        "ABUSE",
		Description: "HaGeZi Threat Intelligence Feeds, mini size.",
		Sources:     []string{"hagezi-tif-mini"},
		MinRules:    50_000,
	},
}
