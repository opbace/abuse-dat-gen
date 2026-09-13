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

// Category is one code in the output file, built from the union of its
// sources.
type Category struct {
	Code        string
	Description string
	Sources     []string
	MinRules    int
}

// DatFile is the name of the published geosite file.
const DatFile = "abuse.dat"

const (
	hagezi    = "HaGeZi DNS Blocklists (https://github.com/hagezi/dns-blocklists), GPL-3.0."
	cyberhost = "CyberHost.uk Malware Blocklist (https://cyberhost.uk/malware-blocklist), " +
		"licensed under CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/). " +
		"Changes: normalized, deduplicated, merged with other lists and converted to " +
		"V2Ray geosite format; the adaptation is distributed under GPL-3.0, a " +
		"BY-SA-compatible license."
)

// DefaultSources are the lists fetched on every build.
var DefaultSources = []Source{
	{
		Name:        "hagezi-tif",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.txt",
		Format:      lists.Wildcard,
		Homepage:    "https://github.com/hagezi/dns-blocklists",
		License:     "GPL-3.0",
		LicenseURL:  "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE",
		Attribution: "Threat Intelligence Feeds from " + hagezi,
		MinRules:    1_000_000,
	},
	{
		Name:        "cyberhost-malware",
		URL:         "https://lists.cyberhost.uk/malware.txt",
		Format:      lists.Domains,
		Homepage:    "https://cyberhost.uk/malware-blocklist",
		License:     "CC-BY-SA-4.0",
		LicenseURL:  "https://creativecommons.org/licenses/by-sa/4.0/",
		Attribution: cyberhost,
		MinRules:    20_000,
	},
}

// DefaultCategories are the codes written to abuse.dat. HaGeZi and CyberHost
// are combined because they overlap little: when this was set up only about
// 12% of CyberHost's entries were also in the TIF list.
var DefaultCategories = []Category{
	{
		Code:        "ABUSE",
		Description: "HaGeZi Threat Intelligence Feeds + CyberHost malware blocklist.",
		Sources:     []string{"hagezi-tif", "cyberhost-malware"},
		MinRules:    1_000_000,
	},
}
