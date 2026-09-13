# Notices

## This project

Copyright (C) 2026 abuse-dat-gen contributors

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, version 3.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details. The
full text is in [`LICENSE`](LICENSE).

The source code and the generated files (`abuse.dat`, `abuse.txt`,
`manifest.json` and `sha256sums.txt`) are all distributed under
**GPL-3.0-only**.

## Third-party data

The generated files are adaptations of the following works. Each release's
`manifest.json` records the exact URL, retrieval time and SHA-256 of every
input used for that build.

### HaGeZi DNS Blocklists

- List used: Threat Intelligence Feeds (`tif`), wildcard format
- Source: <https://github.com/hagezi/dns-blocklists>
- License: GNU General Public License v3.0
  (<https://github.com/hagezi/dns-blocklists/blob/main/LICENSE>)
- Changes made: normalized (lower-cased, IDNA-converted, validated),
  deduplicated, subdomains covered by a parent rule folded away, suffix rules on
  explicit Public Suffix List entries removed, entries conflicting with
  `allowlist.txt` removed, merged with the CyberHost list, converted to V2Ray
  geosite and text formats.

HaGeZi's terms state that the GPL-3.0 covers the lists as published and grants
no rights in the upstream data those lists are built from. This project uses
only the lists as HaGeZi publishes them.

### CyberHost.uk Malware Blocklist

- Source: <https://cyberhost.uk/malware-blocklist>
  (list: <https://lists.cyberhost.uk/malware.txt>)
- License: Creative Commons Attribution-ShareAlike 4.0 International
  (<https://creativecommons.org/licenses/by-sa/4.0/>). The legal code is in
  [`LICENSES/CC-BY-SA-4.0.txt`](LICENSES/CC-BY-SA-4.0.txt).
- Changes made: normalized, deduplicated, entries conflicting with
  `allowlist.txt` removed, merged with HaGeZi's lists, converted to V2Ray
  geosite and text formats. Entries are kept as exact-match (`full:`) rules,
  as CyberHost documents them.

Creative Commons declared the GNU GPL version 3 a BY-SA-Compatible License for
BY-SA 4.0 on 8 October 2015
(<https://creativecommons.org/share-your-work/licensing-considerations/compatible-licenses/>).
This project relies on that one-way compatibility to distribute the adapted
CyberHost data under GPL-3.0. The attribution above is retained as that
license requires.

### Public Suffix List

Suffix rules on public suffixes are detected with `golang.org/x/net/publicsuffix`,
which embeds the Public Suffix List (<https://publicsuffix.org/>), published
under the Mozilla Public License 2.0. The list is used for filtering; none of its
content is redistributed in the generated files.

## Corresponding source

For the generated data, the preferred form for making modifications is the
plain-text list published with every release (`abuse.txt`) together with this
repository's source code at the commit recorded as `version` in `manifest.json`.

## Trademarks and affiliation

This project is not affiliated with, endorsed by, or sponsored by HaGeZi,
CyberHost.uk, Project X (Xray) or Project V (V2Ray). Their names are used only
to identify the data sources and the file format.
