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

The source code and the generated files (`abuse.dat`, `abuse-medium.dat`,
`abuse-mini.dat`, the matching `.txt` lists, `manifest.json` and
`sha256sums.txt`) are all distributed under **GPL-3.0-only**.

## Third-party data

The generated files are adaptations of the following work. Each release's
`manifest.json` records the exact URL, retrieval time and SHA-256 of every
input used for that build.

### HaGeZi DNS Blocklists

- Lists used: Threat Intelligence Feeds in the `tif`, `tif.medium` and
  `tif.mini` sizes, wildcard format
- Source: <https://github.com/hagezi/dns-blocklists>
- License: GNU General Public License v3.0
  (<https://github.com/hagezi/dns-blocklists/blob/main/LICENSE>)
- Changes made: normalized (lower-cased, IDNA-converted, validated),
  deduplicated, subdomains covered by a parent rule folded away, suffix rules on
  explicit Public Suffix List entries removed, entries conflicting with
  `allowlist.txt` removed, converted to V2Ray geosite and text formats.

HaGeZi's terms state that the GPL-3.0 covers the lists as published and grants
no rights in the upstream data those lists are built from. This project uses
only the lists as HaGeZi publishes them.

### Public Suffix List

Suffix rules on public suffixes are detected with `golang.org/x/net/publicsuffix`,
which embeds the Public Suffix List (<https://publicsuffix.org/>), published
under the Mozilla Public License 2.0. The list is used for filtering; none of its
content is redistributed in the generated files.

## Corresponding source

For the generated data, the preferred form for making modifications is the
plain-text lists published with every GitHub release (`abuse.txt`,
`abuse-medium.txt`, `abuse-mini.txt`) together with this repository's source
code at the commit recorded as `version` in `manifest.json`.

## Trademarks and affiliation

This project is not affiliated with, endorsed by, or sponsored by HaGeZi,
Project X (Xray) or Project V (V2Ray). Their names are used only to identify the
data source and the file format.
