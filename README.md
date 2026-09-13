# abuse-dat-gen

[简体中文](README.zh-CN.md)

Daily-built **V2Ray / Xray geosite file of malware, phishing and other abuse
domains**, generated from public blocklists:

- [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists) (GPL-3.0)
- [CyberHost.uk Malware Blocklist](https://cyberhost.uk/malware-blocklist) (CC BY-SA 4.0)

It is meant for proxy and VPN servers that want to stop clients — including
clients on malware-infected devices — from reaching command-and-control and
phishing infrastructure through the server.

> ⚠️ Read the [disclaimer](DISCLAIMER.md) before deploying. Blocklists produce
> false positives, and this project only converts upstream data.

## Download

Repository: <https://github.com/opbace/abuse-dat-gen>

Newest build, served from the `release` branch:

| File | URL |
|---|---|
| `abuse.dat` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse.dat> |
| `sha256sums.txt` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/sha256sums.txt> |
| `manifest.json` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/manifest.json> |

The branch also carries `LICENSE`, `LICENSE-CC-BY-SA-4.0.txt`, `NOTICE.md` and
`DISCLAIMER.md`. It holds a single commit that is replaced on every build, so
older builds are not kept there.

Download and verify:

```sh
curl -fLO https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse.dat
curl -fLO https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/sha256sums.txt
sha256sum --check --ignore-missing sha256sums.txt
```

`manifest.json` lists every input (URL, retrieval time, SHA-256, license), the
rule counts, and every rule removed by filtering.

[GitHub Releases](https://github.com/opbace/abuse-dat-gen/releases) keep the
last 14 builds as archives. Each also includes `abuse.txt`, the same rules as
text with one `domain:` or `full:` rule per line.

Mirror the file on your own infrastructure rather than having many servers pull
from GitHub directly.

## Category

`abuse.dat` contains one category, `abuse`: the union of HaGeZi's Threat
Intelligence Feeds and CyberHost's malware blocklist, about 2.49 million rules.

Loaded through Xray v26.3.27's own config loader and domain matcher on
2026-09-13, it retained about **219 MiB** of Go heap after garbage collection;
peak memory while loading is higher. Each release workflow run repeats the
measurement and shows it in the job summary. Check it against your servers'
memory before deploying.

## Use with Xray

Put `abuse.dat` in Xray's asset directory (next to `geosite.dat`, or the
directory set by `XRAY_LOCATION_ASSET`) and route matching traffic to a
blackhole:

```json
{
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": ["ext:abuse.dat:abuse"],
        "outboundTag": "block"
      }
    ]
  }
}
```

Domain rules only match when Xray knows the destination domain. For clients that
connect to IP addresses, enable `sniffing` with `destOverride` (`http`, `tls`,
`quic`) on the inbound.

## How a build works

1. **Fetch** each list (with retries). A non-200 response fails the build.
2. **Parse** strictly. HaGeZi's wildcard entries `*.example.com` become
   `domain:` rules (domain and subdomains). CyberHost's entries become `full:`
   rules (exact name), because CyberHost documents them as exact matches.
   Names are lower-cased, IDNA-converted and validated.
3. **Filter**, recording everything removed in `manifest.json`:
   - **Shared public suffixes.** A `domain:` rule on a name the
     [Public Suffix List](https://publicsuffix.org/) lists explicitly —
     `github.io`, `co.uk`, dynamic-DNS providers such as `camdvr.org` — would
     block every unrelated customer of that namespace, so it is removed.
     Individual sites under those suffixes stay listed. Names that are public
     suffixes only through a wildcard PSL entry (for example one tunnel under
     `*.localto.net`) are single tenants and are kept, as are all `full:` rules.
   - **Allowlist.** Rules that would block a name in
     [`allowlist.txt`](allowlist.txt), or anything below it, are removed.
4. **Fold** rules already covered by a broader `domain:` rule, and sort, so
   output is reproducible.
5. **Check** before publishing. The build fails, and the previous build stays
   published, if any of these holds:
   - a list or category falls below its minimum size;
   - more than 1% of a list's lines are unparseable (usually an upstream
     format change);
   - a category shrinks by more than 25% since the previous release;
   - anything in the allowlist is still matched;
   - `abuse.dat` does not decode back to exactly what was encoded;
   - Xray itself cannot load a category, or a category blocks a well-known
     domain such as `google.com` (checked in [`compat/`](compat)).

## Development

```sh
git clone https://github.com/opbace/abuse-dat-gen.git
cd abuse-dat-gen
go test ./...                                  # generator
(cd compat && go test ./...)                   # Xray compatibility, golden file
go run ./cmd/abuse-dat-gen -out dist           # full build from live sources
(cd compat && ABUSE_DAT=../dist/abuse.dat go test -v -run TestRelease ./...)
```

The generator does not depend on Xray. It writes the geosite protobuf directly,
because Xray has moved the generated types between packages across releases
while the wire format stayed the same. `compat/` is a separate module that
checks output against a tagged Xray release.

If you change the encoder on purpose, regenerate the golden file with
`go test ./internal/geosite -update` and rerun the compat tests.

To add a source or category, edit
[`internal/build/config.go`](internal/build/config.go). Check the source's
license first: it must allow redistribution of adaptations under GPL-3.0.

### Maintainer notes

- GitHub disables scheduled workflows in public repositories after 60 days
  without repository activity. Watch for the notice email, or the daily builds
  will stop.
- The release workflow force-pushes the `release` branch and deletes GitHub
  releases older than the newest 14 (`KEEP_RELEASES`). `abuse.dat` is larger
  than GitHub's recommended 50 MB file size, so the push logs a warning; the
  hard limit is 100 MB.

## License

GPL-3.0-only. See [`LICENSE`](LICENSE), and [`NOTICE.md`](NOTICE.md) for
third-party attribution and how CyberHost's CC BY-SA 4.0 data can be
distributed under the GPL.
