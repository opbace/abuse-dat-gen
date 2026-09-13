# abuse-dat-gen

[简体中文](README.zh-CN.md)

Daily-built **V2Ray / Xray geosite files of malware, phishing and other abuse
domains**, generated from
[HaGeZi's Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists)
(GPL-3.0) in three sizes.

It is meant for proxy and VPN servers that want to stop clients — including
clients on malware-infected devices — from reaching command-and-control and
phishing infrastructure through the server.

> ⚠️ Read the [disclaimer](DISCLAIMER.md) before deploying. Blocklists produce
> false positives, and this project only converts upstream data.

## Files

Every file contains one category, `abuse`, so switching sizes only changes the
file name in your routing rule.

| File | Built from | Rules | Size | Xray rule |
|---|---|---:|---:|---|
| `abuse.dat` | HaGeZi TIF (full) | ~2,432,000 | ~53 MiB | `ext:abuse.dat:abuse` |
| `abuse-medium.dat` | HaGeZi TIF (medium) | ~686,000 | ~15 MiB | `ext:abuse-medium.dat:abuse` |
| `abuse-mini.dat` | HaGeZi TIF (mini) | ~177,000 | ~4 MiB | `ext:abuse-mini.dat:abuse` |

Each smaller list is a subset of the next larger one. HaGeZi describes medium as
including "only the most important feeds" and mini as a size-optimized version
of medium.

### Memory

Measured on 2026-09-13 (macOS arm64). The files load into far more memory than
their size, so check this against your servers before choosing:

| File | Xray process RSS, peak while loading | Xray process RSS, after ~2.5 min | Go heap retained after GC |
|---|---:|---:|---:|
| `abuse.dat` | ~1,655 MiB | ~1,560 MiB | ~217 MiB |
| `abuse-medium.dat` | ~472 MiB | ~472 MiB | ~58 MiB |
| `abuse-mini.dat` | ~147 MiB | ~61 MiB | ~15 MiB |
| no geosite file | ~30 MiB | ~30 MiB | — |

Process RSS was measured with Xray 26.7.28 routing `ext:<file>:abuse` to a
blackhole. The Go heap column comes from loading the same files through Xray
v26.3.27's config loader and domain matcher; each release workflow run repeats
that measurement in its job summary. How quickly Go hands freed memory back to
the OS varies: in an earlier run the full file's RSS fell to ~853 MiB after two
minutes, in this one it stayed near its peak. Expect different absolute numbers
on Linux, but plan for the peak.

## Download

Repository: <https://github.com/opbace/abuse-dat-gen>

Newest build, served from the `release` branch:

| File | URL |
|---|---|
| `abuse.dat` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse.dat> |
| `abuse-medium.dat` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse-medium.dat> |
| `abuse-mini.dat` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse-mini.dat> |
| `sha256sums.txt` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/sha256sums.txt> |
| `manifest.json` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/manifest.json> |

The branch also carries `LICENSE`, `NOTICE.md` and `DISCLAIMER.md`. It holds a
single commit that is replaced on every build, so older builds are not kept
there.

Download and verify, for example the medium file:

```sh
curl -fLO https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse-medium.dat
curl -fLO https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/sha256sums.txt
sha256sum --check --ignore-missing sha256sums.txt
```

`manifest.json` lists every input (URL, retrieval time, SHA-256, license), the
rule counts per file, and every rule removed by filtering.

[GitHub Releases](https://github.com/opbace/abuse-dat-gen/releases) keep the
last 14 builds as archives. Each also includes `abuse.txt`, `abuse-medium.txt`
and `abuse-mini.txt`, the same rules as text with one rule per line.

Mirror the files on your own infrastructure rather than having many servers
pull from GitHub directly.

## Use with Xray

Put the file in Xray's asset directory (next to `geosite.dat`, or the directory
set by `XRAY_LOCATION_ASSET`) and route matching traffic to a blackhole:

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
        "domain": ["ext:abuse-medium.dat:abuse"],
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
   `domain:` rules, matching the domain and its subdomains. Names are
   lower-cased, IDNA-converted and validated.
3. **Filter**, recording everything removed in `manifest.json`:
   - **Shared public suffixes.** A `domain:` rule on a name the
     [Public Suffix List](https://publicsuffix.org/) lists explicitly —
     `github.io`, `co.uk`, dynamic-DNS providers such as `camdvr.org` — would
     block every unrelated customer of that namespace, so it is removed.
     Individual sites under those suffixes stay listed. Names that are public
     suffixes only through a wildcard PSL entry (for example one tunnel under
     `*.localto.net`) are single tenants and are kept.
   - **Allowlist.** Rules that would block a name in
     [`allowlist.txt`](allowlist.txt), or anything below it, are removed.
4. **Fold** rules already covered by a broader rule, and sort, so output is
   reproducible.
5. **Check** before publishing. The build fails, and the previous build stays
   published, if any of these holds for any file:
   - a list or file falls below its minimum size;
   - more than 1% of a list's lines are unparseable (usually an upstream
     format change);
   - a file's rule count shrinks by more than 25% since the previous release;
   - anything in the allowlist is still matched;
   - a `.dat` file does not decode back to exactly what was encoded;
   - Xray itself cannot load a file, or a file blocks a well-known domain such
     as `google.com` (checked in [`compat/`](compat)).

## Development

```sh
git clone https://github.com/opbace/abuse-dat-gen.git
cd abuse-dat-gen
go test ./...                                  # generator
(cd compat && go test ./...)                   # Xray compatibility, golden file
go run ./cmd/abuse-dat-gen -out dist           # full build from live sources
(cd compat && ABUSE_DAT_DIR=../dist go test -v -run TestRelease ./...)
```

The generator does not depend on Xray. It writes the geosite protobuf directly,
because Xray has moved the generated types between packages across releases
while the wire format stayed the same. `compat/` is a separate module that
checks output against a tagged Xray release.

If you change the encoder on purpose, regenerate the golden file with
`go test ./internal/geosite -update` and rerun the compat tests.

To add a source or output file, edit
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
third-party attribution.
