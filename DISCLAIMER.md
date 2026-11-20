# Disclaimer

**Read this before using the files from this project.**

## No warranty

The software and the generated files are provided "as is", without warranty of
any kind, as set out in sections 15 to 17 of the GNU General Public License
v3.0 ([`LICENSE`](LICENSE)). You use them entirely at your own risk.

## What these files are, and are not

- They are a **mechanical conversion** of third-party blocklists. This project
  does not research, verify or curate individual domains. An entry appearing
  here is not a finding by this project that a domain is malicious.
- They are **not a complete security product**. They will miss threats, and
  entries go stale: a domain may be listed after it has changed hands or been
  cleaned up.
- **False positives will happen.** Blocking a listed domain can break
  legitimate websites, apps, updates, payments or messaging for your users.
  Test before deploying, and keep a way to override.
- Builds are automated. A build is published only if it passes the checks
  described in the README, but those checks cannot catch every upstream
  error.

## Availability

There is no guarantee that builds will be published on any schedule, or at
all. Upstream lists may change format, change license, rate-limit, or
disappear; any of these can stop builds. Releases may be removed. Do not make
your service depend on fetching files from this repository in real time;
mirror what you use.

## False positives and removals

This project republishes upstream data. To get a domain removed, report it to
HaGeZi — the change will flow through on the next build:
<https://github.com/hagezi/dns-blocklists/issues>

`manifest.json` lists the sources each build uses. Additions to
`allowlist.txt` are accepted only for domains operated by the organisation
itself, never for services that host third-party content.

## Your responsibilities

If you use these files to filter other people's traffic — for example on a VPN,
proxy, ISP or corporate network — you are responsible for complying with the
laws, contracts and privacy commitments that apply to you, including telling
your users that filtering takes place where that is required. Nothing in this
project is legal advice.

## No affiliation

This project is not affiliated with, endorsed by, or sponsored by HaGeZi,
Project X (Xray) or Project V (V2Ray).
