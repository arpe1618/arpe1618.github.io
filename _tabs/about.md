---
title: Research
icon: fas fa-flask
order: 2
---

Computer Science Freshman / Security Research

This blog contains vulnerability research, technical notes, and research logs.

## Responsible Disclosure

### VSeeFace / OpenSeeFace — Unsafe BinaryFormatter Deserialization

Reported unsafe `BinaryFormatter` deserialization in expression model loading. Fixed in VSeeFace `1.13.38c5` and OpenSeeFace `1.20.5`.

[Write-up](https://arpe1618.github.io/posts/openseeface-binaryformatter-deserialization/) · [OpenSeeFace patch](https://github.com/emilianavt/OpenSeeFace/commit/a8b4c9979b9214434aa5f1c2e063d9ebd0d49d43)

### Little LUMI Model (꼬미) — Workshop Subscription Plugin Code Execution + 2 Additional Issues

Reported three security issues, including plugin code execution triggered by subscribing to Workshop content. Fixed in `1.3.0`.

[Patch notes — v1.3.0](https://store.steampowered.com/news/app/5075020/view/689768324345626714?l=english)

### Netis EAP930 — Undocumented Debug Backdoor (CVE-2026-112360)

Reported an undocumented debug backdoor in the Netis EAP930 access point firmware. Published as `CVE-2026-112360` 

[CVE Record](https://www.cve.org/CVERecord?id=CVE-2026-112360) 

## Open Source Contributions

### Crawl4AI — robots.txt Blind SSRF / Egress Bypass

Reported a blind SSRF in `robots.txt` fetching that bypassed Docker egress restrictions. Fixed in `0.9.4` and published as `GHSA-f77g-77vp-r96v`.

[Security advisory](https://github.com/unclecode/crawl4ai/security/advisories/GHSA-f77g-77vp-r96v)

### Crawl4AI — Cache Freshness Blind SSRF / Egress Bypass

Reported a blind SSRF in the cache freshness check that bypassed the Docker egress proxy. Fixed in `0.9.5` and published as `GHSA-w4xc-px5p-c32w`.

[Security advisory](https://github.com/unclecode/crawl4ai/security/advisories/GHSA-w4xc-px5p-c32w)

### watermarks-remover — ReDoS in SVG / ODT Metadata Processing

Reported a ReDoS affecting SVG and ODT metadata stripping. Fixed upstream by replacing the affected regex-based paths with linear-time processing. Fixed in 'v0.6.0'.

`GHSA-7vpp-96qp-j9wh`

[Fix PR #147](https://github.com/guillaumemeyer/watermarks-remover/pull/147)

### OpenClaw — Attachment Filename Handling

Contributed a fix for attachment filename handling when source paths ended in `.` or `..`. Merged as PR `#135135` and released in `v2026.9.1`.

[PR #135135](https://github.com/openclaw/openclaw/pull/135135)

## Links

- [GitHub](https://github.com/arpe1618)
- [X](https://x.com/arpe1618)

## Personal 

[Vtuber-Related](https://docs.google.com/document/d/1UxyZq_L88SX6UWKHLOzcZJgBrb7TZpNgYPHm6CfxLfE/edit?tab=t.0)

