---
title: "Blind SSRF in crawl4ai's robots.txt prefetch"
date: 2026-09-26
categories: [Security Research]
tags: [crawl4ai, ssrf, robots.txt, python, security]
---


I found this while using Claude Code to look through recent security fixes in open-source projects.

I did not start by choosing `crawl4ai` as the target. Instead, I gave Claude Code a broader direction: look at projects that had recently fixed security issues and check whether similar code paths were still left behind.

That led to `crawl4ai`, where a recently fixed PDF SSRF became the useful clue.

The issue was in `RobotsParser.can_fetch()`. When it fetched `/robots.txt`, it created a separate `aiohttp` request that did not go through the egress controls used by the other fetch paths.

The issue was later published as [`GHSA-f77g-77vp-r96v`](https://github.com/unclecode/crawl4ai/security/advisories/GHSA-f77g-77vp-r96v) and fixed in `crawl4ai 0.9.4`.

The advisory rates it as CWE-918, Moderate, CVSS 5.3.

## Starting from the previous PDF SSRF fix

`crawl4ai 0.9.3` included several security fixes.

One of them fixed an SSRF in the PDF download path. A comment in the patch stood out to me. Its point was that the PDF path performed its own outbound requests, so it needed to be covered by the same destination policy used to protect the browser path.

In simpler terms:

```text
Crawl4AI's Chromium fetch path already goes through the egress protection
        ↓
the PDF downloader sends its own requests outside that path
        ↓
the same destination policy has to be attached there too
```

The interesting part was not the PDF code itself. It was the condition behind the bug.

**If there are other HTTP requests made outside Chromium, do they get the same protection?**

Looking for similar bugs after one has already been fixed is usually called **variant analysis**.

For this case, the process was basically:

```text
recently fixed vulnerability
        ↓
extract the condition that made it vulnerable
        ↓
look for other code paths with the same condition
        ↓
check whether the same protection exists there
```

Claude Code compared the recent security changes and other outbound fetches using that idea, and `RobotsParser.can_fetch()` came up as a candidate.

## The bug

Depending on its configuration, `crawl4ai` checks a site's `/robots.txt` before crawling the actual page.

For example, before crawling:

```text
https://example.com/page
```

it may first request:

```text
https://example.com/robots.txt
```

In `v0.9.3`, the relevant code looked like this:

```python
scheme = parsed.scheme or 'http'
robots_url = f"{scheme}://{domain}/robots.txt"

async with aiohttp.ClientSession() as session:
    async with session.get(robots_url, timeout=2, ssl=False) as response:
        if response.status == 200:
            rules = await response.text()
            self._cache_rules(domain, rules)
```

At first glance, it is just a normal HTTP request.

The problem was that the Docker server's SSRF protection was built around rules like these:

```text
reject destinations that resolve to non-global IPs
        ↓
re-check every redirect hop
        ↓
pin the validated IP and connect to that exact IP
```

Chromium, the PDF downloader, and the job webhook all had destination validation or pinning wired in, although they used different mechanisms.

The `aiohttp` request used for `robots.txt` did not have `resolve_and_pin`, the pinning proxy, or a peer-IP check.

Also, `session.get()` follows redirects by default.

So even if the original crawl URL passed validation, the same policy was not necessarily applied to the final destination reached by the automatically generated `/robots.txt` request.

## Is it reachable from external input?

A missing check in some helper function is not enough by itself. The path also has to be reachable from something the caller can control.

At the time, `check_robots_txt` was allowed in the untrusted `CrawlerRunConfig` request body.

That meant an API client could enable it, and `RobotsParser.can_fetch()` would run before the browser crawl.

The call site was roughly:

```python
if config and config.check_robots_txt:
    if not await self.robots_parser.can_fetch(
        url,
        self.browser_config.user_agent
    ):
        return CrawlResult(
            ...,
            status_code=403,
            error_message="Access denied by robots.txt",
            ...
        )
```

The easiest case to reason about was a redirect.

An attacker can provide a public host they control, then make its `/robots.txt` return something like:

```text
HTTP/1.1 302 Found
Location: http://127.0.0.1:XXXX/robots.txt
```

The flow becomes:

```text
public URL
        ↓
initial destination check passes
        ↓
crawl4ai requests /robots.txt
        ↓
302 → loopback / private / link-local
        ↓
aiohttp follows the redirect
        ↓
request is sent from the crawl4ai server
```

The first validation only saw the public host. The separate `robots.txt` request followed the later redirect on a path that was not using the same egress controls.

## DNS re-resolution

Redirects were not the only issue.

Suppose the hostname resolves to a public IP during the first validation:

```text
example.com → public IP
```

The `robots.txt` fetch performs another DNS lookup later.

That does not mean a normal DNS lookup will randomly turn a public IP into an internal one. The relevant case is when the attacker controls the DNS responses and can return different addresses at different times.

For example:

```text
initial validation:
example.com → public IP

robots.txt fetch:
example.com → internal IP
```

Changing the resolution result between the check and the later fetch gives a DNS rebinding-style bypass.

The other protected paths avoided this by pinning the IP that had already been validated and using that exact IP for the connection.

The `robots.txt` path created a separate `aiohttp` request and could resolve the hostname again.

The published advisory also describes both redirects and DNS re-resolution as bypass paths.

## PoC

I did not use a real internal service or a cloud metadata endpoint for the PoC.

Instead, I used `127.0.0.1` as a stand-in for an internal service.

Loopback is already a non-global destination that the egress policy is supposed to reject, so reaching it through this path is enough to show the missing protection.

The PoC copied the security-relevant part of `RobotsParser.can_fetch()`:

```python
async def fetch_robots(url: str):
    parsed = urlparse(url)
    domain = parsed.netloc
    scheme = parsed.scheme or "http"
    robots_url = f"{scheme}://{domain}/robots.txt"

    async with aiohttp.ClientSession() as session:
        async with session.get(
            robots_url,
            timeout=2,
            ssl=False
        ) as response:
            if response.status == 200:
                return await response.text()

    return None
```

One detail is worth being explicit about: the `direct` test below does **not** mean I bypassed the Docker API's initial validation by directly supplying a loopback URL.

It is a unit-level check of the fetch inside `RobotsParser.can_fetch()` itself. The point of that test was to confirm that this separate fetch had no non-global destination check of its own. Reachability from the real API was verified separately from the `check_robots_txt` allowlist and call flow.

The two tests were:

```text
1. whether the can_fetch-side request can reach loopback directly (direct)
2. whether it can reach loopback after one 302 redirect (redirect)
```

Both worked:

```text
[+] direct  : robots fetch hit the forbidden loopback host  -> ['/robots.txt']
[+] redirect: robots fetch followed 302 INTO the internal svc -> ['/robots.txt']
```

This was not an end-to-end exploit against a live external Docker deployment.

It was a small reproduction of the vulnerable fetch behavior, with the actual product reachability checked separately in the code.

## Impact

The response body from `robots.txt` is not returned directly to the caller.

It is parsed internally as robots rules.

Because of that, I did not treat this as a way to freely read internal HTTP responses. I reported it as **blind SSRF**.

The PoC directly reproduced the unguarded outbound request and the redirect into loopback. The timing and `403` side channels below are possible impacts derived from the request/response flow; I did not separately demonstrate them in that PoC.

The impact I could support was:

- the server can send requests to internal, private, and link-local destinations
- the `timeout=2` behavior can expose limited timing differences that may be useful for service discovery
- if an internal response is parsed as `robots.txt` and contains a matching `Disallow`, the crawl can change to `403 "Access denied by robots.txt"`, giving a narrow side channel
- TLS verification was disabled on this fetch because it used `ssl=False`

I did not find a way to return the internal response body to the caller, and I said that explicitly in the report.

There was also a practical limit on repeated probing. `RobotsParser` caches `robots.txt` rules by domain with a default seven-day TTL. Once a fresh cache entry exists, another request using the same domain may use the cached rules instead of issuing a new fetch.

That limits repeated probing through one cache key, but it does not remove the underlying SSRF path. A different attacker-controlled hostname is a different domain/cache entry and can cause another fetch.

The final GHSA also classifies the issue as blind SSRF.

## Patch

The issue was fixed in `crawl4ai 0.9.4`.

According to the project's Security page, the `robots.txt` fetch was moved behind the server's pinning egress proxy.

The proxy re-checks redirect destinations and connects using the IP that was already validated.

TLS verification for the `robots.txt` fetch was also restored.

A simplified before/after view is:

```text
Before

crawl URL validation
        ↓
separate robots.txt aiohttp request
        ↓
redirect / DNS re-resolution
        ↓
internal destination
```

```text
After

robots.txt request
        ↓
pinning egress proxy
        ↓
destination validation
        ↓
connect to the validated IP
```

The `v0.9.4` security notes also list other SSRF and trust-boundary fixes shipped in the same release.

## Timeline

- **2026-09-01**: privately reported by email because private vulnerability reporting was not enabled on the repository
- the issue was later moved into a GitHub Security Advisory and fixed
- **2026-09-23**: [`GHSA-f77g-77vp-r96v`](https://github.com/unclecode/crawl4ai/security/advisories/GHSA-f77g-77vp-r96v) published
- **2026-09-23**: `crawl4ai 0.9.4` released

## Notes

The part I found most interesting was not `robots.txt` itself, but the scope of an existing security fix.

The PDF path had already been fixed for the same basic reason: if a request is made outside Chromium, the same egress policy has to be wired into that path too.

A very similar condition was still present in the `robots.txt` prefetch.

For this one, starting from a recent security patch and looking for another path with the same condition worked well.

## Links

- [crawl4ai repository](https://github.com/unclecode/crawl4ai)
- [GHSA-f77g-77vp-r96v](https://github.com/unclecode/crawl4ai/security/advisories/GHSA-f77g-77vp-r96v)
- [crawl4ai Security](https://github.com/unclecode/crawl4ai/security)
- [crawl4ai CHANGELOG](https://github.com/unclecode/crawl4ai/blob/main/CHANGELOG.md)
- [crawl4ai v0.9.4](https://github.com/unclecode/crawl4ai/releases/tag/v0.9.4)
- [GHSA-q5rj-45vw-vp2g — previous PDF SSRF](https://github.com/unclecode/crawl4ai/security/advisories/GHSA-q5rj-45vw-vp2g)
