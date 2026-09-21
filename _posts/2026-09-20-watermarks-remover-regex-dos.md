---
title: "How a 1.4 KB ODT file turned into a 99-second DoS"
date: 2026-09-20
categories: [Security Research]
tags: [security, dos, regex, python, watermarks-remover]
---

I found this while using Claude to analyze the [`watermarks-remover`](https://github.com/guillaumemeyer/watermarks-remover) repository.

At first I thought it was just a normal ReDoS-looking issue. After I started changing the input size and timing it, though, the behavior was pretty consistent: doubling the input made the runtime almost four times longer.

The problem was in the regexes used by `clean_svg()` and `clean_odt()`.

The ODT case was the one I focused on because compression made the result a lot worse than I expected. A request that was only about 1.4 KB on the wire expanded into a 512 KB `meta.xml`, and processing that file took about 99 seconds in my test.

## The vulnerable code

The affected code was in `service/scripts/container_meta.py`.

The SVG cleaner used this:

```python
new, n = re.subn(
    r"<metadata\b[^>]*>.*?</metadata\s*>",
    "",
    text,
    flags=re.I | re.DOTALL,
)
```

The ODT cleaner had almost the same pattern:

```python
new, n = re.subn(
    r"<meta:generator\b[^>]*>.*?</meta:generator\s*>",
    "",
    text,
    flags=re.I | re.DOTALL,
)
```

With normal input there is nothing unusual about this.

```xml
<meta:generator>
something
</meta:generator>
```

The problem starts when the opening tags are there, but the closing tag never appears.

## Why it becomes O(n²)

For example, imagine a `meta.xml` that looks like this:

```xml
<meta:generator>
<meta:generator>
<meta:generator>
<meta:generator>
...
```

There is no `</meta:generator>` anywhere in the string.

Starting from the first opening tag, the regex looks forward for the closing tag. It reaches the end and fails.

Then it tries again from the next opening tag.

Then again from the next one.

```text
first opening tag   ----------------------> EOF
second opening tag    --------------------> EOF
third opening tag       ------------------> EOF
fourth opening tag        ----------------> EOF
...
```

So the same part of the input gets scanned over and over again. If the number of opening tags grows with the input size, the total work ends up being quadratic.

This is why I would not describe it as exponential catastrophic backtracking. The measurements also matched the quadratic case pretty closely: every time I doubled the decompressed input, the runtime was around four times longer.

There was another reason this input looked familiar to me.

Earlier this semester, during a fuzzing study in my university security club, I reproduced the crash associated with [`CVE-2020-19468`](https://nvd.nist.gov/vuln/detail/CVE-2020-19468). The CVE is officially listed for PDF2JSON 0.70, and PDF2JSON itself is based on Xpdf 3.02.

In our exercise, the crashing PDF had a `BI` (Begin Image) without the matching `EI` (End Image). The parser kept treating the inline image as unfinished, eventually reached a bad stream state, and crashed at `EmbedStream::getChar()` with a null pointer dereference.

The input shape here reminded me of that: something starts, but never ends.

The result was completely different, though. The PDF case ended in a crash. Here, the regex kept searching for a closing tag that was not there and burned CPU instead.

## How 1.4 KB became 99 seconds

ODT files are ZIP-based.

That matters because a `meta.xml` filled with the same `<meta:generator>` string compresses extremely well with DEFLATE.

These were the numbers I got:

| decompressed `meta.xml` | upload size | processing time |
|---:|---:|---:|
| 64 KB | 513 B | ~1.6 s |
| 128 KB | 640 B | ~6.3 s |
| 256 KB | 894 B | ~25 s |
| 512 KB | 1,402 B | ~99 s |

The 512 KB test case was only around 1.4 KB after compression.

The timing was also the part that made the complexity clear. The input doubled each time, while the runtime went from about 1.6 seconds to 6.3, 25, and then 99 seconds.

The exact numbers depend on the machine, so the 99 seconds itself is not the important part. The scaling pattern is.

## Reaching it through the HTTP service

If this code had only been used by a local CLI, the impact would have been more limited.

The affected versions also had an HTTP service, though. An ODT uploaded to `/clean` could reach the regex through this path:

```text
POST /clean
    ↓
_handle_clean()
    ↓
clean_container()
    ↓
clean_odt()
    ↓
vulnerable regex
```

In the affected service, authentication was optional. If `WATERMARKS_SERVER_API_KEY` was not set, the request was accepted without an Authorization header.

```python
API_KEY = os.environ.get("WATERMARKS_SERVER_API_KEY", "").strip()
```

```python
def _authorized(self) -> bool:
    if not API_KEY:
        return True
```

That does **not** mean a normal installation was automatically exposed to the Internet.

The documented Docker setup maps the service to loopback (`127.0.0.1:8765`). The current [`compose.yaml`](https://github.com/guillaumemeyer/watermarks-remover/blob/main/compose.yaml) still shows that setup.

But if someone exposed the service outside loopback, an unauthenticated client that could reach `/clean` could also reach this code path.

So I think the accurate description is: **remote unauthenticated DoS on deployments where the HTTP service is network-reachable**, not "every default install is remotely exploitable."

## It could affect more than one request

The server uses `ThreadingHTTPServer`, which makes it tempting to think one slow request would only occupy one thread.

The regex work is done by CPython's `re` engine, though. CPython's `re` matching does not normally release the GIL while it is doing the match.

That means one request stuck in the slow regex can also delay other Python threads in the same process. In this case, even requests such as `/health` could be held up while the crafted file was being processed.

So the effect was not just "this one request takes 99 seconds."

## Why the existing size limits did not help much

The affected code already had size limits:

```text
MAX_ZIP_DECOMPRESSED_BYTES = 128 MiB
MAX_INPUT_BYTES = 256 MiB
```

Those are useful for normal oversized-input and decompression problems, but this bug was about processing cost.

I did not need to get anywhere close to 128 MiB. A 512 KB decompressed `meta.xml` was already enough to take around 99 seconds in my test.

Limiting how much data enters the parser does not automatically limit how expensive the algorithm is on that data.

## Reproduction

For the ODT test, I created a small valid container and filled `meta.xml` with unclosed `<meta:generator>` tags.

```python
import base64
import io
import json
import zipfile

payload = b"<meta:generator>" * (512 * 1024 // 16)

buf = io.BytesIO()

with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.writestr("mimetype", b"application/vnd.oasis.opendocument.text")
    z.writestr("content.xml", b"<x/>")
    z.writestr("meta.xml", payload)

body = json.dumps({
    "file": base64.b64encode(buf.getvalue()).decode(),
    "name": "poc.odt",
}).encode()
```

That was enough to produce an upload of about 1.4 KB while giving the regex roughly 512 KB of repetitive input after decompression.

I used the service locally for the timing tests rather than testing a third-party deployment.

## The fix

The maintainer fixed the issue in [`PR #147`](https://github.com/guillaumemeyer/watermarks-remover/pull/147).

The public changelog describes the change as **linear-time metadata stripping for SVG/ODT**. Instead of using one `.*?` expression to search from every possible opening tag, the fixed code finds opening and closing tags separately and moves forward through the string.

The core logic looks like this:

```python
def _iter_tag_blocks(text, open_re, close_re):
    closes = list(close_re.finditer(text))
    ci = 0
    last_end = 0

    for om in open_re.finditer(text):
        if om.start() < last_end:
            continue

        while ci < len(closes) and closes[ci].start() < om.end():
            ci += 1

        if ci >= len(closes):
            return

        cm = closes[ci]

        yield om.start(), om.end(), cm.start(), cm.end()
        last_end = cm.end()
```

The important part is that the closing-tag matches are collected once, and the index only moves forward.

The old case with thousands of opening tags and no closing tag no longer causes the engine to scan the remaining suffix again for every opening tag.

The fix shipped in [`v0.6.0`](https://github.com/guillaumemeyer/watermarks-remover/releases/tag/v0.6.0).

## Retesting after the patch

I ran the same inputs again after the fix.

| `meta.xml` | before | after |
|---:|---:|---:|
| 64 KB | ~1.6 s | ~0.008 s |
| 128 KB | ~6.3 s | ~0.003 s |
| 256 KB | ~25 s | ~0.004 s |
| 512 KB | **~99 s** | **~0.008 s** |

Before the patch, doubling the input gave roughly four times the runtime.

After the patch, that pattern was gone. The input that had taken about 99 seconds finished in a few milliseconds.

I am not treating those millisecond values as a benchmark. What mattered to me was that the quadratic growth disappeared when I reran the original case.

## Timeline

- **2026-08-15**: reported privately through a GitHub Security Advisory
- **2026-08-19**: the maintainer created and merged the fix in PR #147
- **2026-08-27 KST**: `v0.6.0` was released with the fix  
  (GitHub's release timestamp is 2026-08-26 23:10 UTC)

## Notes

The thing I remember most from this bug is still the 1.4 KB / 99 second result.

It came from a pretty short regex, but ODT compression, the HTTP path, and the way the regex searched for a missing closing tag made the cost much larger than the request size suggested.

It also reminded me of the fuzzing exercise from earlier in the semester. That PDF crash and this DoS both started from a similar malformed-input idea: an opening marker exists, but the matching end marker does not. One ended in a null pointer crash, while the other turned into repeated scanning and CPU exhaustion.

The fix itself was not complicated. The important change was removing the repeated suffix search instead of trying to add another file-size limit around it.

## Links

- [`watermarks-remover` repository](https://github.com/guillaumemeyer/watermarks-remover)
- [Fix PR #147](https://github.com/guillaumemeyer/watermarks-remover/pull/147)
- [`v0.6.0` release](https://github.com/guillaumemeyer/watermarks-remover/releases/tag/v0.6.0)
- [`CVE-2020-19468` on NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-19468)
- [PDF2JSON issue #29: `EmbedStream::getChar()` null pointer dereference](https://github.com/flexpaper/pdf2json/issues/29)
- [CPython issue 23690: `re` functions never release the GIL](https://bugs.python.org/issue23690)
