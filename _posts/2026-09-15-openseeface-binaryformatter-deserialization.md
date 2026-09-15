---
title: "OpenSeeFace BinaryFormatter Deserialization Vulnerability"
date: 2026-09-15 00:00:00 +0900
categories: [Security Research]
tags: [openseeface, vseeface, deserialization, binaryformatter]
description: ""
---

## Summary

I found this issue while using AI to analyze the OpenSeeFace repository. The vulnerable code path used `BinaryFormatter.Deserialize()`.

I had Claude do the initial repository analysis, and it rated the issue as High. The basic finding that the code path could lead to RCE was right, but part of the reasoning behind the severity was not.

Claude specifically said:

> "VTuber 커뮤니티에서 캘리브레이션 모델 파일을 주고받는 사용 패턴을 고려하면 악성 파일 하나로 사용자 PC에서 코드 실행이 가능한 현실적인 시나리오입니다."
>
> *(English: "Considering the usage pattern of exchanging calibration model files in VTuber communities, a malicious file leading to code execution on a user's PC is a realistic scenario.")*

When I checked that assumption again, I could not find evidence for that usage pattern.

I lowered the severity from High to Medium, built a PoC to check whether code execution was actually possible, and then reported it to the maintainer.

The issue was later fixed in VSeeFace `v1.13.38c5` and OpenSeeFace `v1.20.5`.


## OpenSeeFace's ExpressionCapture feature

OpenSeeFace has a feature for training expression detection from a user's own facial movement data.

A very simplified way to think about it is:

> Roughly: record yourself winking repeatedly → "this kind of coordinate pattern means a wink"

The expression data and trained model can be saved and loaded again. In OpenSeeFace `v1.20.4`, .NET's `BinaryFormatter` was used when deserializing this data.

Deserialization is the process of turning saved data back into program objects.

`BinaryFormatter` recreates actual .NET objects. If untrusted input is passed into it, the program can end up creating objects it never intended to create.


## The vulnerability

The problem was that the expression loading code passed the data directly to `BinaryFormatter.Deserialize()`.

The first location was in `Unity/OpenSeeExpression.cs`.

```csharp
IFormatter formatter = new BinaryFormatter();

using (GZipStream gzipStream =
       new GZipStream(memoryStream, CompressionMode.Decompress))
{
    oser = formatter.Deserialize(gzipStream)
        as OpenSeeExpressionRepresentation;
}
```

At first glance, `as OpenSeeExpressionRepresentation` looks like a type check. But the order matters.

`Deserialize()` first reads the type information from the input and creates the object. Only after that does the cast check whether the result can be treated as an `OpenSeeExpressionRepresentation`.

So even if the cast fails, deserialization has already happened.

To test this behavior, I added a small `MaliciousPayload` class to my Unity test environment. It implements `ISerializable`, and its deserialization constructor writes a text file to the desktop.

```csharp
[Serializable]
public class MaliciousPayload : ISerializable
{
    public static string vectorUsed = "";

    public MaliciousPayload() { }

    protected MaliciousPayload(
        SerializationInfo info,
        StreamingContext context)
    {
        string desktop =
            Environment.GetFolderPath(
                Environment.SpecialFolder.Desktop);

        string path =
            Path.Combine(desktop, "OPENSEEFACE_PoC_v2.txt");

        File.WriteAllText(
            path,
            $"=== OpenSeeFace BinaryFormatter PoC ===\n\n" +
            $"벡터: {vectorUsed}\n" +
            $"시각: {DateTime.Now}\n" +
            $"유저: {Environment.UserName}\n" +
            $"OS:   {Environment.OSVersion}\n"
        );

        Debug.LogError(
            $"[PoC] 코드 실행 성공!\n벡터: {vectorUsed}");
    }

    public void GetObjectData(
        SerializationInfo info,
        StreamingContext context)
    {
    }
}
```

When data containing this object reaches `BinaryFormatter.Deserialize()`, the constructor runs before OpenSeeFace gets a chance to check the final type.

The PoC later hit a `NullReferenceException`, but by that point the file had already been created on the desktop.

There was another instance of the same problem.

The expression data contains trained model data in `modelBytes`. When `SVMModel` loaded those bytes, it used `BinaryFormatter.Deserialize()` again.

The flow looked roughly like this:

```text
expression data / byte[]
        ↓
OpenSeeExpression loading
        ↓
BinaryFormatter.Deserialize()   # first location
        ↓
expression data restored
        ↓
modelBytes
        ↓
SVMModel loading
        ↓
BinaryFormatter.Deserialize()   # second location
```

The first deserialization point was already enough to confirm code execution in my test environment. The second one was not required for the PoC, but the same unsafe deserialization pattern existed there as well.


## PoC and actual attack conditions

The PoC was intentionally simple. I only wanted to check whether code could really run during deserialization.

On success, it created `OPENSEEFACE_PoC_v2.txt` on the desktop and wrote basic information such as the current username and OS version.

The most direct way to reproduce the issue was to load a crafted expression model file through `LoadFromFile()`.

```text
crafted expression model file
        ↓
LoadFromFile()
        ↓
BinaryFormatter.Deserialize()
        ↓
PoC code runs
        ↓
file created on the desktop
```

This path successfully created the PoC file.

![PoC code execution on OpenSeeFace v1.20.4](/assets/img/posts/openseeface-binaryformatter/v1.20.4-poc-success.png)
_OpenSeeFace v1.20.4 — the PoC code ran and created the proof file on the desktop._

The same deserialization code could also be reached without a file by passing the data directly to `LoadFromBytes()`.

```csharp
byte[] payload = BuildGzipBinaryFormatterPayload();
expr.LoadFromBytes(payload);
```

I don't consider `LoadFromBytes()` a separate remote attack vector by itself.

It is a public API that takes a byte array and passes it into the same loading logic. OpenSeeFace does not, by default, receive network data and feed it directly into this method.

The realistic attack scenario is getting a user to load a crafted expression model file.

Unlike avatar models, costumes, or visual-effect assets, expression-training data is not something users normally download and trade around. It is tied to a specific user's face and calibration, so getting a victim to load a malicious file would already require a fairly specific social-engineering setup.

That means the file-based path requires some amount of social engineering. For `LoadFromBytes()` to be useful to an attacker, there would need to be some other application flow that delivers attacker-controlled data to that API.

This is why I lowered the AI's original High rating to Medium.


## Patch

In my original report, I suggested a `SerializationBinder` allowlist as a short-term fix.

A `SerializationBinder` acts roughly like a filter for the types that `BinaryFormatter` is allowed to recreate. The problem is that this still keeps `BinaryFormatter` in the design, and I had not verified whether the allowlist would stay compatible with existing files under Unity/Mono.

The actual patch went further than that.

In commit [`a8b4c99`](https://github.com/emilianavt/OpenSeeFace/commit/a8b4c9979b9214434aa5f1c2e063d9ebd0d49d43), the `BinaryFormatter` usage in `OpenSeeExpression.cs` and `SVMModel.cs` was removed. A separate `SafeBinaryReader` and `SafeBinaryWriter` were added instead.

Before the patch, the code restored an actual .NET object:

```csharp
oser = formatter.Deserialize(gzipStream)
    as OpenSeeExpressionRepresentation;
```

After the patch, the decompressed data is passed to the new reader:

```csharp
object root;

using (MemoryStream memoryStream =
       new MemoryStream(modelBytes, false))
using (GZipStream gzipStream =
       new GZipStream(memoryStream, CompressionMode.Decompress))
using (MemoryStream decompressed = new MemoryStream())
{
    gzipStream.CopyTo(decompressed);
    decompressed.Position = 0;

    root = SafeBinaryReader.Deserialize(decompressed);
}
```

The main difference is that serialized type names are no longer used to recreate arbitrary .NET objects.

The new reader stores parsed objects in a data structure such as `SafeObject`, and OpenSeeFace pulls out the fields it expects.

```text
before

type stored in the file
        ↓
BinaryFormatter
        ↓
actual .NET object created
        ↓
code can run during deserialization


after

serialized data
        ↓
SafeBinaryReader
        ↓
SafeObject
        ↓
only the required values are read
```

The second `BinaryFormatter.Deserialize()` in `SVMModel.cs` was removed in the same way.

After the patch was released, I reran the old PoCs.

On OpenSeeFace `v1.20.5`, neither the file-based path nor the direct `LoadFromBytes()` test created the PoC file anymore.

For the file-loading path, execution stopped later while loading the model data with an `ArgumentNullException`. The PoC constructor did not run.

![File-based PoC blocked on OpenSeeFace v1.20.5](/assets/img/posts/openseeface-binaryformatter/v1.20.5-loadfromfile-blocked.png)
_OpenSeeFace v1.20.5 — the old file-based PoC no longer reaches code execution._

The direct `LoadFromBytes()` test stopped at the same part of the loading code.

![LoadFromBytes PoC blocked on OpenSeeFace v1.20.5](/assets/img/posts/openseeface-binaryformatter/v1.20.5-loadfrombytes-blocked.png)
_OpenSeeFace v1.20.5 — the old `LoadFromBytes()` PoC no longer executes._

Both tests ended with roughly the following exception:

```text
ArgumentNullException: Buffer cannot be null.
Parameter name: buffer

System.IO.MemoryStream..ctor(...)
OpenSee.SVMModel.LoadSerialized(...)
OpenSee.SVMModel.LoadModel(...)
OpenSee.SVMModel..ctor(...)
OpenSee.OpenSeeExpression+OpenSeeExpressionRepresentation.LoadSerialized(...)
```

The exception itself is not what proves the fix. The old version also threw an exception after the payload had already run.

The difference is that, with `v1.20.5`, the same inputs no longer execute the PoC code before the failure.


## Disclosure Timeline

**2026-08-04**

I told the maintainer that I had found a vulnerability and had a working PoC.

**2026-08-05**

I sent a report with the affected code, PoC, attack flow, and a suggested fix. The maintainer confirmed the report and said they would fix it.

**2026-08-06**

An update addressing the issue was released for VSeeFace first. The OpenSeeFace repository patch came later.

**2026-09-14**

Before publishing this write-up, I checked the exact fixed versions and the status of the OpenSeeFace patch.

The maintainer confirmed that the VSeeFace fix was in `v1.13.38c5`. On the same day, the OpenSeeFace patch was pushed and [`v1.20.5`](https://github.com/emilianavt/OpenSeeFace/releases/tag/v1.20.5) was released.

I also asked for permission to publish the vulnerability and disclosure process, and the maintainer was fine with it.


## What I took away from this

The interesting part for me was not that the AI invented a vulnerability that did not exist. It found a real issue. The hallucination was in the reasoning it used to rate the risk.

I have spent enough time around VTuber-related projects that the claim about users commonly exchanging these model files sounded odd to me. That was what made me check the assumption again.

This was a good reminder that an AI doing vulnerability analysis can make up plausible details not only about code, but also about how a program is used and what a realistic attack path looks like.

Since then, even when a finding is technically valid, I try not to stop at "the sink is dangerous." I also check how the program is actually used and whether attacker-controlled input can realistically reach that code path.

After the patch, neither of the two entry points I tested led to code execution with the old PoC.

That is the limit of what I verified for this post. I did not audit the new parser as a whole, and I did not test compatibility with existing legitimate expression files.
