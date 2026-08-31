# b64-cli

**b64-cli** is a small command-line base64 encoder/decoder written in C, built mostly out of boredom on couple slow afternoons. It handles text, files, and binary data (images included), both the standard base64 alphabet and the URL-safe variant.

It's not trying to replace `base64` (the coreutils one). It's a from-scratch implementation to actually understand what base64 is doing under the hood, one bit-shift at a time.

## Key Features
* **Standard + URL-safe encoding:** Switch alphabets (`+`/`/` vs `-`/`_`) with a flag, same core logic underneath.
* **Binary-safe:** Works on raw byte buffers, not null-terminated strings, so images and other binary files round-trip correctly instead of getting truncated at the first `\0`.
* **Strict validation on decode:** Wrong-alphabet characters, misplaced =, and impossible lengths are rejected with a clear error instead of silently producing garbage. Whitespace is ignored and missing trailing = is tolerated since both are common in real-world base64.
* **File I/O:** Encode/decode straight to and from files, not just inline strings.
* **Unix filter:** Reads stdin and writes stdout by default, so it pipes: cat file | ./b64 encode | ./b64 decode
* **Whitespace-tolerant decode:** Newlines, spaces, and tabs in base64 input are ignored, so line-wrapped (MIME-style) input and trailing newlines from pipes both decode fine.

## Installation

### Prerequisites

* GCC (or any C11-compliant compiler)
* Linux/Unix environment

### Build

```bash
make
```
To clean artifacts:

```bash
make clean
```

## Usage

Encode or decode a string directly:

```bash
./b64 encode "base64"
./b64 decode "YmFzZTY0"
```

URL-safe variants:

```bash
./b64 urlencode "url-safe base64"
./b64 urldecode "dXJsLXNhZmUgYmFzZTY0"
```

Encode or decode a file:

```bash
./b64 encode -f photo.png -o photo.b64
./b64 decode -f photo.b64 -o restored.png
```

Drop `-o` to print the result to stdout instead of writing a file:

```bash
./b64 encode -f photo.png
```

Pipe through stdin/stdout omit both `text` and `-f`:

```bash
cat photo.png | ./b64 encode > photo.b64
cat photo.b64 | ./b64 decode > restored.png
cat photo.png | ./b64 encode | ./b64 decode | cmp - photo.png
```

`-f -` also means stdin, if you prefer being explicit.

```bash
cat photo.png | ./b64 encode -f -
```

Decoded output is written byte-for-byte with **no trailing newline**, so binary files round-trip exactly. Encoded output gets a newline only when it goes to stdout.
## WIP, Performance, Limitations

* **Whole-file loading:** Input is read fully into memory before encoding, including when reading from a pipe. Fine up to a few hundred MB; not fine for multi-gigabyte files. Streaming (chunked read/encode/write) is on the roadmap and is what will actually make piping cheap.
* **No Base85 (for now) or other encoding algorithms:** Deliberately out of scope for now. Base64 was the point of this exercise; Base85 (or others) is a "maybe later, for fun" extension.

-----
*Note: b64-cli is a learning project, not a production crypto or encoding library. It doesn't encrypt anything, base64 is just a reversible encoding, not a cipher.*
