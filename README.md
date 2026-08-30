# b64-cli

**b64-cli** is a small command-line base64 encoder/decoder written in C, built mostly out of boredom on couple slow afternoons. It handles text, files, and binary data (images included), both the standard base64 alphabet and the URL-safe variant.

It's not trying to replace `base64` (the coreutils one). It's a from-scratch implementation to actually understand what base64 is doing under the hood, one bit-shift at a time.

*Note: b64 is a learning project, not a production crypto or encoding library. It doesn't encrypt anything, base64 is just a reversible encoding, not a cipher.*

