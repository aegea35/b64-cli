#!/usr/bin/env bash
#
# Regression tests for b64-cli.
#
#   tests/run_tests.sh [path-to-binary]
#
# Defaults to ./b64. Point it at a sanitizer build to get memory checking:
#   make debug && tests/run_tests.sh ./b64-debug
#
# Exits 0 if everything passed, 1 otherwise.

set -u

BIN="${1:-./b64}"

if [ ! -x "$BIN" ]; then
    echo "error: '$BIN' not found or not executable. Run 'make' first." >&2
    exit 1
fi

BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP" || exit 1

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }

section() { printf '\n%s\n' "$1"; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# expect_out <label> <expected> <args...>
# Runs the binary, compares stdout (trailing newline stripped by $()).
expect_out() {
    local label="$1" want="$2"; shift 2
    local got
    got="$("$BIN" "$@" 2>/dev/null)"
    if [ "$got" = "$want" ]; then ok "$label"
    else bad "$label (got '$got', want '$want')"; fi
}

# expect_pipe <label> <expected> <stdin> <args...>
expect_pipe() {
    local label="$1" want="$2" input="$3"; shift 3
    local got
    got="$(printf '%s' "$input" | "$BIN" "$@" 2>/dev/null)"
    if [ "$got" = "$want" ]; then ok "$label"
    else bad "$label (got '$got', want '$want')"; fi
}

# expect_reject <label> <args...>   -- must exit non-zero
expect_reject() {
    local label="$1"; shift
    if "$BIN" "$@" >/dev/null 2>&1; then bad "$label (accepted, should have been rejected)"
    else ok "$label"; fi
}

# roundtrip <label> <size> <encode-action> <decode-action> <mode>
# mode is "file" or "pipe".
roundtrip() {
    local label="$1" size="$2" enc="$3" dec="$4" mode="$5"
    head -c "$size" /dev/urandom > orig.bin 2>/dev/null || : > orig.bin

    if [ "$mode" = "file" ]; then
        "$BIN" "$enc" -f orig.bin -o mid.b64 2>err.txt || { bad "$label (encode failed)"; cat err.txt >&2; return; }
        "$BIN" "$dec" -f mid.b64 -o back.bin 2>err.txt || { bad "$label (decode failed)"; cat err.txt >&2; return; }
    else
        "$BIN" "$enc" < orig.bin > mid.b64 2>err.txt || { bad "$label (encode failed)"; cat err.txt >&2; return; }
        "$BIN" "$dec" < mid.b64 > back.bin 2>err.txt || { bad "$label (decode failed)"; cat err.txt >&2; return; }
    fi

    # Sanitizers report on stderr without necessarily changing the exit code.
    if [ -s err.txt ]; then bad "$label (stderr not empty)"; cat err.txt >&2; return; fi

    if cmp -s orig.bin back.bin; then ok "$label"
    else bad "$label (round-trip differs)"; fi
}

printf 'Testing: %s\n' "$BIN"

# ---------------------------------------------------------------------------
section 'RFC 4648 test vectors (standard alphabet)'
# ---------------------------------------------------------------------------
expect_out 'encode ""'       ''           encode ''
expect_out 'encode "f"'      'Zg=='       encode 'f'
expect_out 'encode "fo"'     'Zm8='       encode 'fo'
expect_out 'encode "foo"'    'Zm9v'       encode 'foo'
expect_out 'encode "foob"'   'Zm9vYg=='   encode 'foob'
expect_out 'encode "fooba"'  'Zm9vYmE='   encode 'fooba'
expect_out 'encode "foobar"' 'Zm9vYmFy'   encode 'foobar'

expect_out 'decode "Zg=="'     'f'      decode 'Zg=='
expect_out 'decode "Zm8="'     'fo'     decode 'Zm8='
expect_out 'decode "Zm9v"'     'foo'    decode 'Zm9v'
expect_out 'decode "Zm9vYmFy"' 'foobar' decode 'Zm9vYmFy'

# Historical regression: this produced TQAA before the group_start fix.
expect_out 'encode "M" (padding regression)'  'TQ=='  encode 'M'
expect_out 'encode "Ma"'                      'TWE='  encode 'Ma'
expect_out 'encode "Man"'                     'TWFu'  encode 'Man'

# ---------------------------------------------------------------------------
section 'URL-safe alphabet'
# ---------------------------------------------------------------------------
# 0xFB 0xFF encodes to -_8 in URL-safe, +/8 in standard.
printf '\xfb\xff\xbf' > urlbytes.bin
expect_out 'urlencode uses -_'  '-_-_'  urlencode -f urlbytes.bin
expect_out 'encode uses +/'     '+/+/'  encode    -f urlbytes.bin

expect_out 'urldecode round-trip' 'url-safe base64' urldecode 'dXJsLXNhZmUgYmFzZTY0'

# Cross-alphabet input must be rejected in both directions.
expect_reject 'decode rejects URL-safe chars'  decode    '-_-_'
expect_reject 'urldecode rejects standard chars' urldecode '+/+/'

# ---------------------------------------------------------------------------
section 'Malformed input rejection'
# ---------------------------------------------------------------------------
expect_reject 'rejects impossible length (%4==1)'  decode 'Zm9vYmFyZ'
expect_reject 'rejects "=" in the middle'          decode 'Zm=vYmFy'
expect_reject 'rejects char after padding'         decode 'Zg==Zg=='
expect_reject 'rejects non-alphabet character'     decode 'Zm9v*mFy'
expect_reject 'rejects unknown command'            frobnicate 'x'
expect_reject '-f with no path'                    encode -f
expect_reject '-o with no path'                    encode 'x' -o
expect_reject 'text and -f together'               encode 'x' -f orig.bin
expect_reject 'missing input file'                 encode -f no_such_file.bin

# ---------------------------------------------------------------------------
section 'Lenient decode (whitespace, missing padding)'
# ---------------------------------------------------------------------------
expect_out  'ignores trailing newline'     'foobar'  decode 'Zm9vYmFy
'
expect_out  'ignores embedded newlines'    'foobar'  decode 'Zm9v
YmFy'
expect_out  'ignores spaces and tabs'      'foobar'  decode 'Zm9v	 YmFy'
expect_out  'accepts missing padding'      'f'       decode 'Zg'
expect_out  'accepts missing padding (2)'  'fo'      decode 'Zm8'
expect_pipe 'decodes MIME-wrapped input'   'foobar'  'Zm9v
YmFy
' decode

# ---------------------------------------------------------------------------
section 'stdin / stdout piping'
# ---------------------------------------------------------------------------
expect_pipe 'encode from stdin'      'Zm9vYmFy'  'foobar'    encode
expect_pipe 'decode from stdin'      'foobar'    'Zm9vYmFy'  decode
expect_pipe 'encode from "-f -"'     'Zm9vYmFy'  'foobar'    encode -f -
expect_pipe 'empty stdin encodes'    ''          ''          encode
expect_pipe 'empty stdin decodes'    ''          ''          decode

# Full pipeline: encode | decode must reproduce the input exactly.
if [ "$(printf 'foobar' | "$BIN" encode | "$BIN" decode)" = 'foobar' ]; then
    ok 'encode | decode pipeline'
else
    bad 'encode | decode pipeline'
fi

# Decode output must have NO trailing newline, or binary files corrupt.
n=$(printf 'Zm9vYmFy' | "$BIN" decode | wc -c | tr -d ' ')
if [ "$n" = "6" ]; then ok 'decode adds no trailing newline'
else bad "decode adds no trailing newline (got $n bytes, want 6)"; fi

# Encode to a file must have NO trailing newline either.
"$BIN" encode 'foobar' -o enc.txt
n=$(wc -c < enc.txt | tr -d ' ')
if [ "$n" = "8" ]; then ok 'encode -o writes no trailing newline'
else bad "encode -o writes no trailing newline (got $n bytes, want 8)"; fi

# ---------------------------------------------------------------------------
section 'Binary safety'
# ---------------------------------------------------------------------------
# Embedded NUL bytes must survive; a strlen-based implementation truncates here.
printf 'AB\x00CD' > nul.bin
"$BIN" encode -f nul.bin -o nul.b64 2>/dev/null
"$BIN" decode -f nul.b64 -o nul.back 2>/dev/null
if cmp -s nul.bin nul.back; then ok 'embedded NUL bytes survive round-trip'
else bad 'embedded NUL bytes survive round-trip'; fi

# All 256 byte values.
perl -e 'print map { chr } 0..255' > all256.bin 2>/dev/null \
    || python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256)))" > all256.bin
"$BIN" encode -f all256.bin -o all256.b64 2>/dev/null
"$BIN" decode -f all256.b64 -o all256.back 2>/dev/null
if cmp -s all256.bin all256.back; then ok 'all 256 byte values round-trip'
else bad 'all 256 byte values round-trip'; fi

# ---------------------------------------------------------------------------
section 'Round-trips: boundary sizes (file mode)'
# ---------------------------------------------------------------------------
for size in 0 1 2 3 4 5 6 7 8; do
    roundtrip "std  $size bytes" "$size" encode decode file
done

# ---------------------------------------------------------------------------
section 'Round-trips: boundary sizes (URL-safe, file mode)'
# ---------------------------------------------------------------------------
for size in 0 1 2 3 4 5 6 7 8; do
    roundtrip "url  $size bytes" "$size" urlencode urldecode file
done

# ---------------------------------------------------------------------------
section 'Round-trips: larger sizes (file mode)'
# ---------------------------------------------------------------------------
# 3071/3072/3073 and 6144 straddle the streaming chunk size; 65537 straddles
# the 65536 read_stream buffer; 500000 forces several realloc doublings.
for size in 100 1000 3071 3072 3073 6144 65535 65536 65537 500000; do
    roundtrip "std  $size bytes" "$size" encode decode file
done

# ---------------------------------------------------------------------------
section 'Round-trips: pipe mode'
# ---------------------------------------------------------------------------
for size in 0 1 2 3 3072 65537 500000; do
    roundtrip "pipe $size bytes" "$size" encode decode pipe
done

# ---------------------------------------------------------------------------
printf '\n----------------------------------------\n'
printf '%d passed, %d failed\n' "$PASS" "$FAIL"

[ "$FAIL" -eq 0 ] || exit 1
