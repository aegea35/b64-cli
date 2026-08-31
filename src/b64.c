#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const char b64_table_std[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64_table_url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int b64_char_value(char c, int url_safe) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (url_safe) {
        if (c == '-') return 62;
        if (c == '_') return 63;
    } else {
        if (c == '+') return 62;
        if (c == '/') return 63;
    }
    return -1;
}

char *base64_encode(const unsigned char *data, size_t input_length, int url_safe) {
    const char *table = url_safe ? b64_table_url : b64_table_std;
    size_t output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(output_length + 1);
    if (!encoded_data) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        size_t group_start = i;
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded_data[j++] = table[(triple >> 18) & 0x3F];
        encoded_data[j++] = table[(triple >> 12) & 0x3F];
        encoded_data[j++] = (i - group_start < 2) ? '=' : table[(triple >> 6) & 0x3F];
        encoded_data[j++] = (i - group_start < 3) ? '=' : table[triple & 0x3F];
    }

    encoded_data[output_length] = '\0';
    return encoded_data;
}

static int b64_validate_padding(const char *data, size_t len, int url_safe) {
    if (len == 0) return 1;
    if (len % 4 != 0) return 0; 

    int seen_pad = 0;
    for (size_t i = 0; i < len; i++) {
        char c = data[i];
        if (c == '=') {
            seen_pad = 1;
            if (i < len - 2) return 0;
        } else {
            if (seen_pad) return 0;
            if (b64_char_value(c, url_safe) == -1) return 0;
        }
    }
    return 1;
}

/* +4 for worst case padding, +1 for NUL */
static char *b64_normalize(const char *data, size_t input_length, size_t *out_len) {
    char *buf = malloc(input_length + 5);
    if (!buf) return NULL;

    size_t n = 0;
    for (size_t i = 0; i < input_length; i++) {
        char c = data[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') continue;
        buf[n++] = c;
    }

    size_t rem = n % 4;
    if (rem == 1) { free(buf); return NULL; }  /* impossible length */
    if (rem != 0) {
        memset(buf + n, '=', 4 - rem);
        n += 4 - rem;
    }

    buf[n] = '\0';
    *out_len = n;
    return buf;
}

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length, int url_safe) {
    size_t len = 0;
    char *work_data = b64_normalize(data, input_length, &len);
    if (!work_data) return NULL;

    if (!b64_validate_padding(work_data, len, url_safe)) {
        free(work_data);
        return NULL;
    }

    *output_length = len / 4 * 3;
    if (len >= 1 && work_data[len - 1] == '=') (*output_length)--;
    if (len >= 2 && work_data[len - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length + 1);
    if (!decoded_data) {
        free(work_data);
        return NULL;
    }

    for (size_t i = 0, j = 0; i < len;) {
        int sextet_a = work_data[i] == '=' ? 0 : b64_char_value(work_data[i], url_safe); i++;
        int sextet_b = work_data[i] == '=' ? 0 : b64_char_value(work_data[i], url_safe); i++;
        int sextet_c = work_data[i] == '=' ? 0 : b64_char_value(work_data[i], url_safe); i++;
        int sextet_d = work_data[i] == '=' ? 0 : b64_char_value(work_data[i], url_safe); i++;

        if (sextet_a == -1 || sextet_b == -1 || sextet_c == -1 || sextet_d == -1) {
            free(decoded_data);
            free(work_data);
            return NULL;
        }

        uint32_t triple = ((uint32_t)sextet_a << 18) | ((uint32_t)sextet_b << 12) | ((uint32_t)sextet_c << 6)  | (uint32_t)sextet_d;
        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = triple & 0xFF;
    }

    decoded_data[*output_length] = '\0';
    free(work_data);
    return decoded_data;
}

static unsigned char *read_stream(FILE *f, size_t *len) {
    size_t cap = 65536, n = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return NULL;

    for (;;) {
        if (n == cap) {
            unsigned char *tmp = realloc(buf, cap * 2);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
            cap *= 2;
        }
        size_t got = fread(buf + n, 1, cap - n, f);
        n += got;
        if (got == 0) {
            if (ferror(f)) { free(buf); return NULL; }
            break;  
        }
    }

    if (n == cap) {
        unsigned char *tmp = realloc(buf, cap + 1);
        if (!tmp) { free(buf); return NULL; }
        buf = tmp;
    }
    buf[n] = '\0';
    *len = n;
    return buf;
}

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: could not open '%s' for reading.\n", path);
        return NULL;
    }
    unsigned char *buf = read_stream(f, len);
    fclose(f);
    if (!buf) fprintf(stderr, "Error: read failed on '%s'.\n", path);
    return buf;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: \n"
        "%s <encode|decode|urlencode|urldecode> [text] [-f <in>] [-o <out>]\n"
        "Input:  a literal text argument, -f <path> to read a file,\n"
        "        or nothing at all to read stdin (-f - also means stdin).\n"
        "Output: -o <path> to write a file, otherwise stdout.\n",
        prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *action = argv[1];
    int url_safe  = (strcmp(action, "urlencode") == 0 || strcmp(action, "urldecode") == 0);
    int is_encode = (strcmp(action, "encode")    == 0 || strcmp(action, "urlencode") == 0);
    int is_decode = (strcmp(action, "decode")    == 0 || strcmp(action, "urldecode") == 0);

    if (!is_encode && !is_decode) {
        fprintf(stderr, "Unknown command: %s\n", action);
        usage(argv[0]);
        return 1;
    }

    const char *in_path = NULL, *out_path = NULL, *text = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: -f requires a path.\n"); return 1; }
            in_path = argv[i];
        } else if (strcmp(argv[i], "-o") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: -o requires a path.\n"); return 1; }
            out_path = argv[i];
        } else if (!text) {
            text = argv[i];
        } else {
            fprintf(stderr, "Error: unexpected argument '%s'.\n", argv[i]);
            return 1;
        }
    }
    if (text && in_path) {
        fprintf(stderr, "Error: give either text or -f, not both.\n");
        return 1;
    }

    /* acquire input: literal text, file, or stdin */
    unsigned char *in_buf = NULL;
    size_t in_len = 0;
    int owns_input = 0;

    if (text) {
        in_buf = (unsigned char *)text;
        in_len = strlen(text);
    } else if (in_path && strcmp(in_path, "-") != 0) {
        in_buf = read_file(in_path, &in_len);
        if (!in_buf) return 1;
        owns_input = 1;
    } else {
        in_buf = read_stream(stdin, &in_len);
        if (!in_buf) { fprintf(stderr, "Error: read from stdin failed.\n"); return 1; }
        owns_input = 1;
    }

    FILE *out = stdout;
    if (out_path) {
        out = fopen(out_path, "wb");
        if (!out) {
            fprintf(stderr, "Error: could not open '%s' for writing.\n", out_path);
            if (owns_input) free(in_buf);
            return 1;
        }
    }

    int rc = 0;
    if (is_encode) {
        char *result = base64_encode(in_buf, in_len, url_safe);
        if (!result) { fprintf(stderr, "Error: encoding failed.\n"); rc = 1; }
        else {
            size_t n = strlen(result);
            if (fwrite(result, 1, n, out) != n) rc = 1;
            if (!out_path) fputc('\n', out);
            free(result);
        }
    } else {
        size_t out_len = 0;
        unsigned char *result = base64_decode((const char *)in_buf, in_len, &out_len, url_safe);
        if (!result) { fprintf(stderr, "Error: invalid base64 input.\n"); rc = 1; }
        else {
            if (fwrite(result, 1, out_len, out) != out_len) rc = 1;
            free(result);
        }
    }

    if (owns_input) free(in_buf);
    if (out_path) {
        if (fclose(out) != 0) rc = 1;
    } else {
        if (fflush(out) != 0) rc = 1;
    }
    if (rc) fprintf(stderr, "Error: write failed.\n");
    return rc;
}