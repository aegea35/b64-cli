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

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length, int url_safe) {
    if (input_length == 0) {
        *output_length = 0;
        unsigned char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }

    size_t padded_len = input_length;
    char *padded_data = NULL;
    const char *work_data = data;
	
    /* a single leftover char can never be valid base64. reject it instead of producing garbage. */
    if (input_length % 4 != 0) {
        size_t pad = 4 - (input_length % 4);
        if (input_length % 4 == 1) return NULL;
        padded_len = input_length + pad;
        padded_data = malloc(padded_len + 1);
        if (!padded_data) return NULL;
        memcpy(padded_data, data, input_length);
        memset(padded_data + input_length, '=', pad);
        padded_data[padded_len] = '\0';
        work_data = padded_data;
    }

    if (!b64_validate_padding(work_data, padded_len, url_safe)) {
        free(padded_data);
        return NULL;
    }

    *output_length = padded_len / 4 * 3;
    if (padded_len >= 1 && work_data[padded_len - 1] == '=') (*output_length)--;
    if (padded_len >= 2 && work_data[padded_len - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length + 1);
    if (!decoded_data) {
        free(padded_data);
        return NULL;
    }

    for (size_t i = 0, j = 0; i < padded_len;) {
        int sextet_a = work_data[i] == '=' ? 0 : b64_char_value(work_data[i], url_safe); i++;
        int sextet_b = work_data[i] == '=' ? 0 : b64_char_value(work_data[i], url_safe); i++;
        int sextet_c = work_data[i] == '=' ? 0 : b64_char_value(work_data[i], url_safe); i++;
        int sextet_d = work_data[i] == '=' ? 0 : b64_char_value(work_data[i], url_safe); i++;

        if (sextet_a == -1 || sextet_b == -1 || sextet_c == -1 || sextet_d == -1) {
            free(decoded_data);
            free(padded_data);
            return NULL;
        }

        uint32_t triple = ((uint32_t)sextet_a << 18) | ((uint32_t)sextet_b << 12) | ((uint32_t)sextet_c << 6)  | (uint32_t)sextet_d;
        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = triple & 0xFF;
    }

    decoded_data[*output_length] = '\0';
    free(padded_data);
    return decoded_data;
}

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: could not open '%s' for reading.\n", path);
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0) { fclose(f); return NULL; }
    rewind(f);

    unsigned char *buf = malloc((size_t)size + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t read_bytes = fread(buf, 1, (size_t)size, f);
    fclose(f);

    if (read_bytes != (size_t)size) {
        fprintf(stderr, "Error: short read on '%s'.\n", path);
        free(buf);
        return NULL;
    }

    buf[size] = '\0';
    *len = (size_t)size;
    return buf;
}

static int write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Error: could not open '%s' for writing.\n", path);
        return 0;
    }
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    if (written != len) {
        fprintf(stderr, "Error: short write on '%s'.\n", path);
        return 0;
    }
    return 1;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s <encode|decode|urlencode|urldecode> \"text\"\n"
        "  %s <encode|decode|urlencode|urldecode> -f <input_path> [-o <output_path>]\n",
        prog, prog);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];
    int url_safe = (strcmp(action, "urlencode") == 0 || strcmp(action, "urldecode") == 0);
    int is_encode = (strcmp(action, "encode") == 0 || strcmp(action, "urlencode") == 0);
    int is_decode = (strcmp(action, "decode") == 0 || strcmp(action, "urldecode") == 0);

    if (!is_encode && !is_decode) {
        fprintf(stderr, "Unknown command: %s\n", action);
        usage(argv[0]);
        return 1;
    }

    /* file mode: b64 <action> -f <input_path> [-o <output_path>] */
    if (strcmp(argv[2], "-f") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: -f requires an input path.\n");
            return 1;
        }
        const char *in_path = argv[3];
        const char *out_path = NULL;
        for (int i = 4; i < argc - 1; i++) {
            if (strcmp(argv[i], "-o") == 0) {
                out_path = argv[i + 1];
                break;
            }
        }

        size_t in_len = 0;
        unsigned char *in_buf = read_file(in_path, &in_len);
        if (!in_buf) return 1;

        if (is_encode) {
            char *result = base64_encode(in_buf, in_len, url_safe);
            free(in_buf);
            if (!result) {
                fprintf(stderr, "Error: encoding failed.\n");
                return 1;
            }
            if (out_path) {
                int ok = write_file(out_path, (unsigned char *)result, strlen(result));
                free(result);
                return ok ? 0 : 1;
            }
            printf("%s\n", result);
            free(result);
        } else {
            size_t out_len = 0;
            unsigned char *result = base64_decode((char *)in_buf, in_len, &out_len, url_safe);
            free(in_buf);
            if (!result) {
                fprintf(stderr, "Error: invalid base64 input.\n");
                return 1;
            }
            if (out_path) {
                int ok = write_file(out_path, result, out_len);
                free(result);
                return ok ? 0 : 1;
            }
            fwrite(result, 1, out_len, stdout);
            printf("\n");
            free(result);
        }
        return 0;
    }

    /* string mode: b64 <action> "text" */
    const char *input = argv[2];
    if (is_encode) {
        char *result = base64_encode((const unsigned char *)input, strlen(input), url_safe);
        if (!result) return 1;
        printf("%s\n", result);
        free(result);
    } else {
        size_t out_len = 0;
        unsigned char *result = base64_decode(input, strlen(input), &out_len, url_safe);
        if (!result) {
            fprintf(stderr, "Error: invalid base64 input.\n");
            return 1;
        }
        fwrite(result, 1, out_len, stdout);
        printf("\n");
        free(result);
    }

    return 0;
}