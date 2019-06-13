/*  crypt4gh_add_edit_list.c -- Add an edit list packet to a crypt4gh header

    Copyright (C) 2019 Genome Research Ltd.

    Author: Rob Davies <rmd@sanger.ac.uk>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>

#include "crypt4gh_agent_defs.h"
#include "sodium_if.h"
#include "keyfile.h"
#include <htslib/hts_endian.h>

void usage(FILE *fp, const char *prog) {
    fprintf(fp, "Usage: %s [-i <in>] [-o <out>] -k <keyfile> -l <edits>\n",
            prog);
}

uint32_t count_elements(const char *list) {
    const char *p = list;
    char *endp;
    int32_t count = 0;
    
    for (;;) {
        while (*p != '\0' && *p < '0' && *p > '9') p++;
        if (*p == '\0') break;
        strtoull(p, &endp, 0);
        if (p != endp) count++;
        p = endp;
    }
    return count;
}

int copy_header_packet(const char *in, FILE *in_fp,
                       const char *out, FILE *out_fp) {
    uint8_t buffer[65536];
    ssize_t bytes, written;
    uint32_t len, copied;

    bytes = fread(buffer, 1, 4, in_fp);
    if (bytes != 4) {
        fprintf(stderr, "Error reading \"%s\" : %s", in,
                bytes < 0 ? strerror(errno) : "Unexpected end of file");
        return -1;
    }

    written = fwrite(buffer, 1, 4, out_fp);
    if (written != 4) {
        fprintf(stderr, "Error writing to \"%s\" : %s\n", out, strerror(errno));
    }

    len = le_to_u32(buffer);
    if (len < 4) {
        fprintf(stderr, "Header packet length too small in \"%s\"\n", in);
        return -1;
    }
    len -= 4;
    for (copied = 0; copied < len; copied += sizeof(buffer)) {
        uint32_t to_copy = (len - copied < sizeof(buffer)
                            ? len - copied : sizeof(buffer));
        bytes = fread(buffer, 1, to_copy, in_fp);
        if (bytes != to_copy) {
            fprintf(stderr, "Error reading \"%s\" : %s", in,
                    bytes < 0 ? strerror(errno) : "Unexpected end of file");
            return -1;
        }
        written = fwrite(buffer, 1, to_copy, out_fp);
        if (written != to_copy) {
            fprintf(stderr, "Error writing to \"%s\" : %s\n",
                    out, strerror(errno));
            return -1;
        }
    }
    return 0;
}

int make_edit_packet(const uint8_t *key, uint32_t num, const char *list,
                     uint8_t **pkt_out, size_t *size_out) {
    uint8_t *plain, *pkt, *writer_pk, *header_iv;
    uint8_t header_key[X25519_SESSION_LEN];
    size_t plain_size = 8 * num + 8;
    size_t pkt_size = plain_size + 8 + X25519_PK_LEN + CC20_IV_LEN + P1305_MAC_LEN;
    size_t encrypt_len = 0;
    const char *p = list;
    char *endp;
    unsigned long long val;
    uint32_t i = 0;

    plain = malloc(plain_size);
    if (!plain) {
        perror(NULL);
        return -1;
    }
    pkt = malloc(pkt_size);
    if (!pkt) {
        perror(NULL);
        free(plain);
        return -1;
    }

    u32_to_le(1, plain);       // data_edit_list packet type
    u32_to_le(num, plain + 4); // Number of entries
    i = 0;
    for (;;) {
        while (*p != '\0' && *p < '0' && *p > '9') p++;
        if (*p == '\0') break;
        val = strtoull(p, &endp, 0);
        if (p != endp) u64_to_le(val, plain + 8 + 8 * i++);
        p = endp;
    }
    assert(i == num);

    u32_to_le(pkt_size, pkt); // Packet size
    u32_to_le(0, pkt + 4);    // Packet encryption method
    writer_pk = pkt + 8;
    header_iv = pkt + 8 + X25519_PK_LEN;

    if (get_X25519_hdr_key_w(key, writer_pk, header_key) != 0) {
        fprintf(stderr, "Couldn't generate header key\n");
        goto fail;
    }
    get_random_bytes(header_iv, CC20_IV_LEN);
    if (chacha20_encrypt(pkt + 8 + X25519_PK_LEN + CC20_IV_LEN,
                         &encrypt_len, plain, plain_size,
                         header_iv, header_key) != 0) {
        fprintf(stderr, "Encryption failed\n");
        goto fail;
    }
    assert(encrypt_len + 8 + X25519_PK_LEN + CC20_IV_LEN == pkt_size);
    free(plain);
    *pkt_out = pkt;
    *size_out = pkt_size;
    return 0;

 fail:
    free(plain);
    free(pkt);
    return -1;
}

int add_edit_list(const char *in, FILE *in_fp, const char *out, FILE *out_fp,
                  const uint8_t *key, uint32_t num, const char *list) {
    uint8_t buffer[32], *pkt = NULL;
    uint32_t npackets, i;
    ssize_t bytes;
    size_t pkt_size;

    if (make_edit_packet(key, num, list, &pkt, &pkt_size) != 0)
        return -1;

    bytes = fread(buffer, 1, 16, in_fp);
    if (bytes < 0) {
        fprintf(stderr, "Error reading \"%s\" : %s", in, strerror(errno));
        goto fail;
    }

    if (bytes != 16 || memcmp(buffer, "crypt4gh", 8) != 0) {
        fprintf(stderr, "Not a crypt4gh file : \"%s\"\n", in);
        goto fail;
    }
    if (le_to_u32(buffer + 8) != 1) {
        fprintf(stderr, "Incorrect crypt4gh version : \"%s\"\n", in);
        goto fail;
    }
    npackets = le_to_u32(buffer + 12);
    if (npackets == UINT32_MAX) {
        fprintf(stderr, "Too many header packets : \"%s\"\n", in);
        goto fail;
    }
    u32_to_le(npackets + 1, buffer + 12);
    bytes = fwrite(buffer, 1, 16, out_fp);
    if (bytes != 16) {
        fprintf(stderr, "Error writing to \"%s\" : %s\n", out, strerror(errno));
        goto fail;
    }

    for (i = 0; i < npackets; i++) {
        if (copy_header_packet(in, in_fp, out, out_fp) != 0)
            goto fail;
    }

    bytes = fwrite(pkt, 1, pkt_size, out_fp);
    if (bytes != pkt_size) {
        fprintf(stderr, "Error writing to \"%s\" : %s\n", out, strerror(errno));
        goto fail;
    }
    free(pkt);
    return 0;

 fail:
    free(pkt);
    return -1;
}

int main(int argc, char **argv) {
    const char *in = NULL, *out = NULL, *key_file = NULL, *list = NULL;
    FILE *in_fp, *out_fp;
    uint8_t key[X25519_PK_LEN];
    uint32_t num;
    int opt, is_public = 0, res;

    while ((opt = getopt(argc, argv, "hi:k:l:o:")) != -1) {
        switch (opt) {
        case 'h':
            usage(stdout, argv[0]);
            return EXIT_SUCCESS;
        case 'i': in        = optarg; break;
        case 'k': key_file  = optarg; break;
        case 'l': list      = optarg; break;
        case 'o': out       = optarg; break;
        default:
            usage(stderr, argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (!key_file || !list) {
        usage(stderr, argv[0]);
        return EXIT_FAILURE;
    }

    num = count_elements(list);
    if (num == 0) {
        fprintf(stderr, "Edit list is empty\n");
        return EXIT_FAILURE;
    }

    if (read_key_file(key_file, key, sizeof(key), &is_public) != 0)
        return EXIT_FAILURE;

    if (!is_public) {
        fprintf(stderr, "\"%s\" does not contain a public key\n", key_file);
        return EXIT_FAILURE;
    }

    if (in) {
        in_fp = fopen(in, "rb");
        if (!in_fp) {
            fprintf(stderr, "Couldn't open \"%s\" : %s\n", in, strerror(errno));
            return EXIT_FAILURE;
        }
    } else {
        in_fp = stdin;
        in = "stdin";
    }

    if (out) {
        out_fp = fopen(out, "wb");
        if (!out_fp) {
            fprintf(stderr, "Couldn't open \"%s\" : %s\n",
                    out, strerror(errno));
            return EXIT_FAILURE;
        }
    } else {
        out_fp = stdout;
        out = "stdout";
    }

    res = add_edit_list(in, in_fp, out, out_fp, key, num, list);
    if (fclose(in_fp) != 0) {
        fprintf(stderr, "Error closing \"%s\" : %s\n", in, strerror(errno));
        res = 1;
    }
    if (fclose(out_fp) != 0) {
        fprintf(stderr, "Error closing \"%s\" : %s\n",
                out, strerror(errno));
        res = 1;
    }

    return res == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
