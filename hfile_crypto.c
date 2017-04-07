/*  hfile_crypto.c -- Encrypted file backend

    Copyright (C) 2016 Genome Research Ltd.

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

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "htslib/hts_endian.h"
#include "hts_internal.h"
#include "hfile_internal.h"
#include "version.h"

#ifndef ENOTSUP
#define ENOTSUP EINVAL
#endif

#define CRYPTO_BUFFER_LENGTH 65536
#define RECIPIENT_ENV_VAR "HTS_CRYPT_TO"
#define MAGIC "crypt4gh"
#define PROTO_VERSION 1

#define MAX_IV_LEN 16

typedef enum {
    AES_256_CTR = 0,
    NUM_CRYPT_TYPES
} hCryptType;

typedef struct {
    uint8_t key[32];
    uint8_t iv[16];
} aes_256_params;

typedef struct {
    uint64_t plain_start;
    uint64_t plain_end;
    uint64_t cipher_start;
    int64_t  ctr_offset;
    uint32_t method;
    union {
        aes_256_params a256;
    } u;
} Encryption_params;

typedef struct {
    hFILE base;
    hFILE *parent;
    off_t real_data_start;
    EVP_CIPHER_CTX *ctx;
    uint8_t *key;
    uint8_t *iv;
    Encryption_params *recs;
    uint32_t num_recs;
    uint32_t recnum;
    uint64_t last_ctr;
    uint32_t keylen;
    uint32_t ivlen;
    uint32_t blocklen;
    uint32_t shift;
    uint8_t ctr[MAX_IV_LEN];
    uint8_t crypt_in[CRYPTO_BUFFER_LENGTH];
    uint8_t crypt_out[CRYPTO_BUFFER_LENGTH];
} hFILE_crypto;

static int disclaimed = 0;

static void disclaimer() {
    if (disclaimed) return;
    fprintf(stderr,
            "WARNING:  hfile_crypto is for EXPERIMENTAL use only.  The file "
            "format is liable\n"
            "to change.  Do not expect future versions to be able to read "
            "anything written\n"
            "by this one.   Files encrypted by this module should not "
            "be assumed secure.\n");
    disclaimed = 1;
}

static void dump_ssl_errors() {
    unsigned long code;
    char buf[1024];

    if (hts_verbose <= 1) return;

    while ((code = ERR_get_error()) > 0) {
        buf[0] = '\0';
        ERR_error_string_n(code, buf, sizeof(buf));
        fprintf(stderr, "%s\n", buf);
    }
}

static int ssl_init_encryption(hFILE_crypto *fp, uint32_t recnum) {
    const EVP_CIPHER *cipher = NULL;

    switch (fp->recs[recnum].method) {
    case AES_256_CTR:
        cipher = EVP_aes_256_ctr();
        fp->keylen = sizeof(fp->recs[recnum].u.a256.key);
        fp->ivlen = sizeof(fp->recs[recnum].u.a256.iv);
        fp->blocklen = 16;
        fp->shift = 4;
        fp->key = fp->recs[recnum].u.a256.key;
        fp->iv = fp->recs[recnum].u.a256.iv;
        break;
    default: break;
    }

    if (cipher == NULL) {
        if (hts_verbose > 1)
            fprintf(stderr,
                    "[E::%s] Couldn't get cipher %u\n", __func__,
                    fp->recs[recnum].method);
        if (fp->recs[recnum].method >= 0
            && fp->recs[recnum].method < NUM_CRYPT_TYPES) {
            dump_ssl_errors();
        }
        errno = ENOTSUP;
        return -1;
    }

    if (fp->recnum < fp->num_recs
        && fp->recs[recnum].method == fp->recs[fp->recnum].method) {
        // Just changing key & iv settings; cipher stays the same
        fp->recnum = recnum;
        fp->last_ctr = UINT64_MAX;
        return 0;
    }

    fp->recnum = recnum;

    // Set up EVP context, find key, iv and block lengths
    if (fp->ctx) EVP_CIPHER_CTX_free(fp->ctx);
    fp->ctx = EVP_CIPHER_CTX_new();
    if (!fp->ctx) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Couldn't get cipher context\n",
                    __func__);
        dump_ssl_errors();
        return -1;
    }
    if (!EVP_EncryptInit_ex(fp->ctx, cipher, NULL, NULL, NULL)) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Failed to initialize encryption\n",
                    __func__);
        dump_ssl_errors();
        errno = EIO;
        goto fail;
    }
    EVP_CIPHER_CTX_set_padding(fp->ctx, 0);
    // Paranoia checks
    assert(fp->keylen == EVP_CIPHER_CTX_key_length(fp->ctx));
    assert(fp->ivlen == EVP_CIPHER_CTX_iv_length(fp->ctx));
    assert(fp->ivlen >= 2 * sizeof(uint64_t));
    assert(fp->ivlen <= MAX_IV_LEN);
    assert(fp->blocklen > 0 && fp->blocklen < 256);
    assert((1 << fp->shift) == fp->blocklen);

    fp->last_ctr = UINT64_MAX;
 
    return 0;

 fail:
    return -1;
}

static int ssl_encrypt_block(hFILE_crypto *fp, uint8_t *in, size_t n) {
    size_t done = 0;
    int outl;

    // n must be an exact number of blocks
    assert(n >= fp->blocklen && (n & (fp->blocklen - 1)) == 0);

    while (done < n) {
        int r = EVP_EncryptUpdate(fp->ctx, fp->crypt_out + done, &outl,
                                  in + done, n - done);
        if (r != 1) {
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] Couldn't encrypt data\n", __func__);
            dump_ssl_errors();
            errno = EIO;
            return -1;
        }
        assert(outl > 0);
        done += outl;
        fp->last_ctr += outl >> fp->shift;
    }

    return 0;
}

static int ssl_decrypt_block(hFILE_crypto *fp, uint8_t *out, size_t n) {
    size_t done = 0;
    int outl;

    // n must be an exact number of blocks
    assert(n >= fp->blocklen && (n & (fp->blocklen - 1)) == 0);

    while (done < n) {
        int r = EVP_DecryptUpdate(fp->ctx, out + done, &outl,
                                  fp->crypt_in + done, n - done);
        if (!r) {
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] Couldn't decrypt data\n", __func__);
            dump_ssl_errors();
            errno = EIO;
            return -1;
        }
        assert(outl > 0 && (outl & (fp->blocklen - 1)) == 0);
        done += outl;
        fp->last_ctr += outl >> fp->shift;
    }

    return 0;
}

static void ssl_clear_encryption(hFILE_crypto *fp) {
    // Free the SSL related bits of hFILE_crypto
    if (fp->ctx) EVP_CIPHER_CTX_free(fp->ctx);
}

static ssize_t read_bytes(const char *name, int fd, uint8_t *buf, size_t len) {
    ssize_t got = 0;
    ssize_t res;
    do {
        do {
            res = read(fd, buf + got, len - got);
        } while (res < 0 && (errno == EINTR));
        if (res < 0) {
            if (hts_verbose > 1) {
                fprintf(stderr, "Error reading from %s : %s\n",
                        name, strerror(errno));
            }
            return -1;
        }
        got += res;
    } while (res > 0 && got < len);
    return got;
}

// FIXME: Not portable!
static int get_random_bytes(uint8_t *buf, size_t len) {
    int fd;
    ssize_t got = 0;
    const char *urandom = "/dev/urandom";

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        if (hts_verbose > 1) {
            fprintf(stderr, "Couldn't open %s : %s\n",
                    urandom, strerror(errno));
        }
        return -1;
    }
    got = read_bytes(urandom, fd, buf, len);
    close(fd); // Don't care if this fails, we've got the bytes.

    if (got < len) {
        if (hts_verbose > 1) {
            fprintf(stderr, "Failed to get enough randomness\n");
        }
        return -1;
    }

    return 0;
}

int sanity_check_recipient(const char *name) {
    const char *c = name;
    if (name == NULL) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] %s environment variable is not set\n",
                    __func__, RECIPIENT_ENV_VAR);
        errno = EINVAL;
        return -1;
    }
    while (*c && (isalnum(*c) || *c == '.' || *c == '@')) c++;
    if (*c) {
        if (hts_verbose > 1)
            fprintf(stderr,
                    "[E::%s] %s environment variable contains an illegal character\n",
                    __func__, RECIPIENT_ENV_VAR);
        errno = EINVAL;
        return -1;
    }
    if (c - name > 150) {
        if (hts_verbose > 1)
            fprintf(stderr,
                    "[E::%s] %s environment variable is too long\n",
                    __func__, RECIPIENT_ENV_VAR);
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static int write_to_backend(hFILE_crypto *fp, uint32_t skip, size_t len) {
    size_t done = 0;
    ssize_t n;

    while (done < len) {
        n = fp->parent->backend->write(fp->parent,
                                       fp->crypt_out + skip + done, len - done);
        if (n < 0) {
            fp->base.has_errno = errno;
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] Write failed: %s\n",
                        __func__, strerror(errno));
            return -1;
        }
        done += n;
        fp->parent->offset += n;
    }

    return 0;
}

static int write_encryption_header(hFILE_crypto *fp) {
    char cmd[256];
    uint8_t bytes[4 * sizeof(uint64_t) + sizeof(uint32_t)];
    char *recipient;
    FILE *tmp = NULL;
    FILE *gpg = NULL;
    off_t l;
    size_t i;
    int tmpfd;
    int r;
    int save_errno;
    
    recipient = getenv(RECIPIENT_ENV_VAR);
    if (sanity_check_recipient(recipient) != 0) return -1;

    tmp = tmpfile();
    if (tmp == NULL) {
        if (hts_verbose > 1)
            perror("Making temporary file : ");
        return -1;
    }

    // FIXME: Not portable!
    tmpfd = fileno(tmp);
    r = snprintf(cmd, sizeof(cmd), 
                 "/usr/bin/gpg --batch -r '%s' -e > /dev/fd/%d",
                 recipient, tmpfd);
    if (r < 0 || r >= sizeof(cmd)) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] gpg command line too long\n", __func__);
        goto fail;
    }

    gpg = popen(cmd, "w");
    if (gpg == NULL) {
        if (hts_verbose > 1)
            perror("Opening pipe to gpg : ");
        goto fail;
    }

    u32_to_le(fp->num_recs, bytes);
    if (fwrite(bytes, 4, 1, gpg) != 1) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Write to gpg failed: %s\n",
                    __func__, strerror(errno));
        goto fail;
    }

    for (i = 0; i < fp->num_recs; i++) {
        uint8_t *key, *iv;
        uint32_t keylen, ivlen;

        u64_to_le(fp->recs[i].plain_start,  &bytes[0]);
        u64_to_le(fp->recs[i].plain_end,    &bytes[8]);
        u64_to_le(fp->recs[i].cipher_start, &bytes[16]);
        i64_to_le(fp->recs[i].ctr_offset,   &bytes[24]);
        u32_to_le(fp->recs[i].method,       &bytes[32]);

        switch (fp->recs[i].method) {
          case AES_256_CTR:
            key = fp->recs[i].u.a256.key;
            keylen = sizeof(fp->recs[i].u.a256.key);
            iv = fp->recs[i].u.a256.iv;
            ivlen = sizeof(fp->recs[i].u.a256.iv);
            break;
          default:
            abort(); // Should never happen...
        }

        if (fwrite(bytes, 36, 1, gpg) != 1
            || fwrite(key, keylen, 1, gpg) != 1
            || fwrite(iv, ivlen, 1, gpg) != 1) {
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] Write to gpg failed: %s\n",
                        __func__, strerror(errno));
            goto fail;    
        }
    }
    r = pclose(gpg);
    gpg = NULL;
    if (r != 0) {
        if (hts_verbose > 1)
            fprintf(stderr, "Error running gpg.\n");
        goto fail;
    }

    l = lseek(tmpfd, 0, SEEK_END);
    if (l < 0) {
        if (hts_verbose > 1)
            perror("Seeking to end of temporary file : ");
        goto fail;
    }

    if (lseek(tmpfd, 0, SEEK_SET) < 0) {
        if (hts_verbose > 1)
            perror("Seeking to start of temporary file : ");
        goto fail;
    }

    memcpy(fp->crypt_out, MAGIC, 8);
    u32_to_le(PROTO_VERSION, fp->crypt_out + 8);
    u32_to_le(l + 16, fp->crypt_out + 12);
    if (write_to_backend(fp, 0, 16) != 0) goto fail;

    for (i = 0; i < l; i += CRYPTO_BUFFER_LENGTH) {
        size_t len = (l - i < CRYPTO_BUFFER_LENGTH
                      ? l - i : CRYPTO_BUFFER_LENGTH);
        ssize_t got = read_bytes("temporary file", tmpfd, fp->crypt_out, len);
        if (got < len) {
            if (hts_verbose > 1)
                fprintf(stderr, "Failed to read all of temporary file\n");
            goto fail;
        }
        if (write_to_backend(fp, 0, got) < 0) goto fail;
    }

    fclose(tmp); // Don't really care if this fails

    fp->real_data_start = l + 16;
    fp->base.offset = 0;

    return 0;

 fail:
    save_errno = errno;
    fclose(tmp);
    if (gpg) pclose(gpg);
    errno = save_errno;
    memset(bytes, 0, sizeof(bytes)); // Just in case
    return -1;
}

static int encryption_rec_compare(const void *va, const void *vb) {
    const Encryption_params *a = (const Encryption_params *) va;
    const Encryption_params *b = (const Encryption_params *) vb;

    if (a->plain_start < b->plain_start) return -1;
    if (a->plain_start > b->plain_start) return  1;
    return 0;
}

static int sanity_check_header(hFILE_crypto *fp) {
    uint32_t i;

    for (i = 0; i < fp->num_recs; i++) {
        if (fp->recs[i].plain_start > fp->recs[i].plain_end) {
            if (hts_verbose > 1)
                fprintf(stderr,
                        "[E::%s] Start after end in encryption header.\n",
                        __func__);
        }
        if (i > 0 && fp->recs[i].plain_start < fp->recs[i - 1].plain_end) {
            if (hts_verbose > 1)
                fprintf(stderr,
                        "[E::%s] Encryption header has overlapping records\n",
                        __func__);
            return -1;
        }
        if (fp->recs[i].ctr_offset < 0
            && -fp->recs[i].ctr_offset > fp->recs[i].plain_start) {
            if (hts_verbose > 1)
                fprintf(stderr,
                        "[E::%s] Invalid encryption header counter offset\n",
                        __func__);
            return -1;
        }
    }
    return 0;
}

static int read_encryption_header(hFILE_crypto *fp) {
    char cmd[256];
    uint8_t bytes[4096];
    FILE *tmp = NULL;
    FILE *gpg = NULL;
    uint64_t len;
    size_t i;
    int r, tmpfd, save_errno;

    if (hread(fp->parent, bytes, 16) != 16) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Failed to read encryption magic number\n",
                    __func__);
        goto fail;
    }
    if (memcmp(bytes, MAGIC, 8) != 0) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Incorrect magic number\n",
                    __func__);
        goto fail;
    }
    if (le_to_u32(&bytes[8]) > PROTO_VERSION) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Unsupported protocol version\n",
                    __func__);
        goto fail;
    }
    len = le_to_u32(&bytes[12]);
    if (len < 16) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Encryption data offset too small\n",
                    __func__);
        goto fail;
    }
    fp->real_data_start = len;
    len -= 16;

    tmp = tmpfile();
    if (tmp == NULL) {
        if (hts_verbose > 1) {
            perror("Making temporary file : ");
        }
        return -1;
    }

    tmpfd = fileno(tmp);
    
    for (i = 0; i < len; i += sizeof(bytes)) {
        size_t l = (len - i < sizeof(bytes) ? len - i : sizeof(bytes));
        ssize_t got = hread(fp->parent, bytes, l);
        if (got < l) {
            if (hts_verbose > 1)
                fprintf(stderr, "Failed to read all of encryption header\n");
            goto fail;
        }
        if (fwrite(bytes, 1, l, tmp) != l) {
            if (hts_verbose > 1)
                perror("Writing to temporary file");
            goto fail;
        }
    }
    if (fflush(tmp) != 0) {
        if (hts_verbose > 1)
            perror("Writing to temporary file");
        goto fail;
    }

    // FIXME: Not portable!
    r = snprintf(cmd, sizeof(cmd), "/usr/bin/gpg -d /dev/fd/%d", tmpfd);
    if (r < 0 || r >= sizeof(cmd)) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] gpg command too long\n",
                    __func__);
        goto fail;
    }

    gpg = popen(cmd, "r");
    if (!gpg) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Failed to open pipe to gpg : %s\n",
                    __func__, strerror(errno));
        goto fail;
    }
    if (fread(bytes, 4, 1, gpg) != 1) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Failed to read number of records\n",
                    __func__);
        goto fail;
    }
    fp->num_recs = le_to_u32(bytes);
    if (fp->num_recs == 0) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] No encryption records\n",
                    __func__);
        goto fail;
    }
    fp->recs = calloc(fp->num_recs, sizeof(fp->recs[0]));
    if (!fp->recs) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Allocating encryption records: %s\n",
                    __func__, strerror(errno));
        goto fail;
    }

    for (i = 0; i < fp->num_recs; i++) {
        uint8_t *key, *iv;
        uint32_t keylen, ivlen;

        if (fread(bytes, 36, 1, gpg) != 1) {
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] Failed to read encryption record\n",
                        __func__);
            goto fail;
        }
        fp->recs[i].plain_start  = le_to_u64(&bytes[0]);
        fp->recs[i].plain_end    = le_to_u64(&bytes[8]);
        fp->recs[i].cipher_start = le_to_u64(&bytes[16]);
        fp->recs[i].ctr_offset   = le_to_i64(&bytes[24]);
        fp->recs[i].method       = le_to_u32(&bytes[32]);

        switch (fp->recs[i].method) {
          case AES_256_CTR:
            key = fp->recs[i].u.a256.key;
            keylen = sizeof(fp->recs[i].u.a256.key);
            iv = fp->recs[i].u.a256.iv;
            ivlen = sizeof(fp->recs[i].u.a256.iv);
            break;
          default:
            if (hts_verbose > 1) 
                fprintf(stderr, "[E::%s] Invalid encryption type %u\n",
                        __func__, fp->recs[i].method);
            goto fail;
        }
        
        if (fread(key, keylen, 1, gpg) != 1
            || fread(iv, ivlen, 1, gpg) != 1) {
            if (hts_verbose > 1) 
                fprintf(stderr, "[E::%s] Failed to read encryption key/iv\n",
                        __func__);
            goto fail;
        }
    }


    r = pclose(gpg);
    gpg = NULL;
    if (r != 0) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Error running gpg.\n", __func__);
        goto fail;
    }

    // Ensure records are in plain-text order
    qsort(fp->recs, fp->num_recs, sizeof(fp->recs[0]),
          encryption_rec_compare);

    if (sanity_check_header(fp) != 0) goto fail;

    if (ssl_init_encryption(fp, 0) != 0) goto fail;

    fclose(tmp); // Don't really care if this fails

    fp->base.offset = 0;

    return 0;

 fail:
    save_errno = errno;
    if (tmp) fclose(tmp);
    if (gpg) pclose(gpg);
    errno = save_errno;
    return -1;
}

static int change_counter(hFILE_crypto *fp, uint64_t ctr) {
    // Openssl counter is big-endian
    int i, j;
    uint16_t sum = 0;

    assert(fp->key != NULL);
    assert(fp->iv  != NULL);

    for (i = 0, j = fp->ivlen - 1; i < sizeof(ctr); i++, --j) {
        sum = (sum >> 8) + ((ctr >> i*8) & 0xff) + fp->iv[j];
        fp->ctr[j] = sum & 0xff;
    }
    for (; j >= 0; --j) {
        sum = (sum >> 8) + fp->iv[j];
        fp->ctr[j] = sum & 0xff;
    }

    if (EVP_EncryptInit_ex(fp->ctx, NULL, NULL, fp->key, fp->ctr) != 1) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Failed to set encryption parameters\n",
                    __func__);
        dump_ssl_errors();
        errno = EIO;
        return -1;
    }

    fp->last_ctr = ctr;
    return 0;
}

static int find_encryption_record(hFILE_crypto *fp, off_t offset) {
    uint32_t start, end;

    if (offset >= fp->recs[fp->num_recs - 1].plain_start) {
        return fp->num_recs - 1;
    }

    start = 0;
    end = fp->num_recs - 1;

    while (start < end) {
        uint32_t mid = (start + end) / 2;
        if (fp->recs[mid].plain_start > offset) end = mid;
        if (fp->recs[mid].plain_end <= offset) start = mid + 1;
    }

    assert(start < fp->num_recs);
    return start;
}

static int change_encryption_block(hFILE_crypto *fp, off_t offset) {
    off_t parent_pos, cipher_pos;
    uint32_t recnum = find_encryption_record(fp, offset);

    if (recnum == fp->recnum) return 0;

    if (ssl_init_encryption(fp, recnum) != 0) return -1;

    parent_pos = htell(fp->parent);
    cipher_pos = ((offset >= fp->recs[fp->recnum].plain_start
                   ? offset - fp->recs[fp->recnum].plain_start : 0)
                  + fp->recs[fp->recnum].cipher_start
                  + fp->real_data_start);
    if (cipher_pos != parent_pos) {
        parent_pos = hseek(fp->parent, cipher_pos, SEEK_SET);
        if (parent_pos < 0) {
            if (hts_verbose > 1)
                fprintf(stderr,
                        "[E::%s] Couldn't seek to next encryption block: %s\n",
                        __func__, strerror(errno));
            return -1;
        }
    }

    return 0;
}

static ssize_t crypto_read_part(hFILE_crypto *fp, uint8_t *buf,
                                size_t nbytes, off_t offset) {
    ssize_t i = 0;
    uint64_t ctr;
    uint64_t mask = fp->blocklen - 1;
    uint32_t remainder;

    if (!fp->parent) {
        errno = EIO;
        return EOF;
    }

    ctr = (offset + fp->recs[fp->recnum].ctr_offset) >> fp->shift;
    if (ctr != fp->last_ctr) {
        if (change_counter(fp, ctr) != 0) return EOF;
    }

    while (i < nbytes) {
        size_t n;
        size_t m;
        ssize_t got;
        uint8_t *out;

        remainder = offset & mask;
        n = (nbytes - i < CRYPTO_BUFFER_LENGTH - remainder
             ? nbytes - i : CRYPTO_BUFFER_LENGTH - remainder);
        memset(fp->crypt_in, 0, remainder);
        got = hread(fp->parent, fp->crypt_in + remainder, n);
        if (got < 0) return EOF;
        if (got == 0) break;

        m = (fp->blocklen - ((got + remainder) & mask)) & mask;
        if (m == 0 && remainder == 0) {
            out = buf + i;
        } else {
            memset(fp->crypt_in + remainder + got, 0, m);
            out = fp->crypt_out;
        }
        if (ssl_decrypt_block(fp, out, got + remainder + m) != 0) return EOF;
        if (m != 0 || remainder != 0) {
            memcpy(buf + i, fp->crypt_out + remainder, got);
        }
        i += got;
        offset += got;
        if (got < n) break;
    }

    return i;
}

static ssize_t crypto_read(hFILE *fpv, void *buffer, size_t nbytes) {
    hFILE_crypto *fp = (hFILE_crypto *) fpv;
    uint8_t *buf = (uint8_t *) buffer;
    // Need to adjust fp->base.offset by the number of bytes already read
    // from the buffer to find the true file position
    off_t offset = fp->base.offset + (fp->base.end - fp->base.buffer);
    ssize_t i = 0;
    
    while (nbytes > 0) {
        ssize_t got;
        size_t to_get;

        if ((offset < fp->recs[fp->recnum].plain_start
             && fp->recnum > 0 && offset < fp->recs[fp->recnum].plain_end)
            || (offset >= fp->recs[fp->recnum].plain_end
                && fp->recnum < fp->num_recs - 1)) {
            if (change_encryption_block(fp, offset) != 0) return EOF;
        }

        if (offset < fp->recs[fp->recnum].plain_start) {
            offset = fp->recs[fp->recnum].plain_start;
        }

        if (fp->recnum < fp->num_recs - 1) {
            to_get = (offset + nbytes < fp->recs[fp->recnum].plain_end
                      ? nbytes
                      : fp->recs[fp->recnum].plain_end - offset);
        } else {
            to_get = nbytes;
        }

        if (to_get > 0) {
            got = crypto_read_part(fp, buf + i, to_get, offset);
            if (got < 0) return EOF;
            if (got == 0) break;
        } else {
            // This shouldn't (in theory) happen, but maybe there's a
            // zero length encryption block?  Assertion checks that
            // progress is still possible.
            assert(offset >= fp->recs[fp->recnum].plain_end);
            got = 0;
        }

        i += got;
        nbytes -= got;
        offset += got;
        if (got < to_get) break;
    }

    return i;
}

static ssize_t crypto_write(hFILE *fpv, const void *buffer, size_t nbytes) {
    hFILE_crypto *fp = (hFILE_crypto *) fpv;
    uint8_t *buf = (uint8_t *) buffer;
    uint64_t ctr, i = 0;
    uint64_t mask = fp->blocklen - 1;
    uint32_t remainder;

    if (!fp->parent) {
        errno = EIO;
        return EOF;
    }

    if (fp->recnum < fp->num_recs - 1
        || fp->base.offset < fp->recs[fp->recnum].plain_start) {
        if (hts_verbose > 1) {
            fprintf(stderr,
                    "[E::%s] Sorry, writing to fragmented encrypted files"
                    " is not supported\n", __func__);
            errno = ENOTSUP;
            return EOF;
        }
    }

    ctr = (fp->base.offset + fp->recs[fp->recnum].ctr_offset) >> fp->shift;
    if (ctr != fp->last_ctr) {
        if (change_counter(fp, ctr) != 0) return EOF;
    }
    remainder = fp->base.offset & mask;

    memset(fp->crypt_in, 0, remainder);
    while (i < nbytes) {
        uint8_t *in;
        size_t n = (nbytes - i < CRYPTO_BUFFER_LENGTH - remainder
                    ? nbytes - i : CRYPTO_BUFFER_LENGTH - remainder);
        size_t m = (fp->blocklen - ((n + remainder) & mask)) & mask;
        if (m == 0 && remainder == 0) {
            in = buf + i;
        } else {
            memcpy(fp->crypt_in + remainder, buf + i, n);
            memset(fp->crypt_in + remainder + n, 0, m);
            in = fp->crypt_in;
        }
        if (ssl_encrypt_block(fp, in, n + remainder + m) != 0) return EOF;
        if (write_to_backend(fp, remainder, n) != 0) return EOF;
        i += n;
        remainder = m;
    }

    return nbytes;
}

static off_t crypto_seek(hFILE *fpv, off_t offset, int whence) {
    hFILE_crypto *fp = (hFILE_crypto *) fpv;
    off_t pos;
    uint32_t recnum;

    switch (whence) {
      case SEEK_SET:
        break;
      case SEEK_CUR:
        pos = htell(&fp->base);
        if (pos + offset < 0) {
            fp->base.has_errno = errno = (offset < 0)? EINVAL : EOVERFLOW;
            return -1;
        }
        offset += pos;
        whence = SEEK_SET;
        break;
      case SEEK_END: {
          uint32_t rn = fp->num_recs - 1;
          // Find out how long the underlying file is
          pos = hseek(fp->parent, 0, SEEK_END);
          if (pos < 0) {
              if (hts_verbose > 1)
                  fprintf(stderr, "[E::%s] Seek failed : %s\n",
                          __func__, strerror(errno));
              return pos;
          }
          while (rn > 0 && pos < fp->recs[rn].cipher_start) --rn;
          // Convert to offset into block
          pos -= fp->recs[rn].cipher_start + fp->real_data_start;
          if (pos < 0) pos = 0;
          // Convert to plaintext position
          pos += fp->recs[rn].plain_start;
          if (pos > fp->recs[rn].plain_end) pos = fp->recs[rn].plain_end;
          // Get the absolute position
          offset += pos;
          whence = SEEK_SET;
          break;
      }
      default:
        errno = EINVAL;
        return -1;
    }

    recnum = find_encryption_record(fp, offset);
    if (recnum != fp->recnum) {
        if (ssl_init_encryption(fp, recnum) != 0) return -1;
    }

    if (offset < fp->recs[recnum].plain_start) {
        offset = fp->recs[recnum].plain_start;
    }

    // Convert to parent offset
    pos = (offset - fp->recs[recnum].plain_start
           + fp->recs[recnum].cipher_start + fp->real_data_start);
    
    pos = hseek(fp->parent, pos, whence);
    if (pos < 0) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Seek failed : %s\n",
                    __func__, strerror(errno));
        return pos;
    }
    if (pos < fp->real_data_start) {
        if (hts_verbose > 1)
            fprintf(stderr,
                    "[E::%s] Seek to before start of data in encrypted file\n",
                    __func__);
        errno = EIO;
        return -1;
    }

    fp->base.offset = offset;
    return offset;
}

static int crypto_flush(hFILE *fpv) {
    hFILE_crypto *fp = (hFILE_crypto *) fpv;

    if (!fp->parent) {
        errno = EIO;
        return EOF;
    }

    if (!fp->parent->backend->flush) return 0;

    return fp->parent->backend->flush(fp->parent);
}

static int crypto_close(hFILE *fpv) {
    hFILE_crypto *fp = (hFILE_crypto *) fpv;

    ssl_clear_encryption(fp);
    if (fp->parent) {
        if (hclose(fp->parent) < 0) return -1;
    }
    return 0;
}

static const struct hFILE_backend crypto_backend = {
    crypto_read, crypto_write, crypto_seek, crypto_flush, crypto_close
};

static inline void init_hfile_crypto(hFILE_crypto *fp) {
    fp->ctx = NULL;
    fp->key = fp->iv = NULL;
    fp->recs = NULL;
    fp->num_recs = 0;
    fp->recnum = UINT32_MAX;
    fp->last_ctr = 0;
    fp->keylen = fp->ivlen = fp->blocklen = fp->shift = 0;
    memset(fp->ctr, 0, sizeof(fp->ctr));
    memset(fp->crypt_in, 0, sizeof(fp->crypt_in));
    memset(fp->crypt_out, 0, sizeof(fp->crypt_out));
}

static hFILE *init_for_write(hFILE *hfile, const char *mode) {
    hFILE_crypto *fp;

    fp = (hFILE_crypto *) hfile_init(sizeof(hFILE_crypto), mode, 0);
    if (fp == NULL) return NULL;

    init_hfile_crypto(fp);
    fp->parent = hfile;

    fp->recs = calloc(1, sizeof(Encryption_params));
    if (!fp->recs) goto fail;
    fp->num_recs = 1;
    fp->recs[0].plain_start = 0;
    fp->recs[0].plain_end = UINT64_MAX;
    fp->recs[0].cipher_start = 0;
    fp->recs[0].ctr_offset = 0;
    fp->recs[0].method = AES_256_CTR;
    if (get_random_bytes(&fp->recs[0].u.a256.key[0], sizeof(fp->recs[0].u.a256))) {
        goto fail;
    }

    if (ssl_init_encryption(fp, 0)) goto fail;

    if (write_encryption_header(fp) != 0) goto fail;

    fp->base.backend = &crypto_backend;
    return &fp->base;

 fail:
    ssl_clear_encryption(fp);
    hfile_destroy((hFILE *) fp);
    return NULL;
}

static hFILE *init_for_read(hFILE *hfile, const char *mode) {
    hFILE_crypto *fp;

    fp = (hFILE_crypto *) hfile_init(sizeof(hFILE_crypto), mode, 0);
    if (fp == NULL) return NULL;

    init_hfile_crypto(fp);
    fp->parent = hfile;

    if (read_encryption_header(fp) != 0) goto fail;

    fp->base.backend = &crypto_backend;
    return &fp->base;

 fail:
    ssl_clear_encryption(fp);
    hfile_destroy((hFILE *) fp);
    return NULL;
}

static hFILE *hopen_crypto_wrapper(hFILE *hfile, const char *mode) {
    disclaimer();
    if (strchr(mode, 'r')) {
        return init_for_read(hfile, mode);
    } else {
        return init_for_write(hfile, mode);
    }
}

static hFILE *hopen_crypto(const char *url, const char *mode) {
    hFILE *parent = NULL;
    const char *scheme = "crypto:";
    size_t len = strlen(scheme);
    if (0 != strncmp(url, scheme, len)) {
        errno = ENOTSUP;
        return NULL;
    }

    if (strchr(mode, 'r') != NULL) {
        // There's a bad interaction with hopen's auto-detection in read mode.
        // We need to call it to open the parent, it detects the file is
        // and calls hopen_crypto_wrapper itself.  Best thing to do is
        // just rely on auto-detection and return the result.
        return hopen(url + len, mode);
    }

    parent = hopen(url + len, mode);
    if (!parent) return NULL;

    return hopen_crypto_wrapper(parent, mode);
}

static hFILE *vhopen_crypto(const char *url, const char *mode, va_list args) {
    return hopen_crypto(url, mode);
}

static void crypto_exit() {
    ERR_free_strings();
}

static int crypto_is_remote(const char *fname) {
    const char *scheme = "crypto:";
    size_t len = strlen(scheme);
    if (0 == strncmp(fname, scheme, len)) {
        return hisremote(fname + len);
    }
    return hisremote(fname); // FIXME: possible infinite recursion?
}

int PLUGIN_GLOBAL(hfile_plugin_init,_crypto)(struct hFILE_plugin *self) {
    static const struct hFILE_scheme_handler handler =
        { hopen_crypto, crypto_is_remote, "hfile_crypto",
          3000 + 50,
          vhopen_crypto, hopen_crypto_wrapper };

#ifdef ENABLE_PLUGINS
    // Embed version string for examination via strings(1) or what(1)
    static const char id[] = "@(#)hfile_crypto plugin (htslib)\t" HTS_VERSION;
    if (hts_verbose >= 9) {
        fprintf(stderr, "[M::hfile_crypto.init] version %s\n",
                strchr(id, '\t')+1);
    }
#endif

    ERR_load_crypto_strings();

    self->name = "hfile_crypto";
    self->destroy = crypto_exit;

    hfile_add_scheme_handler("crypto", &handler);
    return 0;
}
