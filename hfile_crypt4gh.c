/*  hfile_crypt4gh.c -- Encrypted file backend

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

#include <sodium.h>

#include "htslib/hts_endian.h"
#include "hts_internal.h"
#include "hfile_internal.h"
#include "crypto/sodium_if.h"
#include "crypto/keyfile.h"
#include "version.h"


#ifndef ENOTSUP
#define ENOTSUP EINVAL
#endif

#define CRYPTO_BLOCK_LENGTH 65536
#define CC20_P1305_BLOCK_LEN (CRYPTO_BLOCK_LENGTH + CC20_IV_LEN + P1305_MAC_LEN)
#define MAGIC "crypt4gh"

typedef enum {
    X25519_chacha20_ietf_poly1305 = 0
} headerCryptType;

typedef enum {
    chacha20_ietf_poly1305 = 0
} dataCryptType;

typedef struct {
    hFILE base;
    hFILE *parent;
    off_t real_data_start;
    uint8_t *crypt_in;
    uint8_t *crypt_out;
    uint8_t *key;
    uint8_t *iv;
    uint32_t crypt_buf_used;
    off_t curr_offset;
    dataCryptType type;
    int keylen;
    int ivlen;
    int blocklen;
    int shift;
} hFILE_crypt4gh;

static inline void increment_iv(uint8_t *iv, size_t iv_len) {
    size_t i;
    uint16_t c = 1;
    for (i = 0; i < iv_len; i++) {
        c += iv[i];
        iv[i] = c & 0xff;
        c >>= 8;
    }
}

static int write_to_backend(hFILE_crypt4gh *fp, size_t len) {
    size_t done = 0;
    ssize_t n;

    while (done < len) {
        n = fp->parent->backend->write(fp->parent,
                                       fp->crypt_out + done, len - done);
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

static inline size_t get_block_length(hFILE_crypt4gh *fp) {
    switch (fp->type) {
    case chacha20_ietf_poly1305: return CC20_P1305_BLOCK_LEN;
    default:                     return 0;
    }
}

static inline size_t get_iv_length(hFILE_crypt4gh *fp) {
    switch (fp->type) {
    case chacha20_ietf_poly1305: return CC20_IV_LEN;
    default:                     return 0;
    }
}

static inline size_t get_mac_length(hFILE_crypt4gh *fp) {
    switch (fp->type) {
    case chacha20_ietf_poly1305: return P1305_MAC_LEN;
    default:                     return 0;
    }
}


static int write_encryption_header(hFILE_crypt4gh *fp) {
    uint8_t writer_pk[X25519_PK_LEN];
    uint8_t reader_pk[X25519_PK_LEN] = { 0 };
    uint8_t header_key[X25519_SESSION_LEN];
    uint8_t header_iv[CC20_IV_LEN];
    uint8_t tmp[4 + CC20_KEY_LEN];
    uint8_t *p = fp->crypt_out;
    char *fname;
    size_t encrypt_len;
    uint32_t header_len;
    int retval = -1;

    assert(fp->keylen <= CC20_KEY_LEN);

    if ((fname = getenv("CRYPT4GH_PUBLIC")) != NULL) {
        if (read_key_file(fname, reader_pk, sizeof(reader_pk)) != 0) return -1;
    } else {
        fprintf(stderr, "[E::%s] CRYPT4GH_PUBLIC not set\n", __func__);
        return -1;
    }
    if (get_X25519_hdr_key_w(reader_pk, writer_pk, header_key) != 0) goto out;
    get_random_bytes(header_iv, CC20_IV_LEN);

    memcpy(p, MAGIC, 8); p += 8;
    u32_to_le(1, p); p += 4;
    p += 4; // Fill header length in later
    u32_to_le(X25519_chacha20_ietf_poly1305, p); p += 4;
    memcpy(p, writer_pk, X25519_PK_LEN); p += X25519_PK_LEN;
    memcpy(p, header_iv, CC20_IV_LEN); p += CC20_IV_LEN;

    u32_to_le(chacha20_ietf_poly1305, tmp);
    memcpy(tmp + 4, fp->key, fp->keylen);
    if (chacha20_encrypt(p, &encrypt_len, tmp, 4 + fp->keylen,
                         header_iv, header_key) != 0) {
        goto out;
    }
    assert(encrypt_len == 4 + CC20_KEY_LEN + P1305_MAC_LEN);
    header_len = 4 + X25519_PK_LEN + CC20_IV_LEN + encrypt_len;
    fp->real_data_start = header_len + 16;
    u32_to_le(header_len, fp->crypt_out + 12);

    if (write_to_backend(fp, header_len + 16) != 0) goto out;
    retval = 0;

 out:
    secure_zero(writer_pk, sizeof(writer_pk));
    secure_zero(header_key, sizeof(header_key));
    secure_zero(header_iv, sizeof(header_iv));
    secure_zero(tmp, sizeof(tmp));
    return retval;
}

static int read_encryption_header(hFILE_crypt4gh *fp) {
    uint8_t bytes[128], tmp[128], *p;
    uint8_t writer_pk[X25519_PK_LEN];
    uint8_t header_key[X25519_SESSION_LEN];
    uint8_t header_iv[CC20_IV_LEN];
    uint8_t reader_pk[X25519_PK_LEN] = { 0 };
    uint8_t reader_sk[X25519_SK_LEN] = { 0 };
    char *fname;
    uint32_t hdr_len;
    int retval = -1;
    size_t decrypt_len = 0;

    if ((fname = getenv("CRYPT4GH_SECRET")) != NULL) {
        if (read_key_file(fname, reader_sk, sizeof(reader_sk)) != 0) return -1;
    } else {
        fprintf(stderr, "[E::%s] CRYPT4GH_SECRET not set\n", __func__);
        return -1;
    }

    if (derive_X25519_public_key(reader_pk, reader_sk) != 0) {
        fprintf(stderr, "[E::%s] Couldn't derive public key\n", __func__);
        return -1;
    }

    if (hread(fp->parent, bytes, 16) != 16) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Failed to read encryption magic number\n",
                    __func__);
        return -1;
    }
    if (memcmp(bytes, MAGIC, 8) != 0) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Incorrect magic number\n",
                    __func__);
        return -1;
    }
    if (le_to_u32(bytes + 8) != 1) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Incorrect version number\n",
                    __func__);
        return -1;
    }
    hdr_len = le_to_u32(bytes + 12);
    if (hdr_len > sizeof(bytes)) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Encrypted header too long (%u bytes)\n",
                    __func__, (unsigned int) hdr_len);
        return -1;
    }
    if (hdr_len < 4 + X25519_PK_LEN + CC20_IV_LEN) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Encrypted header too short (%u bytes)\n",
                    __func__, (unsigned int) hdr_len);
        return -1;
    }
    fp->real_data_start = hdr_len + 16;

    if (hread(fp->parent, bytes, hdr_len) != hdr_len) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Failed to read encryption header\n",
                    __func__);
        return -1;
    }

    p = bytes;
    if (le_to_u32(bytes) != X25519_chacha20_ietf_poly1305) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Unsupported header encryption method\n",
                    __func__);
        return -1;
    }
    p += 4;

    memcpy(writer_pk, p, X25519_PK_LEN); p += X25519_PK_LEN;
    memcpy(header_iv, p, CC20_IV_LEN); p += CC20_IV_LEN;

    if (get_X25519_hdr_key_r(writer_pk, reader_pk, reader_sk, header_key) != 0) {
        goto out;
    }

    if (chacha20_decrypt(tmp, &decrypt_len, p,
                         hdr_len - 4 - X25519_PK_LEN - CC20_IV_LEN,
                         header_iv, header_key) != 0) {
        goto out;
    }
    if (decrypt_len < 4 + CC20_KEY_LEN) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Encrypted header too short\n",
                    __func__);
        goto out;
    }

    if (le_to_u32(tmp) != chacha20_ietf_poly1305) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Unsupported file encyption method\n",
                    __func__);
        goto out;
    }

    memcpy(fp->key, tmp + 4, CC20_KEY_LEN);
    retval = 0;

 out:
    secure_zero(reader_sk, sizeof(reader_sk));
    secure_zero(header_key, sizeof(header_key));
    secure_zero(header_iv, sizeof(header_iv));
    secure_zero(bytes, sizeof(bytes));
    secure_zero(tmp, sizeof(tmp));
    return retval;
}


static ssize_t crypt4gh_read(hFILE *fpv, void *buffer, size_t nbytes) {
    hFILE_crypt4gh *fp = (hFILE_crypt4gh *) fpv;
    ssize_t i = 0;
    uint8_t *buf = (uint8_t *) buffer;
    // Need to adjust fp->base.offset by the number of bytes already read
    // from the buffer to find the true file position
    off_t offset = fp->base.offset + (fp->base.end - fp->base.buffer);
    // Find out how much data is available in the current block
    off_t available = ((offset >= fp->curr_offset
                        && offset - fp->curr_offset < fp->crypt_buf_used)
                       ? fp->crypt_buf_used - (offset - fp->curr_offset)
                       : 0);
    ssize_t to_copy;
    size_t block_len = get_block_length(fp);
    size_t iv_len = get_iv_length(fp);
    size_t mac_len = get_mac_length(fp);
    size_t decrypt_len = 0;

    if (!fp->parent || !block_len || offset < fp->curr_offset) {
        errno = EIO;
        return EOF;
    }

    while (i < nbytes) {
        ssize_t got = block_len;

        // If no data available, read a new block and decrypt
        if (available == 0) {
            // If last block was short, must have hit EOF, in which case
            // don't try to read any more.
            if (fp->crypt_buf_used != 0
                && fp->crypt_buf_used != CRYPTO_BLOCK_LENGTH) {
                break;
            }

            fp->curr_offset += fp->crypt_buf_used;
            got = hread(fp->parent, fp->crypt_in, block_len);
            if (got < 0) return EOF; // Error
            if (got < iv_len + mac_len) break;  // At end of file
            if (chacha20_decrypt(fp->crypt_out, &decrypt_len,
                                 fp->crypt_in + iv_len, got - iv_len,
                                 fp->crypt_in, fp->key) != 0) {
                errno = EIO;
                return EOF;
            }
            assert(decrypt_len <= CRYPTO_BLOCK_LENGTH);
            fp->crypt_buf_used = decrypt_len;
            available = offset - fp->curr_offset < decrypt_len ? decrypt_len : 0;
        }

        // Copy available data to the output buffer
        to_copy = available;
        if (to_copy > nbytes - i) to_copy = nbytes - i;
        if (to_copy) {
            memcpy(buf + i,
                   fp->crypt_out + (offset - fp->curr_offset),
                   to_copy);
            i += to_copy;
            if (to_copy == available) available = 0;
        }

        // Stop if last read was short, as will be at end of file
        if (got < CRYPTO_BLOCK_LENGTH) break;
    }

    return i;
}

static ssize_t crypt4gh_write(hFILE *fpv, const void *buffer, size_t nbytes) {
    hFILE_crypt4gh *fp = (hFILE_crypt4gh *) fpv;
    uint8_t *buf = (uint8_t *) buffer;
    ssize_t bytes = 0;
    size_t iv_len = get_iv_length(fp);
    size_t encrypt_len = 0;

    if (!fp->parent) {
        errno = EIO;
        return EOF;
    }

    while (bytes < nbytes) {
        // Copy up to CRYPTO_BLOCK_LENGTH into fp->crypt_in
        size_t to_copy = CRYPTO_BLOCK_LENGTH - fp->crypt_buf_used;
        if (to_copy > nbytes - bytes) to_copy = nbytes - bytes;
        memcpy(fp->crypt_in + fp->crypt_buf_used, buf + bytes, to_copy);
        fp->crypt_buf_used += to_copy;
        bytes += to_copy;

        // If there's a full block, write it
        if (fp->crypt_buf_used == CRYPTO_BLOCK_LENGTH) {
            increment_iv(fp->iv, iv_len);
            memcpy(fp->crypt_out, fp->iv, iv_len);
            if (chacha20_encrypt(fp->crypt_out + iv_len, &encrypt_len,
                                 fp->crypt_in, CRYPTO_BLOCK_LENGTH,
                                 fp->iv, fp->key) != 0) {
                errno = EIO;
                return EOF;
            }
            if (write_to_backend(fp, encrypt_len + iv_len) != 0) return EOF;
            fp->crypt_buf_used = 0;
        }
    }

    return bytes;
}

static inline off_t get_encrypted_block_pos(hFILE_crypt4gh *fp, off_t pos) {
    if (pos < 0) return -1;
    switch (fp->type) {
    case chacha20_ietf_poly1305:
        return ((pos / CRYPTO_BLOCK_LENGTH) * CC20_P1305_BLOCK_LEN
                + fp->real_data_start);
    default:
        return -1;
    }
}

static inline off_t get_unencrypted_pos(hFILE_crypt4gh *fp, off_t pos, int at_end) {
    if (pos < fp->real_data_start) return -1;
    pos -= fp->real_data_start;
    switch (fp->type) {
    case chacha20_ietf_poly1305: {
        off_t block = pos / CC20_P1305_BLOCK_LEN;
        off_t remain = pos - block * CC20_P1305_BLOCK_LEN - CC20_IV_LEN;
        if (at_end) remain -= P1305_MAC_LEN;
        return (block * CRYPTO_BLOCK_LENGTH
                + (remain < 0
                   ? 0
                   : (remain < CRYPTO_BLOCK_LENGTH
                      ? remain
                      : CRYPTO_BLOCK_LENGTH)));
    }
    default:
        return -1;
    }
}

static off_t crypt4gh_seek(hFILE *fpv, off_t offset, int whence) {
    hFILE_crypt4gh *fp = (hFILE_crypt4gh *) fpv;
    off_t pos, block_pos = -1, unencrypted_pos;
    ssize_t got;
    size_t block_len, iv_len, mac_len, decrypt_len;

    if (!fp->base.readonly) {
        errno = ESPIPE;
        return -1;
    }

    switch (whence) {
    case SEEK_CUR: {
        off_t curr = fp->base.offset + (fp->base.end - fp->base.buffer);
        offset += curr;
        block_pos = get_encrypted_block_pos(fp, offset);
        break;
    }
    case SEEK_END: {
        // This is a bit inefficicent as we have to find where the end of
        // the underlying file is in order to work out the absolute offset
        off_t end = hseek(fp->parent, 0, SEEK_END);
        off_t unencrypted_end;
        if (end < 0) return end;
        if (offset > 0) offset = 0;
        unencrypted_end = get_unencrypted_pos(fp, end, 1);
        offset = unencrypted_end > -offset ? unencrypted_end + offset : -1;
    }
        // Fall through here
    case SEEK_SET:
        block_pos = get_encrypted_block_pos(fp, offset);
        break;
    default:
        break;
    }

    if (block_pos < 0) {
        errno = EINVAL;
        return -1;
    }

    pos = hseek(fp->parent, block_pos, SEEK_SET);
    if (pos < 0) return pos;

    // Work out where we actually ended up.
    unencrypted_pos = get_unencrypted_pos(fp, pos, pos < block_pos ? 1 : 0);
    if (unencrypted_pos < 0) {
        errno = EIO;
        return -1;
    }

    if (pos < block_pos) {
        // This should only happen when trying to seek past EOF.
        // If this is the case then unencrypted_pos should be the EOF position
        fp->crypt_buf_used = 0;
        fp->curr_offset = unencrypted_pos;
        return unencrypted_pos;
    }

    // Need to do a backend read here to find out how much data is available
    // This is necessary because we don't know if the next block is a short
    // one at the end of the file.

    block_len = get_block_length(fp);
    iv_len = get_iv_length(fp);
    mac_len = get_mac_length(fp);
    got = hread(fp->parent, fp->crypt_in, block_len);
    if (got < 0) return -1;
    if (got < iv_len + mac_len) got = 0;
    if (got) {
        if (chacha20_decrypt(fp->crypt_out, &decrypt_len,
                             fp->crypt_in + iv_len, got - iv_len,
                             fp->crypt_in, fp->key) != 0) {
            errno = EIO;
            return -1;
        }
    } else {
        decrypt_len = 0;
    }
    fp->crypt_buf_used = decrypt_len;
    fp->curr_offset = unencrypted_pos;
    fp->base.offset = offset < unencrypted_pos + decrypt_len ? offset : unencrypted_pos + decrypt_len;
    return fp->base.offset;
}

static int crypt4gh_flush(hFILE *fpv) {
    hFILE_crypt4gh *fp = (hFILE_crypt4gh *) fpv;

    if (!fp->parent) {
        errno = EIO;
        return EOF;
    }

    if (!fp->parent->backend->flush) return 0;

    return fp->parent->backend->flush(fp->parent);
}

static int crypt4gh_close(hFILE *fpv) {
    hFILE_crypt4gh *fp = (hFILE_crypt4gh *) fpv;
    int retval = 0;
    size_t iv_len = get_iv_length(fp);
    size_t encrypt_len = 0;

    // Encrypt and write any remaining data
    if (!fp->base.readonly && fp->crypt_buf_used > 0) {
        increment_iv(fp->iv, iv_len);
        memcpy(fp->crypt_out, fp->iv, iv_len);
        if (chacha20_encrypt(fp->crypt_out + iv_len, &encrypt_len,
                                 fp->crypt_in, fp->crypt_buf_used,
                                 fp->iv, fp->key) != 0) {
            retval = -1;
        }
        if (write_to_backend(fp, encrypt_len + iv_len) != 0) retval = -1;
    }

    if (fp->crypt_out) {
        secure_zero(fp->crypt_out, CRYPTO_BLOCK_LENGTH + CC20_P1305_BLOCK_LEN);
        free(fp->crypt_out);
    }
    if (fp->key) {
        secure_zero(fp->key, fp->keylen);
        free(fp->key);
    }
    if (fp->parent) {
        if (hclose(fp->parent) < 0) retval = -1;
    }
    return retval;
}

static const struct hFILE_backend crypt4gh_backend = {
    crypt4gh_read, crypt4gh_write, crypt4gh_seek, crypt4gh_flush, crypt4gh_close
};

static hFILE *init_for_write(hFILE *hfile, const char *mode) {
    hFILE_crypt4gh *fp;

    fp = (hFILE_crypt4gh *) hfile_init(sizeof(hFILE_crypt4gh), mode, 0);
    if (fp == NULL) return NULL;
    fp->base.backend = &crypt4gh_backend;

    fp->crypt_out = calloc(CC20_P1305_BLOCK_LEN + CRYPTO_BLOCK_LENGTH, 1);
    if (!fp->crypt_out) goto fail;
    fp->crypt_in = fp->crypt_out + CC20_P1305_BLOCK_LEN;
    fp->parent = hfile;
    fp->real_data_start = 0;
    fp->crypt_buf_used = 0;
    fp->curr_offset = 0;
    fp->type = chacha20_ietf_poly1305;
    fp->keylen = CC20_KEY_LEN;
    fp->ivlen = CC20_IV_LEN;
    fp->blocklen = 0;
    fp->shift = 0;
    fp->key = malloc(fp->keylen + fp->ivlen);
    if (!fp->key) goto fail;
    fp->iv = fp->key + fp->keylen;

    if (get_random_bytes(fp->key, fp->keylen + fp->ivlen)) {
        goto fail;
    }

    if (write_encryption_header(fp) != 0) goto fail;

    return &fp->base;

 fail:
    hfile_destroy((hFILE *) fp);
    return NULL;
}

static hFILE *init_for_read(hFILE *hfile, const char *mode) {
    hFILE_crypt4gh *fp;

    fp = (hFILE_crypt4gh *) hfile_init(sizeof(hFILE_crypt4gh), mode, 0);
    if (fp == NULL) return NULL;

    fp->crypt_out = calloc(CRYPTO_BLOCK_LENGTH + CC20_P1305_BLOCK_LEN, 1);
    if (!fp->crypt_out) goto fail;
    fp->crypt_in = fp->crypt_out + CRYPTO_BLOCK_LENGTH;
    fp->key = fp->iv = NULL;
    fp->parent = hfile;
    fp->real_data_start = 0;
    fp->crypt_buf_used = 0;
    fp->curr_offset = 0;
    fp->type = 0;
    fp->keylen = CC20_KEY_LEN;
    fp->ivlen = CC20_IV_LEN;
    fp->blocklen = 0;
    fp->shift = 0;

    fp->key = calloc(fp->keylen + fp->ivlen, 1);
    if (!fp->key) goto fail;
    fp->iv = fp->key + fp->keylen;

    if (read_encryption_header(fp) != 0) goto fail;

    fp->base.backend = &crypt4gh_backend;
    return &fp->base;

 fail:
    hfile_destroy((hFILE *) fp);
    return NULL;
}


static void disclaimer() {
    static int disclaimed = 0;
    if (disclaimed) return;
    fprintf(stderr,
            "WARNING:  hfile_crypt4gh is for EXPERIMENTAL use only.  The file "
            "format is liable\n"
            "to change.  Do not expect future versions to be able to read "
            "anything written\n"
            "by this one.   Files encrypted by this module should not "
            "be assumed secure.\n");
    disclaimed = 1;
}

static hFILE *hopen_crypt4gh_wrapper(hFILE *hfile, const char *mode) {
    disclaimer();
    if (strchr(mode, 'r')) {
        return init_for_read(hfile, mode);
    } else {
        return init_for_write(hfile, mode);
    }
}

static hFILE *hopen_crypt4gh(const char *url, const char *mode) {
    hFILE *parent = NULL;
    const char *scheme = "crypt4gh:";
    size_t len = strlen(scheme);
    if (0 != strncmp(url, scheme, len)) {
        errno = ENOTSUP;
        return NULL;
    }

    if (strchr(mode, 'r') != NULL) {
        // There's a bad interaction with hopen's auto-detection in read mode.
        // We need to call it to open the parent, it detects the file is
        // crypt4gh and calls vhopen_crypt4gh itself.  Best thing to do is
        // just rely on auto-detection and return the result.
        return hopen(url + len, mode);
    }

    parent = hopen(url + len, mode);
    if (!parent) return NULL;

    return hopen_crypt4gh_wrapper(parent, mode);
}

static hFILE *vhopen_crypt4gh(const char *url, const char *mode, va_list args) {
    const char *argtype;
    if ((argtype = va_arg(args, const char *)) != NULL) {
        if (strcmp(argtype, "parent") == 0) {
            hFILE *parent = va_arg(args, hFILE *);
            if (parent) {
                return hopen_crypt4gh_wrapper(parent, mode);
            }
        }
    }
    return hopen_crypt4gh(url, mode);
}

static void crypt4gh_exit() {
}

static int crypt4gh_is_remote(const char *fname) {
    const char *scheme = "crypt4gh:";
    size_t len = strlen(scheme);
    if (0 == strncmp(fname, scheme, len)) {
        return hisremote(fname + len);
    }
    return hisremote(fname); // FIXME: possible infinite recursion?
}

int PLUGIN_GLOBAL(hfile_plugin_init,_crypt4gh)(struct hFILE_plugin *self) {
    static const struct hFILE_scheme_handler handler =
        { hopen_crypt4gh, crypt4gh_is_remote, "hfile_crypt4gh",
          2000 + 50, vhopen_crypt4gh };

#ifdef ENABLE_PLUGINS
    // Embed version string for examination via strings(1) or what(1)
    static const char id[] = "@(#)hfile_crypt4gh plugin (htslib)\t" HTS_VERSION;
    if (hts_verbose >= 9) {
        fprintf(stderr, "[M::hfile_crypt4gh.init] version %s\n",
                strchr(id, '\t')+1);
    }
#endif

    self->name = "hfile_crypt4gh";
    self->destroy = crypt4gh_exit;

    hfile_add_scheme_handler("crypt4gh", &handler);
    return 0;
}
