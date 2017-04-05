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

#include "hts_internal.h"
#include "hfile_internal.h"
#include "version.h"

#ifndef ENOTSUP
#define ENOTSUP EINVAL
#endif

#define CRYPTO_BUFFER_LENGTH 65536
#define RECIPIENT_ENV_VAR "HTS_CRYPT_TO"
#define MAGIC "crypt4gh"

typedef enum {
    AES_256_CTR = 0,
    NUM_CRYPT_TYPES
} hCryptType;

typedef struct {
    hFILE base;
    hFILE *parent;
    off_t real_data_start;
    uint8_t *crypt_in;
    uint8_t *crypt_out;
    uint8_t *key;
    uint8_t *iv;
    EVP_CIPHER_CTX *ctx;
    uint64_t last_ctr;
    hCryptType type;
    int keylen;
    int ivlen;
    int blocklen;
    int shift;
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

static int ssl_init_encryption(hFILE_crypto *fp, hCryptType type) {
    const EVP_CIPHER *cipher = NULL;
    switch (type) {
    case AES_256_CTR: cipher = EVP_aes_256_ctr(); break;
    default: break;
    }

    if (cipher == NULL) {
        if (hts_verbose > 1)
            fprintf(stderr,
                    "[E::%s] Couldn't get cipher %d\n", __func__, type);
        if (type >= 0 && type < NUM_CRYPT_TYPES) dump_ssl_errors();
        errno = ENOTSUP;
        return -1;
    }

    fp->type = type;
    fp->key = NULL;
    fp->crypt_in = NULL;

    // Set up EVP context, find key, iv and block lengths
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
    fp->keylen   = EVP_CIPHER_CTX_key_length(fp->ctx);
    fp->ivlen    = EVP_CIPHER_CTX_iv_length(fp->ctx);
    //fp->blocklen = EVP_CIPHER_CTX_block_size(fp->ctx);
    fp->blocklen = fp->ivlen; // Why does the line above not work??
    assert(fp->ivlen >= 2 * sizeof(uint64_t));
    assert(fp->blocklen > 0 && fp->blocklen < 256);

    // Work out shift to convert file pos to counter value
    for (fp->shift = 0; (1 << fp->shift) < fp->blocklen; fp->shift++) {}
    assert((1 << fp->shift) == fp->blocklen);

    // Allocate space for key and iv
    fp->key = malloc(fp->keylen + fp->ivlen);
    if (fp->key == NULL) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Allocating keys: %s\n",
                    __func__, strerror(errno));
        goto fail;
    }
    fp->iv = fp->key + fp->keylen;

    // Allocate input and output buffers.  Must be longer than
    // CRYPTO_BUFFER_LENGTH to account for possible incomplete blocks due to
    // reads or writes not starting exactly on a block boundary
    fp->crypt_in = malloc(2 * (CRYPTO_BUFFER_LENGTH + 2 * fp->blocklen));
    if (fp->crypt_in == NULL) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Allocating buffers: %s\n",
                    __func__, strerror(errno));
        goto fail;
    }
    fp->crypt_out = fp->crypt_in + CRYPTO_BUFFER_LENGTH + 2 * fp->blocklen;

    fp->last_ctr = 0xffffffffffffffffULL;
 
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
    free(fp->key);
    free(fp->crypt_in);
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
    uint8_t bytes[16];
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

    bytes[0] = fp->type;
    memset(bytes + 1, 0, 3);
    if (fwrite(bytes, 4, 1, gpg) != 1
        || fwrite(fp->key, fp->keylen, 1, gpg) != 1
        || fwrite(fp->iv, fp->ivlen, 1, gpg) != 1) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Write to gpg failed: %s\n",
                    __func__, strerror(errno));
        goto fail;
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
    for (i = 0; i < 8; i++) {
        fp->crypt_out[i + 8] = ((l + 16) >> i*8) & 0xff;
    }
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

static int read_encryption_header(hFILE_crypto *fp) {
    char cmd[256];
    uint8_t bytes[4096];
    FILE *tmp = NULL;
    FILE *gpg = NULL;
    uint64_t len;
    uint32_t crypt_type;
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
    for (len = 0, i = 0; i < 8; i++) {
        len |= ((uint64_t) bytes[8 + i]) << 8*i;
    }
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
            fprintf(stderr, "[E::%s] Failed to read encryption type\n",
                    __func__);
        goto fail;
    }
    crypt_type = bytes[0] | (bytes[1]<<8) | (bytes[2]<<16) | (bytes[3]<<24);
    if (ssl_init_encryption(fp, crypt_type) != 0) goto fail;
    if (fread(fp->key, fp->keylen, 1, gpg) != 1
        || fread(fp->iv, fp->ivlen, 1, gpg) != 1) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Failed to get encryption key\n",
                    __func__);
        goto fail;
    }
    r = pclose(gpg);
    gpg = NULL;
    if (r != 0) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Error running gpg.\n", __func__);
        goto fail;
    }

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
    int i;
    for (i = sizeof(ctr); i > 0; --i) {
        fp->iv[fp->ivlen - i] = (ctr >> (i - 1)*8) & 0xff;
    }

    if (EVP_EncryptInit_ex(fp->ctx, NULL, NULL, fp->key, fp->iv) != 1) {
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

static ssize_t crypto_read(hFILE *fpv, void *buffer, size_t nbytes) {
    hFILE_crypto *fp = (hFILE_crypto *) fpv;
    uint8_t *buf = (uint8_t *) buffer;
    ssize_t i = 0;
    uint64_t ctr;
    uint64_t mask = fp->blocklen - 1;
    // Need to adjust fp->base.offset by the number of bytes already read
    // from the buffer to find the true file position
    off_t offset = fp->base.offset + (fp->base.end - fp->base.buffer);
    uint32_t remainder;

    if (!fp->parent) {
        errno = EIO;
        return EOF;
    }

    ctr = offset >> fp->shift;
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

    ctr = fp->base.offset >> fp->shift;
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

    if (whence == SEEK_SET) {
        offset += fp->real_data_start;
    }
    pos = hseek(fp->parent, offset, whence);
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
    pos -= fp->real_data_start;
    fp->base.offset = pos;
    return pos;
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

static hFILE *init_for_write(hFILE *hfile, const char *mode) {
    hFILE_crypto *fp;

    fp = (hFILE_crypto *) hfile_init(sizeof(hFILE_crypto), mode, 0);
    if (fp == NULL) return NULL;

    fp->crypt_in = fp->crypt_out = NULL;
    fp->key = fp->iv = NULL;
    fp->ctx = NULL;
    fp->parent = hfile;

    if (ssl_init_encryption(fp, AES_256_CTR)) goto fail;
    if (get_random_bytes(fp->key, fp->keylen + fp->ivlen - sizeof(uint64_t))) {
        goto fail;
    }
    memset(fp->iv + fp->ivlen - sizeof(uint64_t), 0, sizeof(uint64_t));

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

    fp->crypt_in = fp->crypt_out = NULL;
    fp->key = fp->iv = NULL;
    fp->ctx = NULL;
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

int hfile_plugin_init(struct hFILE_plugin *self) {
    static const struct hFILE_scheme_handler handler =
        { hopen_crypto, crypto_is_remote, "hfile_crypto",
          3000 + 50,
          vhopen_crypto, hopen_crypto_wrapper };
    // Embed version string for examination via strings(1) or what(1)
    static const char id[] = "@(#)hfile_crypto plugin (htslib)\t" HTS_VERSION;
    const char *version = strchr(id, '\t')+1;

    ERR_load_crypto_strings();

    self->name = "hfile_crypto";
    self->destroy = crypto_exit;

    hfile_add_scheme_handler("crypto", &handler);
    return 0;
}
