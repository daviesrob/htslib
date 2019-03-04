/*  crypt4gh_agent.c -- HTSlib crypt4gh agent

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
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <getopt.h>

#include "crypt4gh_agent_defs.h"
#include "sodium_if.h"
#include "keyfile.h"
#include <htslib/hts_endian.h>

#define C4GH_AGENT_ENV_VAR "CRYPT4GH_AGENT"
#define DEV_NULL "/dev/null"

typedef enum {
    X25519_chacha20_ietf_poly1305 = 0
} headerCryptType;

typedef enum {
    chacha20_ietf_poly1305 = 0
} dataCryptType;

typedef enum {
    curve25519_public = 1,
    curve25519_secret
} Key_type;

typedef struct Key_info {
    Key_type type;
    const uint8_t *key;
    const char    *name;
} Key_info;

typedef struct Agent_settings {
    const char *sock_dir;
    const char *sock_path;
    int socket_fd;
    int chld_fd[2];
    int chld_pid;
    size_t nkeys;
    Key_info *keys;
} Agent_settings;

#define INIT_AGENT_SETTINGS { NULL, NULL, -1, { -1, -1 }, -1, 0, NULL }

typedef enum {
    cs_waiting_peer_pk = 0,
    cs_run_session
} Client_state;

typedef struct Client {
    uint8_t rb[512];
    uint8_t wb[512];
    uint16_t rb_in;
    uint16_t wb_out;
    int fd;
    Client_state state;
    struct Client *prev;
    struct Client *next;
    uint8_t pk[X25519_PK_LEN];
    uint8_t sk[X25519_SK_LEN];
    uint8_t rx[X25519_SESSION_LEN];
    uint8_t tx[X25519_SESSION_LEN];
    uint8_t txiv[CC20_IV_LEN];
} Client;

// How much write buffer to have available before accepting a message
// Must be bigger than highest of:
//     4 + X25519_PK_LEN
//     4 + CC20_IV_LEN + CC20_KEY_LEN + P1305_MAC_LEN
#define MIN_WB_AVAIL (4 + CC20_IV_LEN + CC20_KEY_LEN + P1305_MAC_LEN + 16)

static int sig_chld_fd;
static void chld_sig_handler(int sig) {
    char c = 0x55;
    ssize_t r;
    do {
        r = write(sig_chld_fd, &c, sizeof(c));
    } while (r < 0 && errno == EINTR);
}

static int try_sock_dir_var_run(char *path, size_t path_len) {
    pid_t pid = getpid();
    struct stat st;
    snprintf(path, path_len, "/var/run/user/%d", (int) pid);
    if (lstat(path, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) return -1;
    snprintf(path, path_len, "/var/run/user/%d/crypt4gh", (int) pid);
    if (mkdir(path, S_IRWXU) != 0 && errno != EEXIST) return -1;
    if (lstat(path, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) return -1;
    if ((st.st_mode & S_IRWXU) != S_IRWXU) return -1;
    return 0;
}

static int try_sock_dir_tmp(char *path, size_t path_len) {
    char *p;
    snprintf(path, path_len, "/tmp/XXXXXX");
    p = mkdtemp(path);
    if (!p) return -1;
    return 0;
}

int get_sock_dir(char *path, size_t path_len) {
    if (try_sock_dir_var_run(path, path_len) == 0) return 0;
    if (try_sock_dir_tmp(path, path_len) == 0) return 0;
    fprintf(stderr, "Couldn't make socket directory\n");
    return -1;
}

int open_socket(Agent_settings *settings) {
    struct sockaddr_un addr;
    struct timeval tv;
    char *sock_dir = NULL, *sock_path = NULL;
    uint32_t ctr = 0, tries = 0, res;
    mode_t old_mask = umask(077);
    const uint32_t MAX_TRIES = 128;
    const size_t sock_dir_len = sizeof(addr.sun_path) - 9;
    const size_t sock_path_len = sizeof(addr.sun_path);

    sock_dir = calloc(sock_dir_len, 1);
    if (!sock_dir) goto fail;
    sock_path = calloc(sock_path_len, 1);
    if (!sock_path) goto fail;

    if (get_sock_dir(sock_dir, sock_dir_len) != 0)
        return -1;

    settings->socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (settings->socket_fd == -1) {
        perror("socket");
        goto fail;
    }

    gettimeofday(&tv, NULL);
    ctr = tv.tv_sec ^ tv.tv_usec ^ (tv.tv_usec << 12) ^ getpid();
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    for (tries = 0; tries < MAX_TRIES; tries++, ctr++) {
        size_t l = snprintf(sock_path, sock_path_len, "%s/%08x", sock_dir, ctr);
        memcpy(&addr.sun_path, sock_path, l + 1);
        res = bind(settings->socket_fd,
                   (const struct sockaddr *) &addr, sizeof(addr));
        if (res == 0) break;
        if (errno != EADDRINUSE) {
            perror("bind");
            goto fail;
        }
    }
    if (tries == MAX_TRIES) {
        fprintf(stderr, "Failed to get a unique socket name\n");
        goto fail;
    }

    if (listen(settings->socket_fd, SOMAXCONN) != 0) {
        perror("listen");
        goto fail;
    }

    if (setenv(C4GH_AGENT_ENV_VAR, sock_path, 1) != 0) {
        perror("setenv");
        unlink(sock_path);
        goto fail;
    }
    umask(old_mask);
    settings->sock_path = sock_path;
    settings->sock_dir = sock_dir;
    return 0;

 fail:
    if (settings->socket_fd >= 0) close(settings->socket_fd);
    settings->socket_fd = -1;
    free(sock_path);
    if (sock_dir) {
        rmdir(sock_dir);
        free(sock_dir);
    }
    umask(old_mask);
    return -1;
}

void cleanup(Agent_settings *settings) {
    if (settings->socket_fd >= 0) close(settings->socket_fd);
    if (settings->chld_fd[0] >= 0) close(settings->chld_fd[0]);
    if (settings->chld_fd[1] >= 0) close(settings->chld_fd[1]);
    if (settings->sock_path) {
        unlink(settings->sock_path);
        free((char *) settings->sock_path);
    }
    if (settings->sock_dir) {
        rmdir(settings->sock_dir);
        free((char *) settings->sock_dir);
    }
}

static char * get_user_shell() {
    uid_t uid = getuid();
    struct passwd *pw = NULL;
    char *shell = NULL;

    if (uid == 0) {
        fprintf(stderr, "This program should not by run as root\n");
        return NULL;
    }
    pw = getpwuid(uid);
    if (!pw || !pw->pw_shell) {
        fprintf(stderr, "Couldn't get shell for uid %ld\n", (long) uid);
        return NULL;
    }
    shell = strdup(pw->pw_shell);
    if (!shell) {
        perror(NULL);
        return NULL;
    }
    return shell;
}

static int install_sig_handler(Agent_settings *settings) {
    struct sigaction sa;

    sig_chld_fd = settings->chld_fd[1];
    sa.sa_flags = SA_NOCLDSTOP;
    sa.sa_handler = chld_sig_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction(SIGCHLD)");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction(SIGPIPE)");
        return -1;
    }

    return 0;
}

static int run_prog(Agent_settings *settings, int argc, char **argv) {
    char *uargv[2] = { NULL, NULL };
    pid_t pid;

    if (argc == 0) {
        uargv[0] = get_user_shell();
        argv = uargv;
        argc = 1;
    }
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) { /* Child */
        close(settings->socket_fd);
        close(settings->chld_fd[0]);
        close(settings->chld_fd[1]);
        execvp(argv[0], argv);
        exit(EXIT_FAILURE);
    }
    /* Parent */
    settings->chld_pid = pid;
    return 0;
}

static int handle_connection(Agent_settings *settings, Client **clients) {
    struct sockaddr_un peer;
    socklen_t peer_sz = sizeof(peer);
    int new_fd = accept(settings->socket_fd,(struct sockaddr *) &peer, &peer_sz);
    Client *client = NULL;

    if (new_fd < 0) {
        if (errno == EAGAIN) return 0;
        if (errno == EWOULDBLOCK) return 0;
        if (errno == ECONNABORTED) return 0;
        if (errno == EINTR) return 0;
        return -1;
    }
    fprintf(stderr, "Got connection on fd %d\n", new_fd);
    client = calloc(1, sizeof(Client));
    if (!client) {
        close(new_fd);
        return 0;
    }
    if (get_X25519_keypair(client->pk, client->sk) != 0) {
        close(new_fd);
        free(client);
        return 0;
    }
    if (get_random_bytes(client->txiv, sizeof(client->txiv)) != 0) {
        close(new_fd);
        free(client);
        return 0;
    }
    client->fd = new_fd;
    client->state = cs_waiting_peer_pk;

    u32_to_le(X25519_PK_LEN + 4, client->wb);
    u16_to_le(c4gh_msg_connect, client->wb + 4);
    u16_to_le(c4gh_proto_v_1, client->wb + 6);
    memcpy(client->wb + 8, client->pk, X25519_PK_LEN);
    client->wb_out = 8 + X25519_PK_LEN;
    client->next = *clients;
    client->prev = NULL;
    if (client->next) client->next->prev = client;
    *clients = client;
    return 0;
}

static int handle_connect_message(Client *c, uint32_t msg_len) {
    if (msg_len < 4 + X25519_PK_LEN) return -1;
    if (le_to_u16(&c->rb[4]) != c4gh_msg_connect) return -1;
    if (le_to_u16(&c->rb[6]) != c4gh_proto_v_1) return -1;
    if (get_X25519_server_session_keys(c->rx, c->tx, c->pk, c->sk,
                                       &c->rb[8]) != 0) {
        return -1;
    }
    secure_zero(c->sk, sizeof(c->sk));
    secure_zero(c->pk, sizeof(c->pk));
    return 0;
}

static int handle_header_decrypt(Agent_settings *settings, Client *c,
                                 uint8_t *msg, size_t msg_len) {
    char *name;
    uint16_t name_len;
    uint8_t *hdr, *writer_pk, *header_iv, *encrypted;
    size_t hdr_len;
    size_t key, decrypt_len = 0, encrypt_len;
    uint8_t reader_pk[X25519_PK_LEN];
    uint8_t header_key[X25519_SESSION_LEN];
    uint8_t decrypt[256];

    if (msg_len < 4) return -1;
    assert(le_to_u16(msg) == c4gh_msg_hdr_decrypt);
    name_len = le_to_u16(msg + 2);
    name = (char *) msg + 4;
    if (name_len < 1 || name[name_len - 1] != '\0') return -1;

    hdr_len = msg_len - name_len - 4;
    if (hdr_len < X25519_PK_LEN + CC20_IV_LEN + 4 + P1305_MAC_LEN) return -1;
    hdr = msg + 4 + name_len;

    if (le_to_u32(hdr) != X25519_chacha20_ietf_poly1305) return -1;
    writer_pk = hdr + 4;
    header_iv = hdr + 4 + X25519_PK_LEN;
    encrypted = hdr + 4 + X25519_PK_LEN + CC20_IV_LEN;
    if (hdr_len - (encrypted - hdr) - P1305_MAC_LEN > sizeof(decrypt) - 2)
        return -1;

    u16_to_le(c4gh_msg_hdr_decrypt, decrypt);

    for (key = 0; key < settings->nkeys; key++) {
        if (*name && strcmp(name, settings->keys[key].name) != 0) continue;
        if (settings->keys[key].type != curve25519_secret) continue;
        if (derive_X25519_public_key(reader_pk, settings->keys[key].key) != 0)
            continue;
        if (get_X25519_hdr_key_r(writer_pk, reader_pk,
                                 settings->keys[key].key, header_key) != 0)
            continue;
        if (chacha20_decrypt(decrypt + 2, &decrypt_len, encrypted,
                             hdr_len - (encrypted - hdr),
                             header_iv, header_key) == 0) {
            break;
        }
    }
    secure_zero(header_key, sizeof(header_key));
    if (key >= settings->nkeys) return -1;
    if (decrypt_len < 4 + CC20_KEY_LEN) goto fail;
    if (le_to_u32(decrypt + 2) != chacha20_ietf_poly1305) goto fail;
    assert(6 + sizeof(c->txiv) + CC20_KEY_LEN + P1305_MAC_LEN
           < sizeof(c->wb) - c->wb_out);
    memcpy(c->wb + c->wb_out + 4, c->txiv, sizeof(c->txiv));
    if (chacha20_encrypt(c->wb + c->wb_out + 4 + sizeof(c->txiv), &encrypt_len,
                         decrypt, CC20_KEY_LEN + 6,
                         c->txiv, c->tx) != 0) {
        goto fail;
    }
    constant_time_increment(c->txiv, sizeof(c->txiv));
    assert(encrypt_len == CC20_KEY_LEN + 6 + P1305_MAC_LEN);
    encrypt_len += sizeof(c->txiv);
    u32_to_le(encrypt_len, c->wb + c->wb_out);
    c->wb_out += 4 + encrypt_len;

    secure_zero(decrypt, sizeof(decrypt));
    return 0;
 fail:
    secure_zero(decrypt, sizeof(decrypt));
    return -1;
}

static int handle_header_encrypt(Agent_settings *settings, Client *c,
                                 uint8_t *msg, size_t msg_len) {
    char *name;
    uint16_t name_len;
    uint32_t hdr_version, hdr_encryption, data_encryption;
    uint8_t writer_pk[X25519_PK_LEN];
    uint8_t header_key[X25519_SESSION_LEN];
    uint8_t header_iv[CC20_IV_LEN];
    uint8_t *data_key;
    uint8_t tmp[4 + CC20_KEY_LEN];
    uint8_t decrypt[256], *p = decrypt;
    size_t key, encrypt_len;

    if (msg_len < 4) return -1;
    assert(le_to_u16(msg) == c4gh_msg_hdr_encrypt);
    name_len = le_to_u16(msg + 2);

    name = (char *) msg + 4;
    if (name_len < 1 || name[name_len - 1] != '\0') return -1;

    if (msg_len < 4 + name_len + 12 + CC20_KEY_LEN) return -1;
    hdr_version     = le_to_u32(msg + name_len + 4);
    hdr_encryption  = le_to_u32(msg + name_len + 8);
    data_encryption = le_to_u32(msg + name_len + 12);
    data_key = msg + name_len + 16;

    if (hdr_version != 1 || hdr_encryption != 0 || data_encryption != 0)
        return -1;

    for (key = 0; key < settings->nkeys; key++) {
        if (*name && strcmp(name, settings->keys[key].name) != 0) continue;
        if (settings->keys[key].type != curve25519_public) continue;
        if (get_X25519_hdr_key_w(settings->keys[key].key,
                                 writer_pk, header_key) != 0) continue;
        break;
    }
    if (key >= settings->nkeys) return -1;
    get_random_bytes(header_iv, sizeof(header_iv));

    assert(6 + sizeof(writer_pk) + sizeof(header_iv)
           + 4 + CC20_KEY_LEN + P1305_MAC_LEN < sizeof(decrypt));

    u16_to_le(c4gh_msg_hdr_encrypt, p); p += 2;
    u32_to_le(0, p); p += 4;
    memcpy(p, writer_pk, sizeof(writer_pk)); p += sizeof(writer_pk);
    memcpy(p, header_iv, sizeof(header_iv)); p += sizeof(header_iv);

    u32_to_le(0, tmp);
    memcpy(tmp + 4, data_key, CC20_KEY_LEN);

    if (chacha20_encrypt(p, &encrypt_len, tmp, 4 + CC20_KEY_LEN,
                         header_iv, header_key) != 0) {
        goto fail;
    }
    assert(encrypt_len == 4 + CC20_KEY_LEN + P1305_MAC_LEN);
    p += encrypt_len;

    assert(p - decrypt + 4 < sizeof(c->wb) - c->wb_out);

    memcpy(c->wb + c->wb_out + 4, c->txiv, sizeof(c->txiv));
    if (chacha20_encrypt(c->wb + c->wb_out + 4 + sizeof(c->txiv), &encrypt_len,
                         decrypt, p - decrypt, c->txiv, c->tx) != 0) {
        goto fail;
    }
    constant_time_increment(c->txiv, sizeof(c->txiv));
    encrypt_len += sizeof(c->txiv);
    u32_to_le(encrypt_len, c->wb + c->wb_out);
    c->wb_out += 4 + encrypt_len;

    secure_zero(decrypt, sizeof(decrypt));
    secure_zero(writer_pk, sizeof(writer_pk));
    secure_zero(header_key, sizeof(header_key));
    secure_zero(header_iv, sizeof(header_iv));
    secure_zero(tmp, sizeof(tmp));
    return 0;
 fail:
    secure_zero(decrypt, sizeof(decrypt));
    secure_zero(writer_pk, sizeof(writer_pk));
    secure_zero(header_key, sizeof(header_key));
    secure_zero(header_iv, sizeof(header_iv));
    secure_zero(tmp, sizeof(tmp));
    return -1;
}

static int decrypt_and_process_message(Agent_settings *settings,
                                       Client *c, uint32_t msg_len) {
    uint8_t decrypted[256];
    size_t decrypted_len = 0;
    if (msg_len > sizeof(decrypted) + CC20_IV_LEN + P1305_MAC_LEN) return -1;
    if (msg_len < CC20_IV_LEN + P1305_MAC_LEN) return -1;
    if (chacha20_decrypt(decrypted, &decrypted_len,
                         c->rb + 4 + CC20_IV_LEN, msg_len - CC20_IV_LEN,
                         c->rb + 4, c->rx) != 0) {
        return -1;
    }
    if (decrypted_len < 2) return -1;
    switch (le_to_u16(decrypted)) {
    case c4gh_msg_hdr_decrypt:
        if (handle_header_decrypt(settings, c, decrypted, decrypted_len) != 0)
            goto fail;
        break;
    case c4gh_msg_hdr_encrypt:
        if (handle_header_encrypt(settings, c, decrypted, decrypted_len) != 0)
            goto fail;
        break;
    default:
        goto fail;
    }
    secure_zero(decrypted, decrypted_len);
    return 0;
 fail:
    secure_zero(decrypted, decrypted_len);
    return -1;
}

static int process_message(Agent_settings *settings,
                           Client *c, uint32_t msg_len) {
    assert(msg_len < UINT16_MAX);
    if (msg_len < 1) return -1;
    switch (c->state) {
    case cs_waiting_peer_pk:
        if (handle_connect_message(c, msg_len) != 0) return -1;
        c->state = cs_run_session;
        break;
    case cs_run_session:
        if (decrypt_and_process_message(settings, c, msg_len) != 0) return -1;
        break;
    default:
        return -1;
    }
    return 0;
}

static int do_client_write(Client *c) {
    ssize_t bytes;
    if (c->wb_out == 0) return 0;
    bytes = write(c->fd, c->wb, c->wb_out);
    if (bytes < 0) {
        if (errno == EAGAIN)      return 0;
        if (errno == EWOULDBLOCK) return 0;
        if (errno == EINTR)       return 0;
        return -1;
    }
    if (bytes < c->wb_out)
        memmove(c->wb, c->wb + bytes, c->wb_out - bytes);
    c->wb_out -= bytes;
    return 0;
}

static int do_client_read(Agent_settings *settings, Client *c) {
    ssize_t bytes = recv(c->fd, c->rb, sizeof(c->rb) - c->rb_in, 0);

    if (bytes < 0) {
        if (errno == EAGAIN)      return 0;
        if (errno == EWOULDBLOCK) return 0;
        if (errno == EINTR)       return 0;
        return -1;
    }
    if (bytes == 0) return -1;
    c->rb_in += bytes;
    if (c->rb_in > 4) {
        uint32_t msg_len = le_to_u32(c->rb);
        if (msg_len > sizeof(c->rb) - 4) return -1;
        if (c->rb_in - 4 >= msg_len) {
            if (process_message(settings, c, msg_len) < 0) return -1;
            if (c->rb_in - 4 > msg_len)
                memmove(c->rb, c->rb + 4 + msg_len, c->rb_in - 4 - msg_len);
            c->rb_in -= 4 + msg_len;
        }
    }
    return 0;
}

static inline int max_fd(int fd1, int fd2) {
    return fd1 > fd2 ? fd1 : fd2;
}

static int run_server(Agent_settings *settings) {
    int res = 0;
    int null_fd, status = 0;
    Client *clients = NULL;

    null_fd = open(DEV_NULL, O_RDWR, 0);
    if (!null_fd) {
        fprintf(stderr, "Couldn't open \"%s\" : %s\n",
                DEV_NULL, strerror(errno));
        return -1;
    }
    chdir("/");
    dup2(null_fd, STDIN_FILENO);
    dup2(null_fd, STDOUT_FILENO);
    // dup2(null_fd, STDERR_FILENO);
    if (null_fd > STDERR_FILENO) close(null_fd);
    for (;;) {
        int nfds;
        fd_set rd, wr, er;
        Client *c;
        FD_ZERO(&rd);
        FD_ZERO(&wr);
        FD_ZERO(&er);
        FD_SET(settings->socket_fd, &rd);
        FD_SET(settings->chld_fd[0], &rd);
        nfds = max_fd(settings->socket_fd, settings->chld_fd[0]);
        for (c = clients; c != NULL; c = c->next) {
            if (sizeof(c->wb) - c->wb_out > MIN_WB_AVAIL) FD_SET(c->fd, &rd);
            if (c->wb_out) FD_SET(c->fd, &wr);
            nfds = max_fd(nfds, c->fd);
        }
        res = select(nfds + 1, &rd, &wr, &er, NULL);
        if (res == -1 && errno == EINTR) continue;
        if (res == -1) break;
        if (FD_ISSET(settings->chld_fd[0], &rd)) break;
        if (FD_ISSET(settings->socket_fd, &rd)) {
            if (handle_connection(settings, &clients) < 0) { res = -1; break; }
            --res;
        }
        for (c = clients; res > 0 && c != NULL;) {
            int shut = 0;
            Client *next = c->next;
            if (FD_ISSET(c->fd, &wr)) --res, shut = do_client_write(c);
            if (FD_ISSET(c->fd, &rd)) --res, shut = do_client_read(settings, c);
            if (shut) {
                close(c->fd);
                if (c == clients) clients = c->next;
                if (c->next) c->next->prev = c->prev;
                if (c->prev) c->prev->next = c->next;
                free(c);
            }
            c = next;
        }
    }
    if (res >= 0) waitpid(settings->chld_pid, &status, 0);
    return 0;
}

static int import_key(Agent_settings *settings, const char *key_name,
               const char *key_file) {
    Key_info *keys = realloc(settings->keys, settings->nkeys + 1);
    Key_info *key;
    uint8_t *k = NULL;
    int is_public = 0;
    if (!keys) { perror(NULL); return -1; }
    settings->keys = keys;
    key = &keys[settings->nkeys];
    key->key = NULL;
    key->name = strdup(key_name ? key_name : key_file);
    if (!key->name) { perror(NULL); goto fail; }
    k = malloc(X25519_PK_LEN);
    if (!k) { perror(NULL); goto fail; }
    key->key = k;
    if (read_key_file(key_file, k, X25519_PK_LEN, &is_public) != 0)
        goto fail;
    key->type = is_public ? curve25519_public : curve25519_secret;
    settings->nkeys++;
    return 0;

 fail:
    if (key) {
        free((char *) key->name);
        free((uint8_t *) key->key);
    }
    return -1;
}

int main(int argc, char **argv) {
    Agent_settings settings = INIT_AGENT_SETTINGS;
    int opt;
    const char *key_name = NULL;

    while ((opt = getopt(argc, argv, "n:k:")) != -1) {
        switch (opt) {
        case 'n':
            key_name = optarg;
            break;
        case 'k':
            if (import_key(&settings, key_name, optarg) != 0)
                return EXIT_FAILURE;
            key_name = NULL;
            break;
        default:
            fprintf(stderr, "Usage: %s [-n <key_name>] -k <key_file> ...\n",
                    argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (open_socket(&settings) != 0)
        return EXIT_FAILURE;

    if (pipe(settings.chld_fd) != 0) {
        perror("pipe");
        goto fail;
    }

    if (install_sig_handler(&settings) < 0)
        goto fail;

    if (run_prog(&settings, argc - optind, &argv[optind]) < 0)
        goto fail;

    run_server(&settings);

    cleanup(&settings);
    return EXIT_SUCCESS;
 fail:
    cleanup(&settings);
    return EXIT_FAILURE;
}
