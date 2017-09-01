/*  microweb.c -- very basic web server, for testing only.

    Copyright (C) 2017 Genome Research Ltd.

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
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>

#define MIN_PORT 8000
#define MAX_PORT 9000

typedef enum {
    BadRequest    = 400,
    Forbidden     = 403,
    NotFound      = 404,
    NotAllowed    = 405,
    InternalError = 500,
} StatusCode;

typedef struct Thread {
    int fd;
    const char *dir;
} Thread;

typedef struct Server {
    const char *dir;
    int   port;
    int monitor_fd;
    struct addrinfo *addr;
    size_t num_sockets;
    struct pollfd *polls;
} Server;

static void cleanup(Server *s) {
    size_t i;
    if (s->polls) {
        for (i = 0; i < s->num_sockets; i++) {
            if (s->polls[i].fd >= 0) close(s->polls[i].fd);
        }
        free(s->polls);
        s->polls = NULL;
    }
    if (s->addr)
        freeaddrinfo(s->addr);
    s->addr = NULL;
}

static inline char * get_word(char *start, char **next) {
    char *p;
    while (*start && isspace(*start)) ++start;
    for (p = start; *p && !isspace(*p); ++p) {}
    if (*p) *p++ = '\0';
    if (next) *next = p;
    return start;
}

static inline void unpercentify(char *loc) {
    unsigned char *in = (unsigned char *) loc, *out = in;

    for (in = (unsigned char *) loc; *in; ++in, ++out) {
        if (*in == '%' && isxdigit(in[1]) && isxdigit(in[2])) {
            unsigned int x;
            sscanf((char *) in + 1, "%2x", &x);
            *out = x;
            in += 2;
        } else {
            *out = *in;
        }
    }
    if (out < in) *out = '\0';
}

static inline void remove_dot_segments(char *loc) {
    /* See https://tools.ietf.org/html/rfc3986 section 5.2.4 */
    char *in = loc, *out = loc;

    while (*in) {
        int remove = 0;
        while (in[0] == '/' && in[1] == '/') ++in;
        if (strcmp(in, ".") == 0 || strcmp(in, "..") == 0) break;
        if (strncmp(in, "./",  2) == 0) { in += 2; continue; }
        if (strncmp(in, "../", 3) == 0) { in += 3; continue; }
        if (strncmp(in, "/./", 3) == 0) { in += 2; continue; }
        if (strcmp(in, "/.") == 0) { in[1] = '\0'; continue; }
        if (strcmp(in, "/..") == 0) { in[1] = '\0'; remove = 1; }
        if (strncmp(in, "/../", 4) == 0) { in += 3; remove = 1; }
        if (remove) {
            while (out > loc && *out == '/') --out;
            while (out > loc && *out != '/') --out;
            continue;
        }
        if (*in == '/') *out++ = *in++;
        while (*in && *in != '/') *out++ = *in++;
    }
    *out = '\0';
}

static void send_error(FILE *f, StatusCode code) {
    char *msg;
    size_t len;
    unsigned int c = code;
    switch (code) {
    case BadRequest:    msg = "Bad Request"; break;
    case Forbidden:     msg = "Forbidden"; break;
    case NotFound:      msg = "Not Found"; break;
    case NotAllowed:    msg = "Method Not Allowed"; break;
    case InternalError: msg = "Internal Server Error"; break;
    default: msg = "";
    }
    len = strlen(msg) + 4;
    for (c = code; c >= 10; c /= 10) len++;
    fprintf(f, "HTTP/1.1 %u %s\r\n", code, msg);
    fprintf(f, "Content-Type: text/plain; charset=UTF-8\r\n");
    fprintf(f, "Content-Length: %zu\r\n", len);
    fprintf(f, "Connection: close\r\n\r\n");
    fprintf(f, "%d %s\r\n", code, msg);
    fflush(f);
}

static void send_chars(FILE *f, char *loc) {
    unsigned long num = 0, i;
    char chars[94];
    char *end = NULL;

    for (i = 0; i < sizeof(chars); i++) chars[i] = '!' + i;
    num = strtoul(loc, &end, 0);
    if (!*loc || *end) {
        send_error(f, NotFound);
        return;
    }

    fprintf(f, "HTTP/1.1 200 OK\r\n");
    fprintf(f, "Content-Type: text/plain; charset=UTF-8\r\n");
    fprintf(f, "Content-Length: %lu\r\n", num);
    fprintf(f, "Connection: close\r\n\r\n");
    for (i = 0; i < num; i+=sizeof(chars)) {
        fwrite(chars, 1, num - i < sizeof(chars) ? num - i : sizeof(chars), f);
    }
    fflush(f);
}

static void send_file(FILE *f, const char *dir, const char *loc) {
    size_t dlen = strlen(dir), llen = strlen(loc), len;
    FILE *src = NULL;
    struct stat st = { 0 };
    char buffer[4096];
    char *name = buffer;
    unsigned int code = InternalError;
    char *sep = loc[0] == '/' ? "" : "/";
    len = dlen + llen + 2;
    if (len > sizeof(buffer)) {
        name = malloc(len);
        if (!name) { perror(NULL); goto fail; }
    }
    snprintf(name, len, "%s%s%s", dir, sep, loc);
    src = fopen(name, "rb");
    if (!src) {
        switch (errno) {
        case ENOENT: code = NotFound;  goto fail;
        case EACCES: code = Forbidden; goto fail;
        default: goto fail;
        }
    }
    if (fstat(fileno(src), &st) < 0) goto fail;
    if (!S_ISREG(st.st_mode)) { code = Forbidden; goto fail; }

    fprintf(f, "HTTP/1.1 200 OK\r\n");
    fprintf(f, "Content-Type: application/octet-stream\r\n");
    fprintf(f, "Content-Length: %lu\r\n", (unsigned long) st.st_size);
    fprintf(f, "Connection: close\r\n\r\n");
    while ((len = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, len, f) != len) break;
    }
    fclose(src);
    if (name != buffer) free(name);
    return;

 fail:
    if (src) fclose(src);
    if (name != buffer) free(name);
    send_error(f, code);
    return;
}

static void * handle_connection(void *thr_in) {
    Thread *thr = (Thread *) thr_in;
    FILE *f_in = NULL, *f_out = NULL;
    int fd_out = -1;
    char buffer[1024];
    char *verb, *loc, *proto, *p = buffer;

    f_in = fdopen(thr->fd, "rb");
    fd_out = dup(thr->fd);
    if (fd_out >= 0)
        f_out = fdopen(fd_out, "wb");
    if (!f_in || !f_out) {
        perror("dup / fdopen on socket");
        goto end;
    }
    if (fgets(buffer, sizeof(buffer), f_in) == NULL) goto end;
    verb = get_word(buffer, &p);
    loc = get_word(p, &p);
    proto = get_word(p, &p);
    if (strcmp(verb, "GET") != 0) {
        send_error(f_out, NotAllowed);
        goto end;
    }
    if (strncmp(proto, "HTTP/", 5) != 0) {
        send_error(f_out, BadRequest);
        goto end;
    }

    if (strncmp(loc, "http://", 7) == 0) {
        loc += 7;
        if ((p = strchr(loc, '/')) != NULL) loc = p;
    }
    if ((p = strchr(loc, '#')) != NULL) *p = '\0';
    if ((p = strchr(loc, '?')) != NULL) *p = '\0';
    unpercentify(loc);
    remove_dot_segments(loc);

    if (strncmp(loc, "/chargen/", 9) == 0) {
        send_chars(f_out, loc + 9);
    } else if (thr->dir) {
        send_file(f_out, thr->dir, loc);
    } else {
        send_error(f_out, NotFound);
    }

 end:
    if (f_in) {
        fclose(f_in);
    } else {
        close(thr->fd);
    }
    if (f_out) {
        fclose(f_out);
    } else if (fd_out >= 0) {
        close(fd_out);
    }
    free(thr);
    return NULL;
}

static int set_blocking_state(int fd, int block) {
    int val = fcntl(fd, F_GETFL);

    if (val == -1) {
        perror("fcntl(,F_GETFL)");
        return -1;
    }
    if (block) {
        val &= ~O_NONBLOCK;
    } else {
        val |= O_NONBLOCK;
    }
    if (fcntl(fd, F_SETFL, val) == -1) {
        perror("fcntl(,F_SETFL)");
        return -1;
    }

    return 0;
}

static int open_sockets(Server *s) {
    struct addrinfo hints, *a;
    char portnum[64];
    char host[256];
    size_t count = 0, i;
    int res, ret = -2;
    const int one = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    snprintf(portnum, sizeof(portnum), "%d", s->port);
    if ((res = getaddrinfo(NULL, portnum, &hints, &s->addr)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        return -2;
    }

    for (a = s->addr; a != NULL; a = a->ai_next)
        count++;

    if (!count)
        return -1;

    s->polls = calloc((count + 1), sizeof(s->polls[0]));
    if (!s->polls) { perror(NULL);  goto fail; }

    s->num_sockets = count;
    for (i = 0; i  < count; i++)
        s->polls[i].fd = -1;

    for (a = s->addr, i = 0; a != NULL; a = a->ai_next, ++i) {
        s->polls[i].fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s->polls[i].fd < 0) {
            perror("socket");
            goto fail;
        }
        if (setsockopt(s->polls[i].fd, SOL_SOCKET, SO_REUSEADDR,
                       &one, sizeof(one)) < 0) {
            perror("setsockopt");
            goto fail;
        }
        if (bind(s->polls[i].fd, a->ai_addr, a->ai_addrlen) < 0) {
            if (errno != EADDRINUSE) {
                perror("bind");
                goto fail;
            } else {
                ret = -1;
                goto fail;
            }
        }
        if (listen(s->polls[i].fd, 16) < 0) {
            perror("listen");
            goto fail;
        }
        if (set_blocking_state(s->polls[i].fd, 0) < 0)
            goto fail;

        if (i == 0) {
            if ((res = getnameinfo(a->ai_addr, a->ai_addrlen,
                                   host, sizeof(host),
                                   portnum, sizeof(portnum),
                                   NI_NUMERICSERV)) != 0) {
                fprintf(stderr, "getnameinfo: %s\n", gai_strerror(res));
                goto fail;
            }
            printf("%s:%s\n", host, portnum);
            fflush(stdout);
        }
        s->polls[i].events = POLLIN;
    }
    return 0;
 fail:
    cleanup(s);
    return ret;
}

static int accept_connection(Server *s, size_t idx) {
    Thread *t = NULL;
    pthread_t thread;
    pthread_attr_t attr;
    int res, fd;

    fd = accept(s->polls[idx].fd, NULL, NULL);
    if (fd < 0) {
        if (errno == EWOULDBLOCK) errno = EAGAIN;
        switch (errno) {
        case EAGAIN: case EINTR:
#ifdef __linux__ // Linux accept(2) man page says treat all these like EAGAIN
        case ENETDOWN: case EPROTO: case ENOPROTOOPT: case EHOSTDOWN:
        case ENONET: case EHOSTUNREACH: case EOPNOTSUPP: case ENETUNREACH:
#endif
            return 0;
        default:
            perror("accept");
            return -1;
        }
    }

    t = malloc(sizeof(*t));
    if (!t) { perror(NULL); goto fail; }

    if (set_blocking_state(fd, 1) < 0)
        goto fail;

    t->fd = fd;
    t->dir = s->dir;

    if ((res = pthread_attr_init(&attr)) != 0) {
        fprintf(stderr, "pthread_attr_init : %s\n", strerror(res));
        goto fail;
    }
    if ((res = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) != 0) {
        fprintf(stderr, "pthread_attr_setdetachstate : %s\n", strerror(res));
        goto fail2;
    }
    if ((res = pthread_create(&thread, &attr, handle_connection, t)) != 0) {
        fprintf(stderr, "pthread_create : %s\n", strerror(res));
        goto fail2;
    }
    pthread_attr_destroy(&attr);
    return 0;

 fail2:
    pthread_attr_destroy(&attr);

 fail:
    close(fd);
    free(t);
    return -1;
}

static int run_server(Server *s) {
    struct sigaction sa;
    struct sigaction old_sa;
    int ready, npolls;
    size_t i;

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (0 != sigaction(SIGPIPE, &sa, &old_sa)) {
        perror("sigaction(SIGPIPE)");
        return -1;
    }

    if (s->port >= 0) {
        if (!open_sockets(s))
            return EXIT_FAILURE;
    } else {
        for (s->port = MIN_PORT; s->port <= MAX_PORT; s->port++) {
            if (open_sockets(s) == 0) break;
        }
    }

    if (s->monitor_fd >= 0) {
        s->polls[s->num_sockets].fd = s->monitor_fd;
        s->polls[s->num_sockets].events = POLLIN|POLLHUP|POLLERR;
    }
    npolls = s->monitor_fd >= 0 ? s->num_sockets + 1 : s->num_sockets;

    for (;;) {
        ready = poll(s->polls, npolls, -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            goto fail;
        } else if (ready > 0) {
            for (i = 0; i < s->num_sockets; i++) {
                if (s->polls[i].revents & POLLIN) {
                    if (accept_connection(s, i) < 0)
                        goto fail;
                }
            }
            if (s->polls[s->num_sockets].revents & POLLIN) {
                unsigned char buffer[1024];
                ssize_t got = 0;
                do {
                    got = read(s->polls[s->num_sockets].fd,
                               buffer, sizeof(buffer));
                } while (got == sizeof(buffer) || (got < 0 && errno == EINTR));
                if (got == 0)
                    break;
            }
            if (s->polls[s->num_sockets].revents & (POLLHUP|POLLERR))
                break;
        }
    }
    cleanup(s);
    return EXIT_SUCCESS;

 fail:
    cleanup(s);
    return EXIT_FAILURE;
}


static void usage(const char *prog, FILE *f) {
    const char *base = strrchr(prog, '/');
    base = base ? base + 1 : prog;
    fprintf(f, "Usage : %s [-d <dir>] [-m <fileno>] [-p <port>] [-v]\n", base);
}

static void help(const char *prog) {
    usage(prog, stdout);
    printf("Options:\n");
    printf("   -d <dir>     Server up files in directory <dir>\n");
    printf("   -m <fileno>  Quit when file descriptor <fileno> closes\n");
    printf("   -p <port>    Listen for connections on <port>\n");
    printf("   -v           Increase verbosity\n");
    printf("If the -p option is not used, the first free port "
           "between %d and %d\nwill be used.  The host and port to contact are "
           "written to stdout.\n", MIN_PORT, MAX_PORT);
}

int main(int argc, char **argv) {
    Server s = { NULL, -1, -1, NULL, 0, NULL };
    char *dir = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "d:hm:p:")) != -1) {
        switch (opt) {
        case 'd':
            dir = optarg;
            break;
        case 'm':
            s.monitor_fd = atoi(optarg);
            break;
        case 'p':
            s.port = atoi(optarg);
            break;
        case 'h':
            help(argv[0]);
            return EXIT_SUCCESS;
        default:
            usage(argv[0], stderr);
            return EXIT_FAILURE;
        }
    }

    if (dir) {
        size_t l = strlen(dir);
        while (l > 0 && dir[l - 1] == '/') dir[--l] = '\0';
        s.dir = dir;
    }

    return run_server(&s);
}
