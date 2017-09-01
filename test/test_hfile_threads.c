/*  test_hfile_threads.c -- hfile concurrency unit tests.

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

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include "htslib/hfile.h"
#include "htslib/hts_log.h"

#define MAX_THREADS 16

typedef struct Settings {
    char *url;
    unsigned long nthreads;
} Settings;

static void * reader(void *arg) {
    hFILE *h = (hFILE *) arg;
    unsigned char buffer[256];
    ssize_t len, i;
    unsigned int *sum = NULL;

    sum = calloc(1, sizeof(*sum));
    if (!sum) {
        perror("calloc");
        return NULL;
    }

    while ((len = hread(h, buffer, sizeof(buffer))) > 0) {
        for (i = 0; i < len; i++) *sum += buffer[i];
    }
    if (len < 0) {
        perror("hread");
        free(sum);
        return NULL;
    }

    return sum;
}

static void *reader2(void *arg) {
    Settings *s = (Settings *) arg;
    hFILE *h = hopen(s->url, "r");
    unsigned int *sum = NULL;

    if (!h) {
        hts_log_error("hopen(\"%s\", \"r\") failed.\n", s->url);
        return NULL;
    }

    sum = reader(h);

    if (!sum) {
        hclose_abruptly(h);
        return NULL;
    }

    if (hclose(h) < 0) {
        hts_log_error("Error closing handle : %s\n", strerror(errno));
        free(sum);
        return NULL;
    }

    return sum;
}

static int run_test_threads(Settings *s) {
    unsigned long t, started = 0, stopped = 0;
    int ret = EXIT_FAILURE, errs, res;
    hFILE * hfs[MAX_THREADS];
    pthread_t threads[MAX_THREADS];

    assert(s->nthreads <= MAX_THREADS);

    for (t = 0; t < MAX_THREADS; t++) hfs[t] = NULL;

    for (t = 0; t < s->nthreads; t++) {
        hfs[t] = hopen(s->url, "r");
        if (!hfs[t]) {
            hts_log_error("hopen(\"%s\", \"r\") failed.\n", s->url);
            goto out;
        }
    }

    for (t = started = 0; t < s->nthreads; t++, started++) {
        if ((res = pthread_create(&threads[t], NULL, reader, hfs[t])) != 0) {
            hts_log_error("pthread_create failed for thread %lu : %s\n",
                    t, strerror(res));
            goto out;
        }
    }

    for (stopped = 0, errs = 0; stopped < s->nthreads; stopped++) {
        unsigned int *sum = NULL;
        if ((res = pthread_join(threads[stopped], (void **) &sum)) != 0) {
            hts_log_error("pthread_join on thread %lu : %s\n",
                    stopped, strerror(res));
            errs++;
        }
        printf("%s : Download %2lu sum = %u\n", __func__,
               stopped, sum ? *sum : 0);
        free(sum);
    }
    if (errs) goto out;

    for (t = 0, errs = 0; t < s->nthreads; t++) {
        if (hclose(hfs[t]) < 0) {
            hts_log_error("Error closing handle %lu : %s\n",
                    t, strerror(errno));
            errs++;
        }
        hfs[t] = NULL;
    }
    if (errs) goto out;

    ret = EXIT_SUCCESS;

 out:
    for (t = 0; t < s->nthreads; t++) {
        if (hfs[t]) hclose_abruptly(hfs[t]);
    }
    for (t = stopped; t < started; t++) {
        void *r;
        pthread_cancel(threads[t]);
        pthread_join(threads[t], &r);
    }
    return ret;
}

static int run_test_threads2(Settings *s) {
    unsigned long t, started = 0, stopped = 0, errs = 0;
    int ret = EXIT_FAILURE, res;
    pthread_t threads[MAX_THREADS];

    assert(s->nthreads <= MAX_THREADS);

    for (t = started = 0; t < s->nthreads; t++, started++) {
        if ((res = pthread_create(&threads[t], NULL, reader2, s)) != 0) {
            hts_log_error("pthread_create failed for thread %lu : %s\n",
                    t, strerror(res));
            goto out;
        }
    }
    for (stopped = 0, errs = 0; stopped < s->nthreads; stopped++) {
        unsigned int *sum = NULL;
        if ((res = pthread_join(threads[stopped], (void **) &sum)) != 0) {
            hts_log_error("pthread_join on thread %lu : %s\n",
                    stopped, strerror(res));
            errs++;
        }
        if (sum) {
            printf("%s : Download %2lu sum = %u\n", __func__, stopped, *sum);
            free(sum);
        } else {
            printf("%s : Download %2lu failed\n", __func__, stopped);
            errs++;
        }
    }
    if (errs) goto out;

    ret = EXIT_SUCCESS;

 out:
    for (t = stopped; t < started; t++) {
        void *r;
        pthread_cancel(threads[t]);
        pthread_join(threads[t], &r);
    }
    return ret;
}

static int run_test_single(Settings *s) {
    hFILE *hfs[MAX_THREADS];
    unsigned int sums[MAX_THREADS];
    unsigned char buffer[64];
    unsigned long t, running;

    assert(s->nthreads <= MAX_THREADS);

    for (t = 0; t < MAX_THREADS; t++) {
        hfs[t] = NULL;
        sums[t] = 0;
    }

    for (t = 0; t < s->nthreads; t++) {
        hfs[t] = hopen(s->url, "r");
        if (!hfs[t]) {
            hts_log_error("hopen(\"%s\", \"r\") failed.\n", s->url);
            goto fail;
        }
    }

    running = s->nthreads;

    while (running > 0) {
        for (t = 0; t < s->nthreads; t++) {
            ssize_t len, i;
            if (!hfs[t]) continue;
            len = hread(hfs[t], buffer, sizeof(buffer));
            if (len < 0) {
                perror("hread");
                goto fail;
            }
            for (i = 0; i < len; i++) sums[t] += buffer[i];
            if (len < sizeof(buffer)) {
                int res = hclose(hfs[t]);
                hfs[t] = NULL;
                running--;
                if (res < 0) {
                    hts_log_error("Error closing handle %lu : %s\n",
                            t, strerror(errno));
                    goto fail;
                }
            }
        }
    }
    for (t = 0; t < s->nthreads; t++) {
        printf("%s : Download %2lu sum = %u\n", __func__, t, sums[t]);
    }
    return EXIT_SUCCESS;

 fail:
    for (t = 0; t < s->nthreads; t++) {
        if (hfs[t]) hclose_abruptly(hfs[t]);
    }
    return EXIT_FAILURE;
}

static void usage(const char *prog) {
    const char *base = strrchr(prog, '/');
    base = base ? base + 1 : prog;
    fprintf(stderr, "Usage : %s [-@ <threads>] <url>\n", base);
}

int main(int argc, char **argv) {
    Settings s = { NULL, 4 };
    int res;
    int opt;

    setvbuf(stdout, NULL, _IONBF, 0);

    while ((opt = getopt(argc, argv, "@:v")) != -1) {
        switch (opt) {
        case '@': {
            char *end = optarg;
            unsigned long nt = strtoul(optarg, &end, 0);
            if (*optarg && !*end) {
                if (nt < 1 || nt > MAX_THREADS) {
                    fprintf(stderr, "Threads should be between 1 and %d.\n",
                            MAX_THREADS);
                    return EXIT_FAILURE;
                }
                s.nthreads = nt;
            } else {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            break;
        }
        case 'v':
            hts_set_log_level(hts_get_log_level() + 1);
            break;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        s.url = argv[optind];
    } else {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    res = run_test_single(&s);
    if (res) return res;
    res = run_test_threads(&s);
    if (res) return res;
    return run_test_threads2(&s);
}
