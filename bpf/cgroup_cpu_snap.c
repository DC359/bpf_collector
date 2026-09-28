// Userspace driver for the BPF snapshot collector.
//
// Complete tool: CLI, BPF load/sweep, Demand/Supply enrichment, and logging.
// Thread exits are accounted asynchronously by the kernel exit hook.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // name_to_handle_at, struct file_handle, localtime_r
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/types.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cgroup_cpu_snap.skel.h"

#define BPF_COLLECTOR_VERSION "0.1.0"

#define CVM_CG         "/sys/fs/cgroup/ahv.slice/ahv-cvm.slice"
#define UVMS_CG        "/sys/fs/cgroup/ahv.slice/ahv-uvms.slice"
#define SYS_CG         "/sys/fs/cgroup/system.slice"
#define SVC_PARENT     "/sys/fs/cgroup/system.slice"
#define SCHEDSTATS     "/proc/sys/kernel/sched_schedstats"
#define DEFAULT_OUTDIR "/var/log/cpu-stats"

/* One tick with --scope all can carry hundreds of service entries. */
#define JSON_BUF_SZ    (1 << 20)

struct cg_handle {
    struct file_handle fh;
    unsigned char data[128];
};

#define BUCKET_OTHER    0
#define BUCKET_CVM      1
#define BUCKET_UVMS     2
#define BUCKET_SERVICES 3
#define N_SLICE_BUCKETS 4

/* Short names in logs; kernel still accounts "other" — we drop it. */
static const char *SLICE_OUT[N_SLICE_BUCKETS] = {
    NULL, "cvm", "uvm", "services",
};

struct accum {
    __u64 run;
    __u64 wait;
    __u64 count;
};

struct metrics {
    __u64 X, Y, Z, Demand, Supply;
    double x_cores, y_cores;
    __u64 tasks;
};

enum out_format { FMT_RAW = 0, FMT_JSON = 1 };
enum out_scope  { SCOPE_SLICES = 0, SCOPE_ALL = 1 };

static volatile sig_atomic_t exiting = 0;
static char sched_old[16];
static int sched_changed = 0;

static void on_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

static void restore_schedstats(void)
{
    FILE *f;

    if (!sched_changed)
        return;
    f = fopen(SCHEDSTATS, "w");
    if (f) {
        fprintf(f, "%s\n", sched_old);
        fclose(f);
        fprintf(stderr, "[snap] restored schedstats to %s\n", sched_old);
    }
    sched_changed = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [options]\n"
            "  -i, --interval SEC   sample interval (default 5)\n"
            "  -f, --format FMT     raw | json (default raw)\n"
            "  -s, --scope SCOPE    slices | all (default all)\n"
            "  -o, --outdir DIR     log directory (default %s)\n"
            "  -h, --help           show this help\n",
            prog, DEFAULT_OUTDIR);
}

static __u64 cgid_from_path(const char *path)
{
    struct cg_handle h;
    int mount_id = 0;
    __u64 id = 0;
    size_t n;

    h.fh.handle_bytes = sizeof(h.data);
    if (name_to_handle_at(AT_FDCWD, path, &h.fh, &mount_id, 0) != 0)
        return 0;
    n = h.fh.handle_bytes < sizeof(id) ? h.fh.handle_bytes : sizeof(id);
    memcpy(&id, h.fh.f_handle, n);
    return id;
}

struct svc_name {
    __u64 id;
    char name[128];
};

static int scan_services(const char *parent, struct svc_name *out, int max)
{
    DIR *d = opendir(parent);
    struct dirent *e;
    int n = 0;
    char childpath[512];

    if (!d)
        return 0;
    while ((e = readdir(d)) != NULL && n < max) {
        __u64 id;

        if (e->d_name[0] == '.')
            continue;
        if (e->d_type != DT_DIR && e->d_type != DT_UNKNOWN)
            continue;
        snprintf(childpath, sizeof(childpath), "%s/%s", parent, e->d_name);
        id = cgid_from_path(childpath);
        if (id == 0)
            continue;
        out[n].id = id;
        snprintf(out[n].name, sizeof(out[n].name), "%s", e->d_name);
        n++;
    }
    closedir(d);
    return n;
}

static const char *name_for_id(struct svc_name *tbl, int n, __u64 id,
                               char *buf, size_t buflen)
{
    int i;

    for (i = 0; i < n; i++) {
        if (tbl[i].id == id)
            return tbl[i].name;
    }
    snprintf(buf, buflen, "svc-%llu", (unsigned long long)id);
    return buf;
}

static int trigger_sweep(struct bpf_link *iter_link)
{
    int iter_fd = bpf_iter_create(bpf_link__fd(iter_link));
    char buf[4096];
    ssize_t r;
    int err;

    if (iter_fd < 0) {
        fprintf(stderr, "bpf_iter_create failed: %d\n", iter_fd);
        return -1;
    }
    while ((r = read(iter_fd, buf, sizeof(buf))) > 0)
        ;
    err = (r < 0) ? -errno : 0;
    close(iter_fd);
    return err;
}

static void build_metrics(__u64 X, __u64 Y, __u64 N, int interval_s,
                          struct metrics *m)
{
    __u64 INTERVAL_NS = (__u64)interval_s * 1000000000ULL;
    __u64 T_ns = (__u64)interval_s * N * 1000000000ULL;

    m->X = X;
    m->Y = Y;
    m->tasks = N;
    m->Z = (T_ns > (X + Y)) ? (T_ns - X - Y) : 0;
    m->Supply = X;
    if ((X + m->Z) > 0) {
        __u64 ratio_scaled = (X * 1000000ULL) / (X + m->Z);
        m->Demand = X + (Y / 1000000ULL) * ratio_scaled;
    } else {
        m->Demand = X;
    }
    m->x_cores = (INTERVAL_NS > 0) ? ((double)X / (double)INTERVAL_NS) : 0.0;
    m->y_cores = (INTERVAL_NS > 0) ? ((double)Y / (double)INTERVAL_NS) : 0.0;
}

static void json_escape(const char *in, char *out, size_t outlen)
{
    size_t i, j = 0;

    for (i = 0; in[i] && j + 2 < outlen; i++) {
        if (in[i] == '"' || in[i] == '\\') {
            if (j + 3 >= outlen)
                break;
            out[j++] = '\\';
            out[j++] = in[i];
        } else {
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
}

static void emit_dup(FILE *logf, const char *text)
{
    fputs(text, logf);
    fputs(text, stdout);
    fflush(logf);
    fflush(stdout);
}

static void write_entity_raw(FILE *logf, const char *kind, const char *name,
                             const struct metrics *m)
{
    char buf[640];

    snprintf(buf, sizeof(buf),
             "%s %s X=%llu Y=%llu Z=%llu Demand=%llu Supply=%llu "
             "x_cores=%.2f y_cores=%.2f tasks=%llu\n",
             kind, name,
             (unsigned long long)m->X, (unsigned long long)m->Y,
             (unsigned long long)m->Z, (unsigned long long)m->Demand,
             (unsigned long long)m->Supply,
             m->x_cores, m->y_cores, (unsigned long long)m->tasks);
    emit_dup(logf, buf);
}

static void write_entity_json_fields(char *buf, size_t buflen,
                                     const struct metrics *m)
{
    snprintf(buf, buflen,
             "\"X\":%llu,\"Y\":%llu,\"Z\":%llu,\"Demand\":%llu,\"Supply\":%llu,"
             "\"x_cores\":%.2f,\"y_cores\":%.2f,\"xy_cores\":%.2f,\"tasks\":%llu",
             (unsigned long long)m->X, (unsigned long long)m->Y,
             (unsigned long long)m->Z, (unsigned long long)m->Demand,
             (unsigned long long)m->Supply,
             m->x_cores, m->y_cores, m->x_cores + m->y_cores,
             (unsigned long long)m->tasks);
}

static int preflight(void)
{
    const char *paths[] = { CVM_CG, UVMS_CG, SYS_CG, NULL };
    int i;

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: must run as root on the AHV host\n");
        return -1;
    }
    if (access("/sys/kernel/btf/vmlinux", R_OK) != 0) {
        fprintf(stderr, "ERROR: /sys/kernel/btf/vmlinux missing — cannot load BPF\n");
        return -1;
    }
    for (i = 0; paths[i]; i++) {
        if (access(paths[i], F_OK) != 0) {
            fprintf(stderr, "ERROR: missing cgroup path %s\n", paths[i]);
            return -1;
        }
    }
    return 0;
}

static void enable_schedstats(void)
{
    FILE *f = fopen(SCHEDSTATS, "r");
    size_t n;

    if (!f) {
        fprintf(stderr, "[preflight] WARNING: cannot read %s: %s\n",
                SCHEDSTATS, strerror(errno));
        return;
    }
    if (!fgets(sched_old, sizeof(sched_old), f))
        snprintf(sched_old, sizeof(sched_old), "0");
    fclose(f);

    n = strlen(sched_old);
    while (n > 0 && (sched_old[n - 1] == '\n' || sched_old[n - 1] == '\r'))
        sched_old[--n] = '\0';

    if (strcmp(sched_old, "1") == 0)
        return;

    f = fopen(SCHEDSTATS, "w");
    if (!f) {
        fprintf(stderr, "[preflight] WARNING: cannot set schedstats: %s\n",
                strerror(errno));
        return;
    }
    fputs("1\n", f);
    fclose(f);
    sched_changed = 1;
    fprintf(stderr, "[preflight] enabled kernel.sched_schedstats=1 (was %s)\n",
            sched_old);
}

static void clear_svc_map(int svc_fd)
{
    __u64 key = 0, next;
    static __u64 keys[8192];
    int nk = 0, i;
    int have = (bpf_map_get_next_key(svc_fd, NULL, &next) == 0);

    while (have && nk < 8192) {
        keys[nk++] = next;
        key = next;
        have = (bpf_map_get_next_key(svc_fd, &key, &next) == 0);
    }
    for (i = 0; i < nk; i++)
        bpf_map_delete_elem(svc_fd, &keys[i]);
}

int main(int argc, char **argv)
{
    int interval_s = 5;
    enum out_format fmt = FMT_RAW;
    enum out_scope scope = SCOPE_ALL;
    const char *outdir = DEFAULT_OUTDIR;
    int opt;
    char outpath[512];
    char ts_file[32];
    FILE *logf;
    char hdr[256];
    time_t now0;
    struct tm tmv0;
    int ncpu;
    __u64 cvm_id, uvms_id, sys_id;
    struct cgroup_cpu_snap_bpf *skel;
    struct bpf_link *exit_link, *iter_link;
    int slice_fd, svc_fd;
    struct accum *percpu, *zero;
    struct svc_name *svctbl;
    char *jsonbuf = NULL;
    unsigned long tick = 0;
    struct timespec ts_mono;

    static struct option long_opts[] = {
        {"interval", required_argument, 0, 'i'},
        {"format",   required_argument, 0, 'f'},
        {"scope",    required_argument, 0, 's'},
        {"outdir",   required_argument, 0, 'o'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0},
    };

    while ((opt = getopt_long(argc, argv, "i:f:s:o:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            interval_s = atoi(optarg);
            break;
        case 'f':
            if (strcmp(optarg, "raw") == 0)
                fmt = FMT_RAW;
            else if (strcmp(optarg, "json") == 0)
                fmt = FMT_JSON;
            else {
                fprintf(stderr, "ERROR: --format must be raw or json\n");
                return 1;
            }
            break;
        case 's':
            if (strcmp(optarg, "slices") == 0)
                scope = SCOPE_SLICES;
            else if (strcmp(optarg, "all") == 0)
                scope = SCOPE_ALL;
            else {
                fprintf(stderr, "ERROR: --scope must be slices or all\n");
                return 1;
            }
            break;
        case 'o':
            outdir = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (interval_s <= 0)
        interval_s = 5;

    if (preflight() != 0)
        return 1;
    enable_schedstats();

    if (mkdir(outdir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "ERROR: cannot create outdir %s: %s\n",
                outdir, strerror(errno));
        restore_schedstats();
        return 1;
    }

    now0 = time(NULL);
    localtime_r(&now0, &tmv0);
    strftime(ts_file, sizeof(ts_file), "%Y%m%d_%H%M%S", &tmv0);
    snprintf(outpath, sizeof(outpath), "%s/cgroup_cpu_snap_%s.%s",
             outdir, ts_file, fmt == FMT_JSON ? "jsonl" : "txt");

    logf = fopen(outpath, "w");
    if (!logf) {
        fprintf(stderr, "ERROR: cannot open %s: %s\n", outpath, strerror(errno));
        restore_schedstats();
        return 1;
    }

    if (fmt == FMT_RAW) {
        snprintf(hdr, sizeof(hdr),
                 "# bpf_collector version=%s interval=%d format=raw scope=%s\n",
                 BPF_COLLECTOR_VERSION, interval_s,
                 scope == SCOPE_ALL ? "all" : "slices");
    } else {
        snprintf(hdr, sizeof(hdr),
                 "{\"type\":\"meta\",\"version\":\"%s\",\"interval\":%d,"
                 "\"format\":\"json\",\"scope\":\"%s\"}\n",
                 BPF_COLLECTOR_VERSION, interval_s,
                 scope == SCOPE_ALL ? "all" : "slices");
    }
    emit_dup(logf, hdr);

    ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0)
        ncpu = 1;

    cvm_id  = cgid_from_path(CVM_CG);
    uvms_id = cgid_from_path(UVMS_CG);
    sys_id  = cgid_from_path(SYS_CG);
    fprintf(stderr,
            "[snap] version=%s slice ids: cvm=%llu uvms=%llu sys=%llu (ncpu=%d)\n",
            BPF_COLLECTOR_VERSION,
            (unsigned long long)cvm_id, (unsigned long long)uvms_id,
            (unsigned long long)sys_id, ncpu);
    if (sys_id == 0)
        fprintf(stderr, "[snap] WARNING: system.slice id resolved to 0 — "
                        "service accounting will be empty\n");

    skel = cgroup_cpu_snap_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open skeleton\n");
        fclose(logf);
        restore_schedstats();
        return 1;
    }

    skel->rodata->cvm_id  = cvm_id;
    skel->rodata->uvms_id = uvms_id;
    skel->rodata->sys_id  = sys_id;

    if (cgroup_cpu_snap_bpf__load(skel)) {
        fprintf(stderr, "failed to load BPF skeleton\n");
        cgroup_cpu_snap_bpf__destroy(skel);
        fclose(logf);
        restore_schedstats();
        return 1;
    }

    exit_link = bpf_program__attach(skel->progs.snap_exit);
    if (!exit_link) {
        fprintf(stderr, "failed to attach snap_exit\n");
        cgroup_cpu_snap_bpf__destroy(skel);
        fclose(logf);
        restore_schedstats();
        return 1;
    }

    iter_link = bpf_program__attach_iter(skel->progs.snap_iter, NULL);
    if (!iter_link) {
        fprintf(stderr, "failed to attach snap_iter\n");
        bpf_link__destroy(exit_link);
        cgroup_cpu_snap_bpf__destroy(skel);
        fclose(logf);
        restore_schedstats();
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    slice_fd = bpf_map__fd(skel->maps.agg_slice);
    svc_fd   = bpf_map__fd(skel->maps.agg_svc);

    percpu = calloc(ncpu, sizeof(struct accum));
    zero   = calloc(ncpu, sizeof(struct accum));
    svctbl = calloc(8192, sizeof(struct svc_name));
    if (fmt == FMT_JSON)
        jsonbuf = malloc(JSON_BUF_SZ);
    if (!percpu || !zero || !svctbl || (fmt == FMT_JSON && !jsonbuf)) {
        fprintf(stderr, "alloc failed\n");
        free(percpu);
        free(zero);
        free(svctbl);
        free(jsonbuf);
        bpf_link__destroy(iter_link);
        bpf_link__destroy(exit_link);
        cgroup_cpu_snap_bpf__destroy(skel);
        fclose(logf);
        restore_schedstats();
        return 1;
    }

    fprintf(stderr, "[snap] interval=%ds format=%s scope=%s out=%s\n",
            interval_s,
            fmt == FMT_JSON ? "json" : "raw",
            scope == SCOPE_ALL ? "all" : "slices",
            outpath);
    fprintf(stderr, "[snap] stop with Ctrl-C\n");

    /* Prime baseline — not attributed to a displayed tick. */
    trigger_sweep(iter_link);
    {
        __u32 k;
        for (k = 0; k < N_SLICE_BUCKETS; k++)
            bpf_map_update_elem(slice_fd, &k, zero, BPF_ANY);
    }
    clear_svc_map(svc_fd);

    while (!exiting) {
        int s;
        time_t now, now2;
        struct tm tmv;
        char ts_start[32], ts_end[32];
        unsigned long long mono_ns;
        struct accum slice_tot[N_SLICE_BUCKETS];
        struct metrics slice_m[N_SLICE_BUCKETS];
        int nsvc;
        __u32 k;

        for (s = 0; s < interval_s && !exiting; s++)
            sleep(1);
        if (exiting)
            break;

        tick++;

        now = time(NULL);
        localtime_r(&now, &tmv);
        strftime(ts_start, sizeof(ts_start), "%H:%M:%S", &tmv);
        clock_gettime(CLOCK_MONOTONIC, &ts_mono);
        mono_ns = (unsigned long long)ts_mono.tv_sec * 1000000000ULL
                + (unsigned long long)ts_mono.tv_nsec;

        trigger_sweep(iter_link);

        memset(slice_tot, 0, sizeof(slice_tot));
        for (k = 0; k < N_SLICE_BUCKETS; k++) {
            int c;
            if (bpf_map_lookup_elem(slice_fd, &k, percpu) != 0)
                continue;
            for (c = 0; c < ncpu; c++) {
                slice_tot[k].run   += percpu[c].run;
                slice_tot[k].wait  += percpu[c].wait;
                slice_tot[k].count += percpu[c].count;
            }
        }

        nsvc = scan_services(SVC_PARENT, svctbl, 8192);

        now2 = time(NULL);
        localtime_r(&now2, &tmv);
        strftime(ts_end, sizeof(ts_end), "%H:%M:%S", &tmv);

        memset(slice_m, 0, sizeof(slice_m));
        for (k = 1; k < N_SLICE_BUCKETS; k++)
            build_metrics(slice_tot[k].run, slice_tot[k].wait,
                          slice_tot[k].count, interval_s, &slice_m[k]);

        if (fmt == FMT_RAW) {
            char thdr[160];
            snprintf(thdr, sizeof(thdr), "TICK %lu %s %s %d MONO=%lluns\n",
                     tick, ts_start, ts_end, interval_s, mono_ns);
            emit_dup(logf, thdr);
            for (k = 1; k < N_SLICE_BUCKETS; k++)
                write_entity_raw(logf, "SLICE", SLICE_OUT[k], &slice_m[k]);

            if (scope == SCOPE_ALL) {
                char namebuf[64];
                __u64 key = 0, next;
                int have_key = (bpf_map_get_next_key(svc_fd, NULL, &next) == 0);

                while (have_key) {
                    if (bpf_map_lookup_elem(svc_fd, &next, percpu) == 0) {
                        struct accum t = {0, 0, 0};
                        struct metrics sm;
                        const char *nm;
                        int c;

                        for (c = 0; c < ncpu; c++) {
                            t.run   += percpu[c].run;
                            t.wait  += percpu[c].wait;
                            t.count += percpu[c].count;
                        }
                        build_metrics(t.run, t.wait, t.count, interval_s, &sm);
                        nm = name_for_id(svctbl, nsvc, next, namebuf,
                                         sizeof(namebuf));
                        write_entity_raw(logf, "SERVICE", nm, &sm);
                    }
                    key = next;
                    have_key = (bpf_map_get_next_key(svc_fd, &key, &next) == 0);
                }
            }
            emit_dup(logf, "END_TICK\n");
        } else {
            size_t pos = 0;
            int n;

            n = snprintf(jsonbuf + pos, JSON_BUF_SZ - pos,
                         "{\"tick\":%lu,\"ts_start\":\"%s\",\"ts_end\":\"%s\","
                         "\"interval_s\":%d,\"mono_ns\":%llu,\"slices\":{",
                         tick, ts_start, ts_end, interval_s, mono_ns);
            if (n < 0 || (size_t)n >= JSON_BUF_SZ - pos)
                goto json_trunc;
            pos += (size_t)n;

            for (k = 1; k < N_SLICE_BUCKETS; k++) {
                char fields[256];
                write_entity_json_fields(fields, sizeof(fields), &slice_m[k]);
                n = snprintf(jsonbuf + pos, JSON_BUF_SZ - pos, "%s\"%s\":{%s}",
                             k > 1 ? "," : "", SLICE_OUT[k], fields);
                if (n < 0 || (size_t)n >= JSON_BUF_SZ - pos)
                    goto json_trunc;
                pos += (size_t)n;
            }
            n = snprintf(jsonbuf + pos, JSON_BUF_SZ - pos, "}");
            if (n < 0 || (size_t)n >= JSON_BUF_SZ - pos)
                goto json_trunc;
            pos += (size_t)n;

            if (scope == SCOPE_ALL) {
                char namebuf[64], esc[160], fields[256];
                __u64 key = 0, next;
                int first = 1;
                int have_key;

                n = snprintf(jsonbuf + pos, JSON_BUF_SZ - pos, ",\"services\":{");
                if (n < 0 || (size_t)n >= JSON_BUF_SZ - pos)
                    goto json_trunc;
                pos += (size_t)n;

                have_key = (bpf_map_get_next_key(svc_fd, NULL, &next) == 0);
                while (have_key) {
                    if (bpf_map_lookup_elem(svc_fd, &next, percpu) == 0) {
                        struct accum t = {0, 0, 0};
                        struct metrics sm;
                        const char *nm;
                        int c;

                        for (c = 0; c < ncpu; c++) {
                            t.run   += percpu[c].run;
                            t.wait  += percpu[c].wait;
                            t.count += percpu[c].count;
                        }
                        build_metrics(t.run, t.wait, t.count, interval_s, &sm);
                        nm = name_for_id(svctbl, nsvc, next, namebuf,
                                         sizeof(namebuf));
                        json_escape(nm, esc, sizeof(esc));
                        write_entity_json_fields(fields, sizeof(fields), &sm);
                        n = snprintf(jsonbuf + pos, JSON_BUF_SZ - pos,
                                     "%s\"%s\":{%s}",
                                     first ? "" : ",", esc, fields);
                        if (n < 0 || (size_t)n >= JSON_BUF_SZ - pos)
                            goto json_trunc;
                        pos += (size_t)n;
                        first = 0;
                    }
                    key = next;
                    have_key = (bpf_map_get_next_key(svc_fd, &key, &next) == 0);
                }
                n = snprintf(jsonbuf + pos, JSON_BUF_SZ - pos, "}");
                if (n < 0 || (size_t)n >= JSON_BUF_SZ - pos)
                    goto json_trunc;
                pos += (size_t)n;
            }

            n = snprintf(jsonbuf + pos, JSON_BUF_SZ - pos, "}\n");
            if (n < 0 || (size_t)n >= JSON_BUF_SZ - pos)
                goto json_trunc;
            emit_dup(logf, jsonbuf);
            goto wipe;

json_trunc:
            fprintf(stderr,
                    "[snap] WARNING: tick %lu exceeded the %d byte JSON buffer; "
                    "record dropped\n", tick, JSON_BUF_SZ);
        }

wipe:
        for (k = 0; k < N_SLICE_BUCKETS; k++)
            bpf_map_update_elem(slice_fd, &k, zero, BPF_ANY);
        clear_svc_map(svc_fd);
    }

    fprintf(stderr, "[snap] exiting, wrote %lu ticks -> %s\n", tick, outpath);
    free(percpu);
    free(zero);
    free(svctbl);
    free(jsonbuf);
    bpf_link__destroy(iter_link);
    bpf_link__destroy(exit_link);
    cgroup_cpu_snap_bpf__destroy(skel);
    fclose(logf);
    restore_schedstats();
    return 0;
}
