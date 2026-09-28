# Prebuilt `schedstat_snap`

`schedstat_snap` here is a precompiled, **statically-libbpf-linked** build of the
BPF snapshot+exit collector. Copy it to the AHV host and run it directly —
no `clang` / `bpftool` / `libbpf-devel` is needed on the host.

## Why prebuilt

AHV hosts have no build toolchain. Compile once on a separate Linux box and
commit (or copy) the result.

## How it was built

Built on a CentOS Stream 8 VM (`clang 17`), targeting the el9 AHV host
(kernel `6.18.x el9`). `libbpf` is linked **statically** because el8 ships
`libbpf.so.0` while the el9 host has `libbpf.so.1` — a dynamic link would not load
on the host. `libelf` / `libz` / `glibc` stay dynamic (compatible across el8 -> el9).

**Critical: use a modern libbpf (>= 1.0).** The host's 6.x kernel BTF uses
`BTF_KIND_ENUM64`, which only libbpf >= 1.0 can parse. The build pulls
**libbpf + a matching `bpftool` from source** (the `libbpf/bpftool` repo at tag
`v7.5.0`) rather than the distro packages.

Build-box packages needed: `clang`, `llvm` (for `llvm-strip`), `git`, `make`,
`elfutils-libelf-devel`, `zlib-devel`, `binutils-devel`, `libcap-devel`.

Steps (see `../build_static.sh`):

1. Capture the target host's BTF as `bpf/vmlinux.h` (gitignored; regenerate, don't commit):
   ```bash
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
   ```
   Run that on the **target AHV host**, then copy `vmlinux.h` next to the sources
   on the build box.
2. On the build box:
   ```bash
   cd bpf && bash build_static.sh
   ldd schedstat_snap            # must NOT list libbpf.so.*
   strip --strip-unneeded schedstat_snap
   cp schedstat_snap prebuilt/schedstat_snap
   ```

## Runtime notes

- The AHV host mounts `/tmp`, `/var/tmp`, `/home` as `noexec`; run the binary
  from `/root/bpfsnap`.
- The host still needs kernel features the collector checks at startup
  (BTF, `bpf_iter` task support, `sched_process_exit`).
