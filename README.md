# bpf_collector

Collect AHV host CPU time per cgroup slice/service via eBPF. No VM or workload
orchestration. **One binary — no RPM, no Python, no GitHub pull on the host.**

## What you need on the host

Just the file `schedstat_snap`. Put it under `/root/bpfsnap/` (AHV mounts
`/tmp` as `noexec`, so do not run from `/tmp`).

## Get the binary onto a new host (no git on CVM/AHV)

### Recommended: wget / curl from uranus

After the prebuilt is published to uranus:

```bash
# On AHV host, as root
mkdir -p /root/bpfsnap /var/log/cpu-stats
wget -O /root/bpfsnap/schedstat_snap \
  https://uranus.corp.nutanix.com/~dhruv.choudhary/schedstat_snap
# if https fails: use http://uranus.corp.nutanix.com/~dhruv.choudhary/schedstat_snap
chmod +x /root/bpfsnap/schedstat_snap
```

If `wget` is missing:

```bash
curl -L -o /root/bpfsnap/schedstat_snap \
  https://uranus.corp.nutanix.com/~dhruv.choudhary/schedstat_snap
chmod +x /root/bpfsnap/schedstat_snap
```

### Publish / refresh the uranus copy (from your laptop)

```bash
sftp dhruv.choudhary@upload.uranus.corp.nutanix.com
# at the sftp> prompt:
put bpf/prebuilt/schedstat_snap schedstat_snap
bye
```

### Alternatives if uranus is unreachable

- `scp` / `scp -O` laptop → CVM → AHV `/root/bpfsnap/schedstat_snap`
- SSH pipe (no scp subsystem):  
  `ssh nutanix@<CVM> 'cat > /tmp/schedstat_snap' < bpf/prebuilt/schedstat_snap`  
  then from CVM:  
  `ssh root@<AHV> 'mkdir -p /root/bpfsnap && cat > /root/bpfsnap/schedstat_snap' < /tmp/schedstat_snap`

You do **not** need `git clone` / `git pull` on the CVM or AHV.

## Run (AHV host, as root)

```bash
/root/bpfsnap/schedstat_snap --interval 5 --format raw --scope slices
/root/bpfsnap/schedstat_snap --interval 5 --format json --scope all
```

| Option | Values | Notes |
|--------|--------|--------|
| `--interval` / `-i` | seconds | default `5` |
| `--format` / `-f` | `raw` \| `json` | default `raw` |
| `--scope` / `-s` | `slices` \| `all` | `slices` = cvm/uvm/services; `all` also emits per-service (default `all`) |
| `--outdir` / `-o` | directory | default `/var/log/cpu-stats` |

Stop with Ctrl-C. The tool enables `kernel.sched_schedstats=1` while running and
restores the previous value on exit.

Output: `/var/log/cpu-stats/bpfsnap_<timestamp>.txt` (or `.jsonl` for json).

## How it works

1. Loads a BPF program on the AHV host (task iterator + exit hook).
2. Every `--interval` seconds, accounts run/wait into **cvm** / **uvm** /
   **services** (and optionally each service under `system.slice`).
3. Computes X, Y, Z, Demand, Supply, and cores for that interval.
4. Appends one record to a timestamped file under `--outdir`.
5. Runs until Ctrl-C / SIGTERM.

Log files start with version metadata (`0.1.0`).

## Build (optional — only to refresh the prebuilt)

AHV has no toolchain. On a Linux build box with the target host's `vmlinux.h`:

```bash
cd bpf && bash build_static.sh
cp schedstat_snap prebuilt/schedstat_snap
```

Then re-upload to uranus (see above) and/or commit `bpf/prebuilt/schedstat_snap`.
See [bpf/prebuilt/README.md](bpf/prebuilt/README.md) for build details.
