# bpf_collector

Collect AHV host CPU time per cgroup slice/service via eBPF. No VM or workload orchestration. 

## What you need on the host

Just the file `schedstat_snap`. Put it under `/root/bpfsnap/` (AHV mounts
`/tmp` as `noexec`, so do not run from `/tmp`).

## Get the binary onto a new host 

### Recommended: wget from uranus

After the prebuilt is published to uranus:

```bash
# On AHV host, as root
mkdir -p /root/bpfsnap /var/log/cpu-stats
wget -O /root/bpfsnap/schedstat_snap \
  https://uranus.corp.nutanix.com/~dhruv.choudhary/schedstat_snap

chmod +x /root/bpfsnap/schedstat_snap
```

### Alternatives if uranus is unreachable

- `scp -O` laptop → CVM → AHV `/root/bpfsnap/schedstat_snap`
- SSH pipe (no scp subsystem):  
`ssh nutanix@<CVM> 'cat > /tmp/schedstat_snap' < bpf/prebuilt/schedstat_snap`  
then from CVM:  
`ssh root@<AHV> 'mkdir -p /root/bpfsnap && cat > /root/bpfsnap/schedstat_snap' < /tmp/schedstat_snap`

## Run (AHV host, as root)

```bash
/root/bpfsnap/schedstat_snap --interval 5 --format raw --scope slices
/root/bpfsnap/schedstat_snap --interval 5 --format json --scope all
```


| Option              | Values           | Notes                                                                     |
| ------------------- | ---------------- | ------------------------------------------------------------------------- |
| `--interval` / `-i` | seconds          | default `5`                                                               |
| `--format` / `-f`   | `raw` | `json`   | default `raw`                                                             |
| `--scope` / `-s`    | `slices` | `all` | `slices` = cvm/uvm/services; `all` also emits per-service (default `all`) |
| `--outdir` / `-o`   | directory        | default `/var/log/cpu-stats`                                              |


Stop with Ctrl-C. The tool enables `kernel.sched_schedstats=1` while running and
restores the previous value on exit.

Output: `/var/log/cpu-stats/bpfsnap_<timestamp>.txt` (or `.jsonl` for json).

## How it works

1. Loads a BPF program on the AHV host 
2. Every `--interval` seconds, accounts run/wait into **cvm** / **uvm** /
  **services** (and optionally each service under `system.slice`)
3. Computes X, Y, Z, Demand, Supply, and cores for that interval
4. Appends one record to a timestamped file under `--outdir`
5. Runs until Ctrl-C / SIGTERM

Log files start with version metadata (`0.1.0`).

## Build (optional — only to refresh the prebuilt)

AHV has no toolchain. On a Linux build box with the target host's `vmlinux.h`:

```bash
cd bpf && bash build_static.sh
cp schedstat_snap prebuilt/schedstat_snap
```

Then re-upload to uranus (see above) and/or commit `bpf/prebuilt/schedstat_snap`.
See [bpf/prebuilt/README.md](bpf/prebuilt/README.md) for build details.
