# bpf_collector

Collect AHV host CPU time per cgroup slice/service/UVM via eBPF. No VM or
workload orchestration.

## What you need on the host

Just the file `cgroup_cpu_snap`. Put it under `/root/` (AHV mounts
`/tmp` as `noexec`, so do not run from `/tmp`).

## Get the binary onto a new host

### Recommended: wget from uranus

```bash
# On AHV host, as root
mkdir -p /var/log/cpu-stats
wget -O /root/cgroup_cpu_snap \
  https://uranus.corp.nutanix.com/~dhruv.choudhary/cgroup_cpu_snap
chmod +x /root/cgroup_cpu_snap
```

### Alternatives if uranus is unreachable

- `scp -O` laptop → CVM → AHV `/root/cgroup_cpu_snap`
- SSH pipe (no scp subsystem):  
`ssh nutanix@<CVM> 'cat > /tmp/cgroup_cpu_snap' < bpf/prebuilt/cgroup_cpu_snap`  
then from CVM:  
`ssh root@<AHV> 'cat > /root/cgroup_cpu_snap' < /tmp/cgroup_cpu_snap && chmod +x /root/cgroup_cpu_snap`

## Run (AHV host, as root)

```bash
/root/cgroup_cpu_snap --interval 5 --format raw --scope slices
/root/cgroup_cpu_snap --interval 5 --format json --scope all
```


| Option              | Values           | Notes                                                                     |
| ------------------- | ---------------- | ------------------------------------------------------------------------- |
| `--interval` / `-i` | seconds          | default `5`                                                               |
| `--format` / `-f`   | `raw` \| `json`  | default `raw`                                                             |
| `--scope` / `-s`    | `slices` \| `all`| `slices` = cvm/uvm/services totals; `all` also emits per-service **and** per-UVM UUID (default `all`) |
| `--outdir` / `-o`   | directory        | default `/var/log/cpu-stats`                                              |


Stop with Ctrl-C. The tool enables `kernel.sched_schedstats=1` while running and
restores the previous value on exit.

Output: `/var/log/cpu-stats/cgroup_cpu_snap_<timestamp>.txt` (or `.jsonl` for json).

## How it works

1. Loads a BPF program on the AHV host
2. Every `--interval` seconds, accounts run/wait into **cvm** / **uvm** /
  **services** (and, with `--scope all`, each service under `system.slice`
  plus each UVM under `ahv-uvms.slice` named by guest UUID)
3. Computes X, Y, Z, Demand, Supply, and cores for that interval
4. Appends one record to a timestamped file under `--outdir` (and mirrors
  raw/json ticks to stdout)
5. Runs until Ctrl-C / SIGTERM

Log files start with version metadata (`0.2.0`).

With `--scope all --format raw`, each tick looks like:

```text
TICK ...
SLICE cvm ...
SLICE uvm ...
SLICE services ...
SERVICE sshd.service ...
UVM 2a516746-7653-4622-5d54-3423c5b9398c ...
END_TICK
```

JSON mode adds `"uvms": { "<uuid>": { ... }, ... }` alongside `"services"`.

## Build (optional — only to refresh the prebuilt)

AHV has no toolchain. On a Linux build box with the target host's `vmlinux.h`:

```bash
cd bpf && bash build_static.sh
cp cgroup_cpu_snap prebuilt/cgroup_cpu_snap
```

Then re-upload to uranus and/or commit `bpf/prebuilt/cgroup_cpu_snap`.
See [bpf/prebuilt/README.md](bpf/prebuilt/README.md) for build details.
