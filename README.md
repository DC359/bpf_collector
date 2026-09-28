# bpf_collector

Collect AHV host CPU time per cgroup slice/service via eBPF. No VM or workload orchestration.

## How it works

1. Loads a BPF program on the AHV host (task iterator + exit hook).
2. Every `--interval` seconds, sweeps live threads and accounts run/wait into
   **cvm** / **uvm** / **services** (and optionally each service under `system.slice`).
3. Computes X, Y, Z, Demand, Supply, and cores for that interval.
4. Appends one record to a timestamped file under `--outdir` (default `/var/log/cpu-stats`).
5. Runs until Ctrl-C / SIGTERM.

Log files start with version metadata (`0.1.0`).

## Run (AHV host, as root)

AHV mounts `/tmp` as `noexec`, so run the binary from an executable path:

```bash
mkdir -p /root/bpfsnap
cp bpf/prebuilt/schedstat_snap /root/bpfsnap/
chmod +x /root/bpfsnap/schedstat_snap

/root/bpfsnap/schedstat_snap --interval 5 --format raw --scope slices
/root/bpfsnap/schedstat_snap --interval 5 --format json --scope all
```

- `--format raw` — text blocks
- `--format json` — one JSON object per line (`.jsonl`)
- `--scope slices` — cvm, uvm, services only
- `--scope all` — those slices plus per-service lines (default)
- `--outdir DIR` — log directory (default `/var/log/cpu-stats`)

Stop: Ctrl-C. Output: `/var/log/cpu-stats/bpfsnap_<timestamp>.txt` or `.jsonl`.

## Build

AHV has no toolchain. On a Linux build box with the target host's `vmlinux.h`:

```bash
cd bpf && bash build_static.sh
cp schedstat_snap prebuilt/
```

Ship `bpf/prebuilt/schedstat_snap` to the host.
