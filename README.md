# bpf_collector

Collect AHV host CPU time per cgroup slice/service via eBPF. No VM or workload orchestration.

## How it works

1. Loads a BPF program on the AHV host (task iterator + exit/free hooks).
2. Every `--interval` seconds, sweeps live threads and accounts run/wait into
   `ahv-cvm` / `ahv-uvms` / `ahv.services` / `other` (and per-service under `system.slice`).
3. Computes X, Y, Z, Demand, Supply, and cores for that interval.
4. Appends one record to a timestamped file under `--outdir` (default `/tmp`).
5. Runs until Ctrl-C / SIGTERM.

## Run (AHV host, as root)

```bash
./scripts/bpfsnap_collect --interval 5 --format raw
./scripts/bpfsnap_collect --interval 5 --format json
```

- `--format raw` — text blocks
- `--format json` — one JSON object per line (`.jsonl`)

Stop: Ctrl-C. Output: `/tmp/bpfsnap_<timestamp>.txt` or `.jsonl`.

## Build

AHV has no toolchain. On a Linux build box with the target host's `vmlinux.h`:

```bash
cd bpf && bash build_static.sh
cp schedstat_snap prebuilt/
```

Ship `scripts/bpfsnap_collect` + `bpf/prebuilt/schedstat_snap` to the host.
