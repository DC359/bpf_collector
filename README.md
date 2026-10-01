# bpf_collector

Collect AHV host CPU time per cgroup via eBPF.

## New host setup (AHV, as root)

```bash
mkdir -p /var/log/cpu-stats
wget -O /root/cgroup_cpu_snap \
  https://uranus.corp.nutanix.com/~dhruv.choudhary/cgroup_cpu_snap
chmod +x /root/cgroup_cpu_snap
```

Must live under `/root/` — AHV mounts `/tmp` as `noexec`.

## Run

Totals only (cvm / uvm / services):

```bash
/root/cgroup_cpu_snap --interval 5 --format raw --scope slices
```

Totals plus each service and each UVM:

```bash
/root/cgroup_cpu_snap --interval 5 --format raw --scope all
```

Stop with Ctrl-C.

Output goes to the terminal and to  
`/var/log/cpu-stats/cgroup_cpu_snap_<timestamp>.txt`.

## Options


| Option              | Values           | Default              |
| ------------------- | ---------------- | -------------------- |
| `--interval` / `-i` | seconds          | `5`                  |
| `--format` / `-f`   | `raw` | `json`   | `raw`                |
| `--scope` / `-s`    | `slices` | `all` | `all`                |
| `--outdir` / `-o`   | directory        | `/var/log/cpu-stats` |


- `slices` — cvm, uvm, services totals  
- `all` — same totals, plus each service and each UVM

## Metrics

Per thread the BPF program measures run (`delta_execution`), wait (`delta_ready`),
and alive time (T), then `delta_sleep = T − delta_execution − delta_ready` and
per-thread Demand. Published values are sums over threads in that
slice/service/UVM. `Supply = delta_execution`. `execution_cores` /
`ready_cores` (and `execution_ready_cores` = sum) use the wall-clock `--interval`.
`Demand` and `Supply` keep those names.

## If wget/uranus is unavailable

Copy the prebuilt from this repo to the host:

```bash
# Mac -> CVM
scp -O bpf/prebuilt/cgroup_cpu_snap nutanix@<CVM_IP>:/tmp/cgroup_cpu_snap

# CVM -> AHV
ssh nutanix@<CVM_IP>
scp -O /tmp/cgroup_cpu_snap root@<AHV_IP>:/root/cgroup_cpu_snap
ssh root@<AHV_IP> 'chmod +x /root/cgroup_cpu_snap'
```

## Rebuild (maintainers only)

On a Linux build box with the target host’s `vmlinux.h`:

```bash
cd bpf && bash build_static.sh
cp cgroup_cpu_snap prebuilt/cgroup_cpu_snap
```

Publish: See [bpf/prebuilt/README.md](bpf/prebuilt/README.md) for build details.