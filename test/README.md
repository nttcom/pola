# Scenario Test

## 1. Install Required Tools and Container Images

See [Containerlab Setup Prerequisites](../setup/containerlab-prerequisites.md) for detailed setup instructions.

Quick checklist:

- Docker installed and executable without sudo
- Containerlab installed
- uv (Python package manager) installed
- Container images:
  - `ios-xr/xrd-control-plane:24.4.1` (if running XRd-based topologies)
  - `vrnetlab/juniper_vjunos-router:26.2R1.7` (if running Juniper-based topologies)
  - `quay.io/frrouting/frr:10.7.1` (if running FRRouting-based topologies)
- MPLS kernel modules loaded (if using SR-MPLS)

## 2. Synchronize Dependencies with uv

```bash
cd <repository-root>/test
uv sync
```

## 3. Place the Target Binary

Place the binaries you want to test in the appropriate location, or run
`make test-deps` from the repository root to build and stage them.

For example:

```bash
$ ls -la <repository-root>/test/bin
drwxrwxr-x 2 --- ---     4096 Sep  3 06:06 .
drwxrwxr-x 9 --- ---     4096 Aug 28 01:23 ..
-rw-rw-r-- 1 --- ---        2 Sep  3 06:06 .gitignore
-rwxrwxr-x 1 --- --- 24878822 Aug 31 16:51 gobgp
-rwxrwxr-x 1 --- --- 29413392 Aug 31 16:42 gobgpd
-rwxrwxr-x 1 --- --- 16308672 Sep  2 09:46 pola
-rwxrwxr-x 1 --- --- 18156563 Sep  2 13:16 polad
```

## 4. Run the Test

Run the full scenario suite:

```bash
uv run pytest -s
```

From the repository root, the same run is available as a Make target:

```bash
make test-scenario
```

> [!NOTE]
> The `-s` option is required; without it, scenario tests may fail.

### Running a Subset

A full run boots every Containerlab topology, so it takes a while. Use these
options to run a smaller subset while iterating:

```bash
make test-scenario PYTEST_ARGS="-s -x"                      # stop at the first failure
make test-scenario PYTEST_ARGS="-s --lf"                    # rerun only the last failures
make test-scenario PYTEST_ARGS="-s scenario/sr-mpls/isis"   # one lab
make test-scenario PYTEST_ARGS="-s -k show_ted"             # TED tests in every lab
make test-scenario PYTEST_ARGS="-s -k loose_source_routing" # one test case
```

| Lab directory | Topology name | Routers | Vendors | Underlay |
| --- | --- | --- | --- | --- |
| `scenario/sr-mpls/isis` | `sr-mpls-isis` | 5 | XRd, vJunos, FRR | IS-IS / IPv4 / SR-MPLS |
| `scenario/sr-mpls/isis-dual-stack` | `sr-mpls-isis-dual-stack` | 5 | XRd, vJunos, FRR | IS-IS / IPv4+IPv6 / SR-MPLS |
| `scenario/sr-mpls/ospf` | `sr-mpls-ospf` | 4 | XRd, FRR | OSPFv2+OSPFv3 / IPv4 / SR-MPLS |
| `scenario/srv6/isis` | `srv6-isis` | 4 | XRd, vJunos | IS-IS / IPv6 / SRv6 (full-length SIDs) |
| `scenario/srv6-usid/isis` | `srv6-usid-isis` | 4 | XRd, vJunos | IS-IS / IPv6 / SRv6 uSID |

### Running in Parallel

```bash
make test-scenario-parallel
```

By default, 3 workers are used. Adjust this with:

```bash
make test-scenario-parallel TEST_WORKERS=2
```

New tests must declare the topology they use with
`@pytest.mark.xdist_group("<topology name>")` so tests sharing a topology run
on the same worker. A parallel run boots every topology at once, so it requires
enough memory for all of them.

> [!IMPORTANT]
> When running `pytest -n` directly, always use `--dist loadgroup`.
> Otherwise, multiple workers may deploy the same topology simultaneously.
