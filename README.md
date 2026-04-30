# PSI Protocol Implementations

This repository contains the runnable reviewer artifact for five PSI protocol implementations:

| Protocol label | Source directory | Reviewer run script |
| --- | --- | --- |
| hash-based | `new/` | `./scripts/run_hash_based.sh` |
| HE-based-1 | `hepsi-1/` | `./scripts/run_he_based_1.sh` |
| HE-based-2 | `hepsi-2/` | `./scripts/run_he_based_2.sh` |
| VOKVS-based PaXoS | `crx1/HEPSI-1/` | `./scripts/run_vokvs_paxos.sh` |
| VOKVS-based RBOKVS | `crx1/HEPSI-2/` | `./scripts/run_vokvs_rbokvs.sh` |

The code is self-contained under this repository and does not require any external local source tree.

## Environment

Tested on Linux with:

- CMake 3.20 or newer
- `g++-11` or newer, or `clang++` with C++20 support
- `bash`, `make`, `pthread`

The reviewer dependency bundle is under `crx1/preLibrary/` and includes the prebuilt crypto libraries used by the CMake projects.

## Quick Start

Build all five protocol targets:

```bash
./scripts/build_all.sh
```

Run the smoke-test suite:

```bash
./scripts/run_smoke_tests.sh
```

The smoke tests use small parameters where possible. Successful runs print `Intersection correct: YES` for the hash-based and HE-based variants. The VOKVS variants print timing and communication totals after completing the two-party local run.

## Individual Runs

Hash-based PSI:

```bash
./scripts/run_hash_based.sh 10 vole 12345
./scripts/run_hash_based.sh 10 ot 12345
```

HE-based-1:

```bash
./scripts/run_he_based_1.sh 6 6 512 12346
```

HE-based-2:

```bash
./scripts/run_he_based_2.sh 6 6 512 12347 PSI_v
```

VOKVS-based PaXoS:

```bash
./scripts/run_vokvs_paxos.sh 0 20
```

VOKVS-based RBOKVS:

```bash
./scripts/run_vokvs_rbokvs.sh 0 20
```

Parameter convention:

- Hash-based: `log2(set_size)`, mode `ot` or `vole`, TCP port.
- HE-based-1: `log2(receiver_size)`, `log2(sender_size)`, target block size, TCP port.
- HE-based-2: `log2(receiver_size)`, `log2(sender_size)`, target block size, TCP port, executable name. The validated reviewer entry is `PSI_v`.
- VOKVS variants: `log2(sender_size)`, `log2(receiver_size)`.

## Full LAN/WAN Batch Scripts

The HE-based directories also include batch-stat runners. The top-level wrappers set up clean build paths first:

```bash
./scripts/run_he1_lan_full.sh
./scripts/run_he1_wan_full.sh
./scripts/run_he2_lan_full.sh
./scripts/run_he2_wan_full.sh
```

These wrappers use Linux `tc` on loopback and may require `sudo`. You can pass the underlying `PSI_batch_stats` options directly, for example:

```bash
./scripts/run_he1_lan_full.sh --initial-repetitions 1 --max-repetitions 1 --jobs 1 --recv-exponents 20 --send-exponents 0 --block-sizes 6144
```

## Repository Notes

- Build outputs are generated in `build-review/` and ignored by Git.
- Old copied `build/` directories are ignored because their CMake caches are machine-specific.
- `crx1/preCode/` is ignored for upload. It contains about 9 GB of historical archives/generated data and is not used by the reviewer run scripts.
- `crx1/preInstall/` is ignored for upload. The reviewer scripts use the portable dependency bundle in `crx1/preLibrary/`.
