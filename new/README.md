# hash-based PSI

Source directory: `new/`

This implementation provides the hash-based PSI runner with OT and VOLE-backed preprocessing modes.

## Build

From the repository root:

```bash
./scripts/build_all.sh
```

Or build only this target:

```bash
source ./scripts/common.sh
build_protocol new
```

## Run

```bash
./scripts/run_hash_based.sh <log2_set_size> <ot|vole> <port>
```

Example smoke run:

```bash
./scripts/run_hash_based.sh 10 vole 12345
```

The program launches sender and receiver in one process over localhost and reports offline time, online time, communication, intersection size, and correctness.

Expected success marker:

```text
Intersection correct:      YES
```

Additional binaries built from this directory:

- `PSI`: end-to-end local two-party runner.
- `PSI_selftest`: internal tests for binfuse, cryptoTools channel, OT triples, and VOLE triples.
- `PSI_profile`: preprocessing profiler.
- `PSI_batch_stats`: repeated benchmark runner.
