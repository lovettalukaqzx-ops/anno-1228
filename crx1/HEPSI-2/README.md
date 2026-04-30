# VOKVS-based RBOKVS PSI

Source directory: `crx1/HEPSI-2/`

This implementation is the VOKVS-based RBOKVS variant. It uses the dependency bundle in `../preLibrary/`.

## Build

From the repository root:

```bash
./scripts/build_all.sh
```

Or build only this target:

```bash
source ./scripts/common.sh
build_protocol crx1/HEPSI-2
```

## Run

```bash
./scripts/run_vokvs_rbokvs.sh <log2_sender_size> <log2_receiver_size>
```

Example smoke run:

```bash
./scripts/run_vokvs_rbokvs.sh 0 20
```

Supported benchmark-size combinations in the current source:

- Sender sizes: `2^0`, `2^6`, `2^8`, `2^10`
- Receiver sizes: `2^20`, `2^22`, `2^24`

The runner starts sender and receiver in one process over localhost and prints preprocessing time, online time, and communication totals.
