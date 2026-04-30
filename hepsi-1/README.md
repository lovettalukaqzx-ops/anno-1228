# HE-based-1 PSI

Source directory: `hepsi-1/`

This implementation provides the first HE-based PSI variant using the shared dependency bundle in `../crx1/preLibrary/`.

## Build

From the repository root:

```bash
./scripts/build_all.sh
```

Or build only this target:

```bash
source ./scripts/common.sh
build_protocol hepsi-1
```

## Run

```bash
./scripts/run_he_based_1.sh <log2_receiver_size> <log2_sender_size> <target_block_size> <port>
```

Example smoke run:

```bash
./scripts/run_he_based_1.sh 6 6 512 12346
```

The program launches sender and receiver in one process over localhost and reports timing, communication, and intersection correctness.

Expected success marker:

```text
Intersection correct:      YES
```

## Batch Evaluation

LAN emulation:

```bash
./scripts/run_he1_lan_full.sh --initial-repetitions 1 --max-repetitions 1 --jobs 1 --recv-exponents 20 --send-exponents 0 --block-sizes 6144
```

WAN emulation:

```bash
./scripts/run_he1_wan_full.sh --initial-repetitions 1 --max-repetitions 1 --jobs 1 --recv-exponents 20 --send-exponents 0 --block-sizes 6144
```

The LAN/WAN scripts configure Linux `tc` on the loopback device and may require `sudo`.
