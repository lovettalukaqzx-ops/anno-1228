# HE-based-2 PSI

Source directory: `hepsi-2/`

This implementation provides the second HE-based PSI variant. The CMake project can use its local `prelib/binfuse` copy or the shared `hepsi-1/prelib/binfuse` copy.

## Build

From the repository root:

```bash
./scripts/build_all.sh
```

Or build only this target:

```bash
source ./scripts/common.sh
build_protocol hepsi-2
```

## Run

```bash
./scripts/run_he_based_2.sh <log2_receiver_size> <log2_sender_size> <target_block_size> <port> <executable>
```

Example smoke run:

```bash
./scripts/run_he_based_2.sh 6 6 512 12347 PSI_v
```

The program launches sender and receiver in one process over localhost and reports timing, communication, and intersection correctness. The validated reviewer entry is `PSI_v`; the directory also builds the original `PSI` executable for comparison.

Expected success marker:

```text
Intersection correct:      YES
```

## Batch Evaluation

LAN emulation:

```bash
./scripts/run_he2_lan_full.sh --initial-repetitions 1 --max-repetitions 1 --jobs 1 --recv-exponents 20 --send-exponents 0
```

WAN emulation:

```bash
./scripts/run_he2_wan_full.sh --initial-repetitions 1 --max-repetitions 1 --jobs 1 --recv-exponents 20 --send-exponents 0
```

The LAN/WAN scripts configure Linux `tc` on the loopback device and may require `sudo`.
