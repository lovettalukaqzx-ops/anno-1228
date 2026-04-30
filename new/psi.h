#ifndef PSI_PSI_H
#define PSI_PSI_H

#include <cryptoTools/Common/block.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <map>

#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <coproto/Socket/LocalAsyncSock.h>
#include <coproto/Socket/AsioSocket.h>
#include <macoro/sync_wait.h>
#include <macoro/when_all.h>

#include "binfuse/filter.hpp"
#include "binfuse/sharded_filter.hpp"

using namespace osuCrypto;

// ============================================================
//  Protocol Parameters
// ============================================================

extern int Number;

// Runtime switch: false = IKNP OT, true = SilentOT (VOLE)
extern bool use_vole;

// Public seed shared by both parties for Binary Fuse Filter construction.
// Both Sender and Receiver must use the same seed so that positions()
// returns identical bin indices for the same key.
constexpr uint64_t kFilterSeed = 0x50534946696C7472ULL;

// Cuckoo hash table parameters (used by both Sender's T_C and Receiver's T_S).
constexpr double   kCuckooBinScaler = 1.27;
constexpr u64      kCuckooNumHashes = 3;
const oc::block    kCuckooHashSeed  = toBlock(0x4355434b4f4f31ULL, 0x5053494841534831ULL);

// ============================================================
//  Type Aliases
// ============================================================

using sm3_digest_t = std::array<std::uint8_t, 32>;

// ============================================================
//  Utilities
// ============================================================

// --- SM3 hashing ---

// Hash a single 128-bit block into a 64-bit value using SM3 (quantum-resistant,
// 256-bit cryptographic hash). Takes the first 8 bytes of the 32-byte digest.
uint64_t sm3_hash_block_to_u64(const oc::block& blk);

// Hash a vector of blocks into a vector of uint64_t (suitable for binfuse::filter64).
std::vector<uint64_t> sm3_hash_keys(const std::vector<oc::block>& keys);

// Hash a single uint64_t into a 256-bit SM3 digest (for step 6/7 comparison).
sm3_digest_t sm3_hash_u64(std::uint64_t value);

// --- Bit-level conversion (for OT) ---

BitVector uint64s_to_bits(const std::vector<uint64_t>& vals);
std::vector<uint64_t> bits_to_uint64s(const std::vector<oc::block>& msgs, size_t m);

// --- Key generation ---

void key_init(std::vector<oc::block>& key, bool choose);

// --- Cuckoo / protocol helpers ---

CuckooParam make_cuckoo_param(std::size_t n);

std::vector<uint64_t> compute_associated_values(
    const std::vector<uint64_t>& hashed_keys,
    const binfuse::filter64&     filter,
    const std::vector<uint64_t>& mult_share);

// ============================================================
//  Beaver Triple Generation (F_BT)
// ============================================================
//
//  Sender (P0) holds (a, b), Receiver (P1) holds (a, b).
//  After the protocol:
//      c_sender[i] XOR c_receiver[i] = (a_s[i] XOR a_r[i]) AND (b_s[i] XOR b_r[i])
//
//  Each party calls its own function; they communicate via coproto::Socket.
//
//  Protocol flow on the socket (sequential, both parties stay in sync):
//    Phase 1  cross term 1 (a_sender & b_receiver):
//             Sender = OT ext sender,  Receiver = OT ext receiver
//    Phase 2  cross term 2 (a_receiver & b_sender):
//             Sender = OT ext receiver, Receiver = OT ext sender
//

// Sender side (P0): coroutine, call with co_await or macoro::sync_wait
macoro::task<void> beaver_triple_sender(
    coproto::Socket sock,
    const std::vector<uint64_t>& a, const std::vector<uint64_t>& b,
    std::vector<uint64_t>& c);

// Receiver side (P1): coroutine, call with co_await or macoro::sync_wait
macoro::task<void> beaver_triple_receiver(
    coproto::Socket sock,
    const std::vector<uint64_t>& a, const std::vector<uint64_t>& b,
    std::vector<uint64_t>& c);

// ============================================================
//  Beaver Triple Generation — VOLE-based (SilentVole<block,bool,CoeffCtxGF2>)
// ============================================================
//
//  Same contract as the OT-based versions above but uses SilentVole
//  for cross-term sharing.  Communication is sublinear in numCorr
//  (only O(security_param) base OTs), which drastically reduces
//  offline traffic compared to IKNP for large m.
//

// Sender side (P0): coroutine
macoro::task<void> beaver_triple_sender_vole(
    coproto::Socket sock,
    const std::vector<uint64_t>& a, const std::vector<uint64_t>& b,
    std::vector<uint64_t>& c);

// Receiver side (P1): coroutine
macoro::task<void> beaver_triple_receiver_vole(
    coproto::Socket sock,
    const std::vector<uint64_t>& a, const std::vector<uint64_t>& b,
    std::vector<uint64_t>& c);

// ============================================================
//  PSI Protocol (Sender / Receiver)
// ============================================================

class Sender {
public:
    // --- Input ---
    std::vector<oc::block> keys;
    std::vector<uint64_t>  hashed_keys;   // SM3-hashed keys (input to binfuse filter)

    // --- Binary Fuse Filter ---
    binfuse::filter64      filter;        // T_X in the protocol
    std::size_t            m = 0;         // Number of bins (ArrayLength)

    // --- Beaver triple shares (per bin i) ---
    std::vector<uint64_t> a_share;
    std::vector<uint64_t> b_share;
    std::vector<uint64_t> c_share;

    // --- Step 2: random mask r_1 and precomputed local openings (d_i^1, e_i^1) ---
    uint64_t              random_mask = 0;
    std::vector<uint64_t> open_local;
    std::vector<uint64_t> open_peer;

    // --- Step 2.4: Beaver multiplication share s_i^1 ---
    std::vector<uint64_t> mult_share;

    // --- Step 3: associated values and Cuckoo table T_C ---
    std::vector<uint64_t> associated_values;
    oc::CuckooIndex<oc::ThreadSafe> cuckoo;
    std::vector<uint64_t> cuckoo_table;

    // --- Step 6: SM3-256 digest of each T_C bin payload ---
    std::vector<sm3_digest_t> cuckoo_table_hashes;

    void init(coproto::Socket& sock, std::vector<oc::block>& sendK);
    void output(coproto::Socket& sock);
};

class Receiver {
public:
    // --- Input ---
    std::vector<oc::block> keys;
    std::vector<uint64_t>  hashed_keys;   // SM3-hashed keys (input to binfuse filter)

    // --- Binary Fuse Filter ---
    binfuse::filter64      filter;        // T_Y in the protocol
    std::size_t            m = 0;         // Number of bins (ArrayLength)

    // --- Beaver triple shares (per bin i) ---
    std::vector<uint64_t> a_share;
    std::vector<uint64_t> b_share;
    std::vector<uint64_t> c_share;

    // --- Step 2: random mask r_2 and precomputed local openings (d_i^2, e_i^2) ---
    uint64_t              random_mask = 0;
    std::vector<uint64_t> open_local;
    std::vector<uint64_t> open_peer;

    // --- Step 2.4: Beaver multiplication share s_i^2 ---
    std::vector<uint64_t> mult_share;

    // --- Step 4: associated values and Simple hash table T_S ---
    std::vector<uint64_t>                  associated_values;
    std::vector<std::vector<std::size_t>>  simple_item_indices;

    // Flat buffer layout (pre-allocated in init, filled in output):
    //   flat_bin_offsets[i] = start index for bin i in flat_values/flat_hashes
    //   flat_bin_offsets[num_bins] = flat_total_entries
    std::vector<std::size_t>  flat_bin_offsets;
    std::size_t               flat_total_entries = 0;
    std::vector<uint64_t>     flat_values;
    std::vector<sm3_digest_t> flat_hashes;

    // --- Step 6/7: sender digest reception and intersection output ---
    std::vector<sm3_digest_t>              sender_payload_hashes;
    std::vector<oc::block>                 intersection;
    std::map<std::size_t, oc::block>       receiver_sender_psi;

    void init(coproto::Socket& sock, std::vector<oc::block>& recvK);
    void output(coproto::Socket& sock);
};

#endif //PSI_PSI_H
