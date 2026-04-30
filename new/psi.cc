#include "psi.h"
#include <cstring>
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <sys/time.h>
#include <gmssl/sm3.h>
#include <immintrin.h>
#include "sm3_avx512.h"

using namespace std;
using namespace osuCrypto;

int Number = 100;
bool use_vole = true;

// ============================================================
//  Utilities — SM3 hashing
// ============================================================

// SM3: a 256-bit cryptographic hash (Chinese national standard, similar to
// SHA-256). Considered quantum-resistant — Grover's algorithm only halves the
// effective security, so 256 bits → 128-bit post-quantum security.
//
// We hash a 16-byte block and take the first 8 bytes of the 32-byte digest.
uint64_t sm3_hash_block_to_u64(const oc::block& blk) {
    uint8_t inputData[16];
    memcpy(inputData, &blk, 16);

    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, inputData, sizeof(inputData));

    uint8_t digest[32];
    sm3_finish(&ctx, digest);

    uint64_t out;
    memcpy(&out, digest, sizeof(uint64_t));
    return out;
}

vector<uint64_t> sm3_hash_keys(const vector<oc::block>& keys) {
    vector<uint64_t> out(keys.size());
    for (size_t i = 0; i < keys.size(); i++) {
        out[i] = sm3_hash_block_to_u64(keys[i]);
    }
    return out;
}

sm3_digest_t sm3_hash_u64(uint64_t value)
{
    sm3_digest_t digest{};
    SM3_CTX      ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
    sm3_finish(&ctx, digest.data());
    return digest;
}

// ============================================================
//  AVX-512 batched SM3 for uint64_t inputs
// ============================================================

static void sm3_hash_u64_batch(const uint64_t* input,
                               sm3_digest_t* output,
                               size_t count)
{
#ifdef __AVX512F__
    size_t i = 0;
    for (; i + 16 <= count; i += 16) {
        sm3_avx512::hash_u64_x16(input + i, output + i);
    }
    for (; i < count; ++i) {
        output[i] = sm3_hash_u64(input[i]);
    }
#else
    for (size_t i = 0; i < count; ++i) {
        output[i] = sm3_hash_u64(input[i]);
    }
#endif
}

// AVX-256 fast 32-byte digest comparison
static inline bool digest_equal(const sm3_digest_t& a, const sm3_digest_t& b) {
#ifdef __AVX2__
    __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a.data()));
    __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b.data()));
    __m256i cmp = _mm256_cmpeq_epi8(va, vb);
    return _mm256_movemask_epi8(cmp) == static_cast<int>(0xFFFFFFFF);
#else
    return a == b;
#endif
}

// ============================================================
//  Utilities — Bit-level conversion (for OT)
// ============================================================

BitVector uint64s_to_bits(const vector<uint64_t>& vals) {
    size_t n = vals.size();
    BitVector bv(n * 64);
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < 64; j++) {
            bv[i * 64 + j] = (vals[i] >> j) & 1;
        }
    }
    return bv;
}

vector<uint64_t> bits_to_uint64s(const vector<oc::block>& msgs, size_t m) {
    vector<uint64_t> out(m, 0);
    for (size_t i = 0; i < m; i++) {
        uint64_t val = 0;
        for (size_t j = 0; j < 64; j++) {
            uint64_t low;
            memcpy(&low, &msgs[i * 64 + j], sizeof(uint64_t));
            val |= (low & 1) << j;
        }
        out[i] = val;
    }
    return out;
}

// ============================================================
//  Utilities — Key generation
// ============================================================

void key_init(vector<oc::block>& key, bool choose) {
    oc::PRNG prng(toBlock(123));
    oc::PRNG prng0(toBlock(456));
    oc::PRNG prng1(toBlock(789));

    if (choose) {
        for (int i = 0; i < Number; i++) {
            key[i] = prng.get<oc::block>();
        }
        for (size_t i = Number; i < key.size(); i++) {
            key[i] = prng0.get<oc::block>();
        }
    } else {
        for (int i = 0; i < Number; i++) {
            key[i] = prng.get<oc::block>();
        }
        for (size_t i = Number; i < key.size(); i++) {
            key[i] = prng1.get<oc::block>();
        }
    }
}

// ============================================================
//  Utilities — Cuckoo / protocol helpers
// ============================================================

CuckooParam make_cuckoo_param(size_t n) {
    return CuckooParam{0, kCuckooBinScaler, kCuckooNumHashes, static_cast<u64>(n)};
}

vector<uint64_t> compute_associated_values(
    const vector<uint64_t>& hashed_keys,
    const binfuse::filter64&     filter,
    const vector<uint64_t>& mult_share)
{
    const size_t n = hashed_keys.size();
    vector<uint64_t> associated(n);

#ifdef __AVX512F__
    // Inlined & vectorised position computation avoids per-item function-call
    // overhead and the is_populated() branch.  We process 8 keys per iteration
    // using AVX-512: murmur64 hash → position arithmetic → gather → XOR.
    const uint64_t seed     = filter.seed();
    const uint32_t seg_cl   = filter.segment_count_length();
    const uint32_t seg_len  = filter.segment_length();
    const uint32_t seg_mask = filter.segment_length_mask();
    const uint64_t* ms      = mult_share.data();

    const __m512i v_seed    = _mm512_set1_epi64(seed);
    const __m512i v_scl     = _mm512_set1_epi64(seg_cl);
    const __m512i v_seglen  = _mm512_set1_epi64(seg_len);
    const __m512i v_mask    = _mm512_set1_epi64(seg_mask);
    const __m512i v_lo32    = _mm512_set1_epi64(0xFFFFFFFF);
    const __m512i v_m1      = _mm512_set1_epi64(0xff51afd7ed558ccdULL);
    const __m512i v_m2      = _mm512_set1_epi64(0xc4ceb9fe1a85ec53ULL);

    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        // --- murmur64(key + seed) ---
        __m512i h = _mm512_add_epi64(
            _mm512_loadu_si512(hashed_keys.data() + i), v_seed);
        h = _mm512_xor_epi64(h, _mm512_srli_epi64(h, 33));
        h = _mm512_mullo_epi64(h, v_m1);
        h = _mm512_xor_epi64(h, _mm512_srli_epi64(h, 33));
        h = _mm512_mullo_epi64(h, v_m2);
        h = _mm512_xor_epi64(h, _mm512_srli_epi64(h, 33));

        // --- mulhi(h, SegmentCountLength) ---
        __m512i p_lo = _mm512_mul_epu32(h, v_scl);
        __m512i p_hi = _mm512_mul_epu32(_mm512_srli_epi64(h, 32), v_scl);
        __m512i hi = _mm512_srli_epi64(
            _mm512_add_epi64(p_hi, _mm512_srli_epi64(p_lo, 32)), 32);

        // --- three bin positions ---
        __m512i h0 = _mm512_and_epi64(hi, v_lo32);
        __m512i h1 = _mm512_add_epi64(h0, v_seglen);
        __m512i h2 = _mm512_add_epi64(h1, v_seglen);
        h1 = _mm512_xor_epi64(h1,
            _mm512_and_epi64(_mm512_srli_epi64(h, 18), v_mask));
        h2 = _mm512_xor_epi64(h2, _mm512_and_epi64(h, v_mask));

        // --- gather mult_share[h0/h1/h2] and XOR ---
        __m512i g0 = _mm512_i64gather_epi64(h0, ms, 8);
        __m512i g1 = _mm512_i64gather_epi64(h1, ms, 8);
        __m512i g2 = _mm512_i64gather_epi64(h2, ms, 8);

        _mm512_storeu_si512(associated.data() + i,
            _mm512_xor_epi64(_mm512_xor_epi64(g0, g1), g2));
    }
    // Scalar tail
    for (; i < n; ++i) {
        const auto pos = filter.positions(hashed_keys[i]);
        associated[i] = mult_share[pos[0]] ^ mult_share[pos[1]] ^ mult_share[pos[2]];
    }
#else
    for (size_t i = 0; i < n; ++i) {
        const auto pos = filter.positions(hashed_keys[i]);
        associated[i] = mult_share[pos[0]] ^ mult_share[pos[1]] ^ mult_share[pos[2]];
    }
#endif

    return associated;
}

// ============================================================
//  Beaver Triple — Sender (P0)
// ============================================================
//
//  Phase 1: P0 is OT ext sender  (input = a bits)
//  Phase 2: P0 is OT ext receiver (choice = b bits)
//  Finally:  c ^= local term (a & b)
//

macoro::task<void> beaver_triple_sender(
    coproto::Socket sock,
    const vector<uint64_t>& a, const vector<uint64_t>& b,
    vector<uint64_t>& c)
{
    size_t m = a.size();
    size_t numOTs = m * 64;
    c.assign(m, 0);

    oc::PRNG prng(toBlock(1000));

    // Phase 1: cross term (a_sender & b_receiver)
    // P0 = OT sender (random OT + 1-bit Gilboa correction)
    {
        IknpOtExtSender extSender;
        co_await extSender.genBaseOts(prng, sock);

        // Random OT: sender gets (t0[k], t1[k]) pairs
        vector<array<oc::block, 2>> otMsgs(numOTs);
        co_await extSender.send(otMsgs, prng, sock);

        // Compute d[k] = x_bit XOR (t0[k].bit0 XOR t1[k].bit0)
        BitVector dCorr(numOTs);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low, t1_low;
                memcpy(&t0_low, &otMsgs[k][0], sizeof(uint64_t));
                memcpy(&t1_low, &otMsgs[k][1], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                dCorr[k] = x_bit ^ ((t0_low ^ t1_low) & 1);
            }
        }

        // Exchange corrections concurrently to avoid deadlock
        BitVector eCorr(numOTs);
        co_await macoro::when_all_ready(
            sock.send(std::move(dCorr)),
            sock.recv(eCorr)
        );

        // Sender share: z_s = t0.bit0 XOR (x_bit AND e)
        vector<uint64_t> shares(m, 0);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low;
                memcpy(&t0_low, &otMsgs[k][0], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                uint64_t s = (t0_low & 1) ^ (x_bit & (uint64_t)eCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
    }

    // Phase 2: cross term (a_receiver & b_sender)
    // P0 = OT receiver (random OT + 1-bit Gilboa correction)
    {
        IknpOtExtReceiver extRecv;
        co_await extRecv.genBaseOts(prng, sock);

        // Random OT: receiver gets (choice[k], t_c[k])
        BitVector choices(numOTs);
        choices.randomize(prng);
        vector<oc::block> otMsgs(numOTs);
        co_await extRecv.receive(choices, otMsgs, prng, sock);

        // Compute e[k] = y_bit XOR choice[k]
        BitVector eCorr(numOTs);
        for (size_t i = 0; i < m; i++)
            for (size_t j = 0; j < 64; j++)
                eCorr[i * 64 + j] = ((b[i] >> j) & 1) ^ choices[i * 64 + j];

        // Exchange corrections concurrently
        BitVector dCorr(numOTs);
        co_await macoro::when_all_ready(
            sock.send(std::move(eCorr)),
            sock.recv(dCorr)
        );

        // Receiver share: z_r = t_c.bit0 XOR (c AND d)
        // NOTE: use the random OT choice bit c, NOT y_bit
        vector<uint64_t> shares(m, 0);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t tc_low;
                memcpy(&tc_low, &otMsgs[k], sizeof(uint64_t));
                uint64_t s = (tc_low & 1) ^ ((uint64_t)choices[k] & (uint64_t)dCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
    }

    // Local term
    for (size_t i = 0; i < m; i++) c[i] ^= (a[i] & b[i]);
}

// ============================================================
//  Beaver Triple — Receiver (P1)
// ============================================================
//
//  Phase 1: P1 is OT ext receiver (choice = b bits)
//  Phase 2: P1 is OT ext sender   (input = a bits)
//  Finally:  c ^= local term (a & b)
//

macoro::task<void> beaver_triple_receiver(
    coproto::Socket sock,
    const vector<uint64_t>& a, const vector<uint64_t>& b,
    vector<uint64_t>& c)
{
    size_t m = a.size();
    size_t numOTs = m * 64;
    c.assign(m, 0);

    oc::PRNG prng(toBlock(2000));

    // Phase 1: cross term (a_sender & b_receiver)
    // P1 = OT receiver (random OT + 1-bit Gilboa correction)
    {
        IknpOtExtReceiver extRecv;
        co_await extRecv.genBaseOts(prng, sock);

        // Random OT: receiver gets (choice[k], t_c[k])
        BitVector choices(numOTs);
        choices.randomize(prng);
        vector<oc::block> otMsgs(numOTs);
        co_await extRecv.receive(choices, otMsgs, prng, sock);

        // Compute e[k] = y_bit XOR choice[k]
        BitVector eCorr(numOTs);
        for (size_t i = 0; i < m; i++)
            for (size_t j = 0; j < 64; j++)
                eCorr[i * 64 + j] = ((b[i] >> j) & 1) ^ choices[i * 64 + j];

        // Exchange corrections concurrently to avoid deadlock
        BitVector dCorr(numOTs);
        co_await macoro::when_all_ready(
            sock.send(std::move(eCorr)),
            sock.recv(dCorr)
        );

        // Receiver share: z_r = t_c.bit0 XOR (c AND d)
        // NOTE: use the random OT choice bit c, NOT y_bit
        vector<uint64_t> shares(m, 0);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t tc_low;
                memcpy(&tc_low, &otMsgs[k], sizeof(uint64_t));
                uint64_t s = (tc_low & 1) ^ ((uint64_t)choices[k] & (uint64_t)dCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
    }

    // Phase 2: cross term (a_receiver & b_sender)
    // P1 = OT sender (random OT + 1-bit Gilboa correction)
    {
        IknpOtExtSender extSender;
        co_await extSender.genBaseOts(prng, sock);

        // Random OT: sender gets (t0[k], t1[k]) pairs
        vector<array<oc::block, 2>> otMsgs(numOTs);
        co_await extSender.send(otMsgs, prng, sock);

        // Compute d[k] = x_bit XOR (t0[k].bit0 XOR t1[k].bit0)
        BitVector dCorr(numOTs);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low, t1_low;
                memcpy(&t0_low, &otMsgs[k][0], sizeof(uint64_t));
                memcpy(&t1_low, &otMsgs[k][1], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                dCorr[k] = x_bit ^ ((t0_low ^ t1_low) & 1);
            }
        }

        // Exchange corrections concurrently
        BitVector eCorr(numOTs);
        co_await macoro::when_all_ready(
            sock.send(std::move(dCorr)),
            sock.recv(eCorr)
        );

        // Sender share: z_s = t0.bit0 XOR (x_bit AND e)
        vector<uint64_t> shares(m, 0);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low;
                memcpy(&t0_low, &otMsgs[k][0], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                uint64_t s = (t0_low & 1) ^ (x_bit & (uint64_t)eCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
    }

    // Local term
    for (size_t i = 0; i < m; i++) c[i] ^= (a[i] & b[i]);
}

// ============================================================
//  Beaver Triple — VOLE-based (SilentOT with 1-bit corrections)
// ============================================================
//
//  Uses SilentOtExt to generate random OT pairs, then converts
//  to AND-triple shares with compact 1-bit corrections instead
//  of the generic sendChosen/receiveChosen (which sends 32 bytes
//  per OT).
//
//  For each cross-term "x AND y" (sender knows x, receiver knows y):
//
//    Random OT gives:
//      Sender:   (t0, t1)        — two random blocks per OT
//      Receiver: (c, t_c)        — random choice bit and one block
//
//    Conversion (Gilboa):
//      Sender sends:    d = x XOR (t0.bit0 XOR t1.bit0)   [1 bit]
//      Receiver sends:  e = y XOR c                         [1 bit]
//      Sender share:    z_s = t0.bit0 XOR (x AND e)
//      Receiver share:  z_r = t_c.bit0 XOR (y AND d)
//
//    Then z_s XOR z_r = x AND y.
//
//  Total correction traffic per phase: 2 * numOTs bits = numOTs/4 bytes.
//  For n=2^22: ~75 MB per phase instead of ~9.7 GB with sendChosen.
//

macoro::task<void> beaver_triple_sender_vole(
    coproto::Socket sock,
    const vector<uint64_t>& a, const vector<uint64_t>& b,
    vector<uint64_t>& c)
{
    size_t m = a.size();
    size_t numOTs = m * 64;
    c.assign(m, 0);

    oc::PRNG prng(toBlock(1000));

    // ---- Phase 1: cross term (a_sender & b_receiver) ----
    // P0 = random OT sender, P1 = random OT receiver
    {
        SilentOtExtSender extSender;
        co_await extSender.genBaseOts(prng, sock);

        // Generate random OT pairs: sender gets (t0[k], t1[k])
        vector<array<oc::block, 2>> otMsgs(numOTs);
        co_await extSender.send(otMsgs, prng, sock);

        // Sender's chosen input for this cross term: x[i][j] = a[i].bit_j
        // Compute and send d[k] = x_bit XOR (t0[k].bit0 XOR t1[k].bit0)
        BitVector dCorr(numOTs);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low, t1_low;
                memcpy(&t0_low, &otMsgs[k][0], sizeof(uint64_t));
                memcpy(&t1_low, &otMsgs[k][1], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                dCorr[k] = x_bit ^ ((t0_low ^ t1_low) & 1);
            }
        }
        // Exchange corrections concurrently to avoid deadlock
        BitVector eCorr(numOTs);
        co_await macoro::when_all_ready(
            sock.send(std::move(dCorr)),
            sock.recv(eCorr)
        );

        // Sender share: z_s = t0.bit0 XOR (x_bit AND e)
        vector<uint64_t> shares(m, 0);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low;
                memcpy(&t0_low, &otMsgs[k][0], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                uint64_t s = (t0_low & 1) ^ (x_bit & (uint64_t)eCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
    }

    // ---- Phase 2: cross term (a_receiver & b_sender) ----
    // P0 = random OT receiver, P1 = random OT sender
    {
        SilentOtExtReceiver extRecv;
        co_await extRecv.genBaseOts(prng, sock);

        // Generate random OT: receiver gets (c[k], t_c[k])
        BitVector choices(numOTs);
        choices.randomize(prng);
        vector<oc::block> otMsgs(numOTs);
        co_await extRecv.receive(choices, otMsgs, prng, sock);

        // Receiver's chosen input for this cross term: y[i][j] = b[i].bit_j
        // Send e[k] = y_bit XOR c[k]
        BitVector eCorr(numOTs);
        for (size_t i = 0; i < m; i++)
            for (size_t j = 0; j < 64; j++)
                eCorr[i * 64 + j] = ((b[i] >> j) & 1) ^ choices[i * 64 + j];

        // Exchange corrections concurrently to avoid deadlock
        BitVector dCorr(numOTs);
        co_await macoro::when_all_ready(
            sock.send(std::move(eCorr)),
            sock.recv(dCorr)
        );

        // Receiver share: z_r = t_c.bit0 XOR (c AND d)
        // NOTE: use the random OT choice bit c, NOT y_bit
        vector<uint64_t> shares(m, 0);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t tc_low;
                memcpy(&tc_low, &otMsgs[k], sizeof(uint64_t));
                uint64_t s = (tc_low & 1) ^ ((uint64_t)choices[k] & (uint64_t)dCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
    }

    // Local term
    for (size_t i = 0; i < m; i++) c[i] ^= (a[i] & b[i]);
}

// ============================================================
//  Beaver Triple — Receiver (P1) — VOLE-based (SilentOT)
// ============================================================

macoro::task<void> beaver_triple_receiver_vole(
    coproto::Socket sock,
    const vector<uint64_t>& a, const vector<uint64_t>& b,
    vector<uint64_t>& c)
{
    size_t m = a.size();
    size_t numOTs = m * 64;
    c.assign(m, 0);

    oc::PRNG prng(toBlock(2000));

    // ---- Phase 1: cross term (a_sender & b_receiver) ----
    // P1 = random OT receiver, P0 = random OT sender
    {
        SilentOtExtReceiver extRecv;
        co_await extRecv.genBaseOts(prng, sock);

        BitVector choices(numOTs);
        choices.randomize(prng);
        vector<oc::block> otMsgs(numOTs);
        co_await extRecv.receive(choices, otMsgs, prng, sock);

        // Receiver's chosen input: y[i][j] = b[i].bit_j
        // Send e[k] = y_bit XOR c[k]
        BitVector eCorr(numOTs);
        for (size_t i = 0; i < m; i++)
            for (size_t j = 0; j < 64; j++)
                eCorr[i * 64 + j] = ((b[i] >> j) & 1) ^ choices[i * 64 + j];

        // Exchange corrections concurrently to avoid deadlock
        BitVector dCorr(numOTs);
        co_await macoro::when_all_ready(
            sock.send(std::move(eCorr)),
            sock.recv(dCorr)
        );

        // Receiver share: z_r = t_c.bit0 XOR (c AND d)
        // NOTE: use the random OT choice bit c, NOT y_bit
        vector<uint64_t> shares(m, 0);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t tc_low;
                memcpy(&tc_low, &otMsgs[k], sizeof(uint64_t));
                uint64_t s = (tc_low & 1) ^ ((uint64_t)choices[k] & (uint64_t)dCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
    }

    // ---- Phase 2: cross term (a_receiver & b_sender) ----
    // P1 = random OT sender, P0 = random OT receiver
    {
        SilentOtExtSender extSender;
        co_await extSender.genBaseOts(prng, sock);

        vector<array<oc::block, 2>> otMsgs(numOTs);
        co_await extSender.send(otMsgs, prng, sock);

        // Sender's chosen input: x[i][j] = a[i].bit_j
        // Compute d[k] = x_bit XOR (t0.bit0 XOR t1.bit0)
        BitVector dCorr(numOTs);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low, t1_low;
                memcpy(&t0_low, &otMsgs[k][0], sizeof(uint64_t));
                memcpy(&t1_low, &otMsgs[k][1], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                dCorr[k] = x_bit ^ ((t0_low ^ t1_low) & 1);
            }
        }

        // Exchange corrections concurrently to avoid deadlock
        BitVector eCorr(numOTs);
        co_await macoro::when_all_ready(
            sock.send(std::move(dCorr)),
            sock.recv(eCorr)
        );

        // Sender share: z_s = t0.bit0 XOR (x_bit AND e)
        vector<uint64_t> shares(m, 0);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low;
                memcpy(&t0_low, &otMsgs[k][0], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                uint64_t s = (t0_low & 1) ^ (x_bit & (uint64_t)eCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
    }

    // Local term
    for (size_t i = 0; i < m; i++) c[i] ^= (a[i] & b[i]);
}

// ============================================================
//  Sender
// ============================================================
//
//  NOTE: sock is coproto::Socket — use coroutine-style IO:
//    macoro::sync_wait(sock.send(data));
//    macoro::sync_wait(sock.recv(data));
//  Or call co_await inside a macoro::task<void> function.
//

void Sender::init(coproto::Socket& sock, vector<oc::block>& sendK) {
    keys = sendK;

    // Build T_X during init so the online phase only performs the
    // cross-party exchange and final local Beaver combination.
    hashed_keys = sm3_hash_keys(keys);
    filter.populate(hashed_keys, kFilterSeed);
    m = filter.array_length();

    // Sender (P0) inputs
    oc::PRNG gen0(toBlock(666));
    a_share.resize(m);
    b_share.resize(m);
    for (size_t i = 0; i < m; i++) {
        a_share[i] = gen0.get<uint64_t>();
        b_share[i] = gen0.get<uint64_t>();
    }
    random_mask = gen0.get<uint64_t>();

    // Sender performs beaver_triple_sender / beaver_triple_sender_vole
    if (use_vole) {
        macoro::sync_wait(beaver_triple_sender_vole(sock, a_share, b_share, c_share));
    } else {
        macoro::sync_wait(beaver_triple_sender(sock, a_share, b_share, c_share));
    }

    // Precompute local openings d_i^1 = T_X[i] xor a_i^1 and
    // e_i^1 = r_1 xor b_i^1. The online phase then only exchanges these
    // precomputed values and finalizes the Beaver formula.
    //
    // Layout (split): open_local[0..m-1] = d values,
    //                 open_local[m..2m-1] = e values.
    // This enables contiguous AVX-512 loads during the online phase.
    const uint64_t* tx = filter.data();
    open_local.resize(2 * m);
    for (size_t i = 0; i < m; ++i) {
        open_local[i]     = tx[i] ^ a_share[i];
        open_local[m + i] = random_mask ^ b_share[i];
    }

    // Precompute the cuckoo locations for the sender's original items x_i.
    // The payload inserted later in step 3 is \tilde{x}_i, but the placement
    // itself depends only on the original item and public cuckoo hash family.
    cuckoo.init(make_cuckoo_param(keys.size()));
    cuckoo.insert(osuCrypto::span<oc::block>(keys.data(), keys.size()), kCuckooHashSeed);

    // Pre-fill the entire cuckoo table with random values so that the online
    // phase only needs to overwrite the occupied bins (no branch + PRNG there).
    oc::PRNG prng_dummy(toBlock(321));
    cuckoo_table.resize(cuckoo.mBins.size());
    for (size_t i = 0; i < cuckoo.mBins.size(); ++i) {
        cuckoo_table[i] = prng_dummy.get<uint64_t>();
    }
    cuckoo_table_hashes.resize(cuckoo.mBins.size());

    // Pre-allocate online-phase buffers so output() does zero heap work.
    mult_share.resize(m);
    associated_values.resize(keys.size());
}

void Sender::output(coproto::Socket& sock) {
    macoro::sync_wait(macoro::when_all_ready(
        sock.send(open_local),
        sock.recvResize(open_peer)
    ));

    if (open_peer.size() != open_local.size()) {
        throw runtime_error("sender received malformed (d, e) payload");
    }

    // ---- AVX-512 Beaver mult_share (split layout, pre-allocated) ----
    // open_local/open_peer layout: [d0..d_{m-1}, e0..e_{m-1}]

#ifdef __AVX512F__
    {
        const uint64_t* dl = open_local.data();
        const uint64_t* dp = open_peer.data();
        const uint64_t* el = open_local.data() + m;
        const uint64_t* ep = open_peer.data() + m;
        const uint64_t* a  = a_share.data();
        const uint64_t* b  = b_share.data();
        const uint64_t* c  = c_share.data();
        uint64_t* ms = mult_share.data();

        size_t i = 0;
        for (; i + 8 <= m; i += 8) {
            __m512i vd = _mm512_xor_epi64(
                _mm512_loadu_si512(dl + i), _mm512_loadu_si512(dp + i));
            __m512i ve = _mm512_xor_epi64(
                _mm512_loadu_si512(el + i), _mm512_loadu_si512(ep + i));
            __m512i vb = _mm512_loadu_si512(b + i);
            __m512i va = _mm512_loadu_si512(a + i);
            __m512i vc = _mm512_loadu_si512(c + i);
            // Sender: s = (d & e) ^ (d & b) ^ (e & a) ^ c
            __m512i res = _mm512_xor_epi64(
                _mm512_xor_epi64(
                    _mm512_and_epi64(vd, ve),
                    _mm512_and_epi64(vd, vb)),
                _mm512_xor_epi64(
                    _mm512_and_epi64(ve, va), vc));
            _mm512_storeu_si512(ms + i, res);
        }
        for (; i < m; ++i) {
            const uint64_t d = dl[i] ^ dp[i];
            const uint64_t e = el[i] ^ ep[i];
            ms[i] = (d & e) ^ (d & b[i]) ^ (e & a[i]) ^ c[i];
        }
    }
#else
    for (size_t i = 0; i < m; ++i) {
        const uint64_t d = open_local[i] ^ open_peer[i];
        const uint64_t e = open_local[m + i] ^ open_peer[m + i];
        mult_share[i] = (d & e) ^ (d & b_share[i]) ^ (e & a_share[i]) ^ c_share[i];
    }
#endif

    // Step 3: compute \tilde{x}_i by XORing the three Beaver-multiplication
    // shares associated with x_i's three fuse positions, then place that
    // payload into the sender's cuckoo table T_C.
    associated_values = compute_associated_values(hashed_keys, filter, mult_share);

    // Overwrite only the occupied cuckoo bins (empty bins already hold
    // random dummies from init, so no branch or PRNG needed here).
    for (size_t i = 0; i < cuckoo.mBins.size(); ++i) {
        if (!cuckoo.mBins[i].isEmpty()) {
            cuckoo_table[i] = associated_values[cuckoo.mBins[i].idx()];
        }
    }

    // Step 6.1: Sender hashes each cuckoo bin payload (AVX-512 batched SM3)
    // and sends the digest vector to the receiver for final comparison.
    sm3_hash_u64_batch(cuckoo_table.data(),
                       cuckoo_table_hashes.data(),
                       cuckoo_table.size());

    vector<uint8_t> send_data(cuckoo_table_hashes.size() * sizeof(sm3_digest_t));
    memcpy(send_data.data(), cuckoo_table_hashes.data(), send_data.size());
    macoro::sync_wait(sock.send(send_data));
}

// ============================================================
//  Receiver
// ============================================================

void Receiver::init(coproto::Socket& sock, vector<oc::block>& recvK) {
    keys = recvK;

    // Build T_Y during init so the online phase stays as small as possible.
    hashed_keys = sm3_hash_keys(keys);
    filter.populate(hashed_keys, kFilterSeed);
    m = filter.array_length();

    // Receiver (P1) inputs
    oc::PRNG gen1(toBlock(888));
    a_share.resize(m);
    b_share.resize(m);
    for (size_t i = 0; i < m; i++) {
        a_share[i] = gen1.get<uint64_t>();
        b_share[i] = gen1.get<uint64_t>();
    }
    random_mask = gen1.get<uint64_t>();

    // Receiver performs beaver_triple_receiver / beaver_triple_receiver_vole
    if (use_vole) {
        macoro::sync_wait(beaver_triple_receiver_vole(sock, a_share, b_share, c_share));
    } else {
        macoro::sync_wait(beaver_triple_receiver(sock, a_share, b_share, c_share));
    }

    // Precompute local openings d_i^2 = T_Y[i] xor a_i^2 and
    // e_i^2 = r_2 xor b_i^2.
    //
    // Layout (split): open_local[0..m-1] = d values,
    //                 open_local[m..2m-1] = e values.
    const uint64_t* ty = filter.data();
    open_local.resize(2 * m);
    for (size_t i = 0; i < m; ++i) {
        open_local[i]     = ty[i] ^ a_share[i];
        open_local[m + i] = random_mask ^ b_share[i];
    }

    // Precompute the public simple-hash locations for all receiver items y_i
    // using the same cuckoo hash family as the sender's T_C.
    CuckooIndex<ThreadSafe> location_helper;
    location_helper.init(make_cuckoo_param(keys.size()));
    location_helper.insert(osuCrypto::span<oc::block>(keys.data(), keys.size()), kCuckooHashSeed);

    const size_t num_bins = location_helper.mBins.size();
    simple_item_indices.assign(num_bins, {});
    for (size_t item_idx = 0; item_idx < keys.size(); ++item_idx) {
        for (u64 hash_idx = 0; hash_idx < kCuckooNumHashes; ++hash_idx) {
            const auto bin_idx = static_cast<size_t>(location_helper.mLocations(item_idx, hash_idx));
            simple_item_indices[bin_idx].push_back(item_idx);
        }
    }

    // Pre-compute flat-buffer offsets so the online phase does zero heap
    // allocations for the simple-table hashing path.
    flat_bin_offsets.resize(num_bins + 1);
    flat_bin_offsets[0] = 0;
    for (size_t i = 0; i < num_bins; ++i) {
        flat_bin_offsets[i + 1] = flat_bin_offsets[i] + simple_item_indices[i].size();
    }
    flat_total_entries = flat_bin_offsets[num_bins];
    flat_values.resize(flat_total_entries);
    flat_hashes.resize(flat_total_entries);

    // Pre-allocate online-phase buffers.
    mult_share.resize(m);
    associated_values.resize(keys.size());
    sender_payload_hashes.resize(num_bins);
}

void Receiver::output(coproto::Socket& sock) {
    macoro::sync_wait(macoro::when_all_ready(
        sock.send(open_local),
        sock.recvResize(open_peer)
    ));

    if (open_peer.size() != open_local.size()) {
        throw runtime_error("receiver received malformed (d, e) payload");
    }

    // ---- AVX-512 Beaver mult_share (split layout, pre-allocated) ----

#ifdef __AVX512F__
    {
        const uint64_t* dl = open_local.data();
        const uint64_t* dp = open_peer.data();
        const uint64_t* el = open_local.data() + m;
        const uint64_t* ep = open_peer.data() + m;
        const uint64_t* a  = a_share.data();
        const uint64_t* b  = b_share.data();
        const uint64_t* c  = c_share.data();
        uint64_t* ms = mult_share.data();

        size_t i = 0;
        for (; i + 8 <= m; i += 8) {
            __m512i vd = _mm512_xor_epi64(
                _mm512_loadu_si512(dl + i), _mm512_loadu_si512(dp + i));
            __m512i ve = _mm512_xor_epi64(
                _mm512_loadu_si512(el + i), _mm512_loadu_si512(ep + i));
            __m512i vb = _mm512_loadu_si512(b + i);
            __m512i va = _mm512_loadu_si512(a + i);
            __m512i vc = _mm512_loadu_si512(c + i);
            // Receiver: s = (d & b) ^ (e & a) ^ c   (no (d & e) term)
            __m512i res = _mm512_xor_epi64(
                _mm512_and_epi64(vd, vb),
                _mm512_xor_epi64(
                    _mm512_and_epi64(ve, va), vc));
            _mm512_storeu_si512(ms + i, res);
        }
        for (; i < m; ++i) {
            const uint64_t d = dl[i] ^ dp[i];
            const uint64_t e = el[i] ^ ep[i];
            ms[i] = (d & b[i]) ^ (e & a[i]) ^ c[i];
        }
    }
#else
    for (size_t i = 0; i < m; ++i) {
        const uint64_t d = open_local[i] ^ open_peer[i];
        const uint64_t e = open_local[m + i] ^ open_peer[m + i];
        mult_share[i] = (d & b_share[i]) ^ (e & a_share[i]) ^ c_share[i];
    }
#endif

    // Step 4: compute \tilde{y}_i and place into a flat contiguous buffer
    // indexed by the pre-computed bin offsets (no heap allocation here).
    associated_values = compute_associated_values(hashed_keys, filter, mult_share);

    const size_t num_bins = simple_item_indices.size();
    for (size_t bin_idx = 0; bin_idx < num_bins; ++bin_idx) {
        size_t off = flat_bin_offsets[bin_idx];
        const auto& indices = simple_item_indices[bin_idx];
        for (size_t j = 0; j < indices.size(); ++j) {
            flat_values[off + j] = associated_values[indices[j]];
        }
    }

    // Batch SM3 directly on the flat buffer — no collect/distribute overhead.
    sm3_hash_u64_batch(flat_values.data(), flat_hashes.data(), flat_total_entries);

    // Step 6.2 / 7: Receiver receives H(T_C[i]), compares it against the
    // hashed simple-table payloads in bin i, and outputs the matched y items.
    vector<uint8_t> recv_data;
    macoro::sync_wait(sock.recvResize(recv_data));

    if (recv_data.size() % sizeof(sm3_digest_t) != 0) {
        throw runtime_error("receiver received malformed sender hash payload");
    }

    const size_t n_hashes = recv_data.size() / sizeof(sm3_digest_t);
    if (n_hashes != num_bins) {
        throw runtime_error("receiver hash payload size does not match T_S bin count");
    }
    memcpy(sender_payload_hashes.data(), recv_data.data(), recv_data.size());

    intersection.clear();

    for (size_t bin_idx = 0; bin_idx < num_bins; ++bin_idx) {
        const size_t off = flat_bin_offsets[bin_idx];
        const size_t cnt = flat_bin_offsets[bin_idx + 1] - off;
        if (cnt == 0) continue;

        for (size_t j = 0; j < cnt; ++j) {
            if (digest_equal(flat_hashes[off + j],
                             sender_payload_hashes[bin_idx])) {
                intersection.push_back(keys[simple_item_indices[bin_idx][j]]);
                break;
            }
        }
    }
}
