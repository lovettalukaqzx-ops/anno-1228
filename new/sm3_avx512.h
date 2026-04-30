#pragma once
// ============================================================
//  AVX-512 Multi-Buffer SM3 — 16-way parallel hashing
// ============================================================
//
//  Processes 16 independent SM3(uint64_t) in parallel using a single
//  core.  Each input is an 8-byte value that is padded to one 512-bit
//  SM3 block and compressed with the standard SM3 algorithm.
//
//  Requires: AVX-512F + AVX-512BW (for _mm512_shuffle_epi8)
//

#ifdef __AVX512F__

#include <immintrin.h>
#include <cstdint>
#include <cstring>
#include <array>

namespace sm3_avx512 {

using digest_t = std::array<std::uint8_t, 32>;

// ---- constexpr ROTL32 for precomputation ----

static constexpr uint32_t rotl32_c(uint32_t x, int n) {
    n &= 31;
    return n == 0 ? x : ((x << n) | (x >> (32 - n)));
}

// Precomputed round constants: ROTL32(T_j, j)
//   T_j = 0x79CC4519  for j =  0..15
//   T_j = 0x7A879D8A  for j = 16..63
static constexpr uint32_t T_CONST[64] = {
    rotl32_c(0x79CC4519u,  0), rotl32_c(0x79CC4519u,  1),
    rotl32_c(0x79CC4519u,  2), rotl32_c(0x79CC4519u,  3),
    rotl32_c(0x79CC4519u,  4), rotl32_c(0x79CC4519u,  5),
    rotl32_c(0x79CC4519u,  6), rotl32_c(0x79CC4519u,  7),
    rotl32_c(0x79CC4519u,  8), rotl32_c(0x79CC4519u,  9),
    rotl32_c(0x79CC4519u, 10), rotl32_c(0x79CC4519u, 11),
    rotl32_c(0x79CC4519u, 12), rotl32_c(0x79CC4519u, 13),
    rotl32_c(0x79CC4519u, 14), rotl32_c(0x79CC4519u, 15),
    rotl32_c(0x7A879D8Au, 16), rotl32_c(0x7A879D8Au, 17),
    rotl32_c(0x7A879D8Au, 18), rotl32_c(0x7A879D8Au, 19),
    rotl32_c(0x7A879D8Au, 20), rotl32_c(0x7A879D8Au, 21),
    rotl32_c(0x7A879D8Au, 22), rotl32_c(0x7A879D8Au, 23),
    rotl32_c(0x7A879D8Au, 24), rotl32_c(0x7A879D8Au, 25),
    rotl32_c(0x7A879D8Au, 26), rotl32_c(0x7A879D8Au, 27),
    rotl32_c(0x7A879D8Au, 28), rotl32_c(0x7A879D8Au, 29),
    rotl32_c(0x7A879D8Au, 30), rotl32_c(0x7A879D8Au, 31),
    rotl32_c(0x7A879D8Au, 32), rotl32_c(0x7A879D8Au, 33),
    rotl32_c(0x7A879D8Au, 34), rotl32_c(0x7A879D8Au, 35),
    rotl32_c(0x7A879D8Au, 36), rotl32_c(0x7A879D8Au, 37),
    rotl32_c(0x7A879D8Au, 38), rotl32_c(0x7A879D8Au, 39),
    rotl32_c(0x7A879D8Au, 40), rotl32_c(0x7A879D8Au, 41),
    rotl32_c(0x7A879D8Au, 42), rotl32_c(0x7A879D8Au, 43),
    rotl32_c(0x7A879D8Au, 44), rotl32_c(0x7A879D8Au, 45),
    rotl32_c(0x7A879D8Au, 46), rotl32_c(0x7A879D8Au, 47),
    rotl32_c(0x7A879D8Au, 48), rotl32_c(0x7A879D8Au, 49),
    rotl32_c(0x7A879D8Au, 50), rotl32_c(0x7A879D8Au, 51),
    rotl32_c(0x7A879D8Au, 52), rotl32_c(0x7A879D8Au, 53),
    rotl32_c(0x7A879D8Au, 54), rotl32_c(0x7A879D8Au, 55),
    rotl32_c(0x7A879D8Au, 56), rotl32_c(0x7A879D8Au, 57),
    rotl32_c(0x7A879D8Au, 58), rotl32_c(0x7A879D8Au, 59),
    rotl32_c(0x7A879D8Au, 60), rotl32_c(0x7A879D8Au, 61),
    rotl32_c(0x7A879D8Au, 62), rotl32_c(0x7A879D8Au, 63),
};

// ---- SM3 permutation functions (vectorised) ----

static inline __m512i P0(__m512i x) {
    return _mm512_xor_epi32(
        _mm512_xor_epi32(x, _mm512_rol_epi32(x, 9)),
        _mm512_rol_epi32(x, 17));
}

static inline __m512i P1(__m512i x) {
    return _mm512_xor_epi32(
        _mm512_xor_epi32(x, _mm512_rol_epi32(x, 15)),
        _mm512_rol_epi32(x, 23));
}

// ============================================================
//  hash_u64_x16 — hash 16 × uint64_t in parallel
// ============================================================
//
//  Each uint64_t is treated as an 8-byte message.  Padding produces
//  one 512-bit SM3 block per message:
//
//    W[0]  = bswap32(lower 32 bits of input)
//    W[1]  = bswap32(upper 32 bits of input)
//    W[2]  = 0x80000000       (padding '1' bit)
//    W[3..14] = 0
//    W[15] = 0x00000040       (message length = 64 bits)
//

inline void hash_u64_x16(const uint64_t input[16], digest_t output[16]) {

    // -- byte-swap mask: reverse bytes in each 32-bit element --
    // _mm512_shuffle_epi8 uses per-128-bit-lane indices 0..15.
    // For bswap32: byte i gets value from byte (i/4)*4 + 3 - (i%4).
    const __m512i bswap32 = _mm512_set_epi8(
        12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3,
        12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3,
        12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3,
        12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);

    // ---- Load 16 uint64_t and convert to message words ----
    //
    // raw0/raw1 each hold 8 uint64_t = 16 uint32_t.
    // After bswap32, element layout (32-bit each) is:
    //   [bswap32(v0_lo), bswap32(v0_hi), bswap32(v1_lo), ... ]
    // We deinterleave even (lo → W[0]) and odd (hi → W[1]) elements.

    __m512i raw0 = _mm512_shuffle_epi8(
        _mm512_loadu_si512(input), bswap32);
    __m512i raw1 = _mm512_shuffle_epi8(
        _mm512_loadu_si512(input + 8), bswap32);

    // Deinterleave indices: even 32-bit elements → W[0], odd → W[1].
    // _mm512_permutex2var_epi32(a, idx, b): idx 0..15 ↦ a, 16..31 ↦ b.
    const __m512i idx_even = _mm512_set_epi32(
        30,28,26,24,22,20,18,16, 14,12,10,8,6,4,2,0);
    const __m512i idx_odd  = _mm512_set_epi32(
        31,29,27,25,23,21,19,17, 15,13,11,9,7,5,3,1);

    __m512i W[68];
    W[0] = _mm512_permutex2var_epi32(raw0, idx_even, raw1);
    W[1] = _mm512_permutex2var_epi32(raw0, idx_odd,  raw1);
    W[2] = _mm512_set1_epi32(static_cast<int>(0x80000000u));
    for (int k = 3; k < 15; ++k) W[k] = _mm512_setzero_si512();
    W[15] = _mm512_set1_epi32(0x00000040);   // 64-bit message length

    // ---- Message expansion: W[16..67] ----
    for (int j = 16; j <= 67; ++j) {
        __m512i tmp = _mm512_xor_epi32(
            _mm512_xor_epi32(W[j - 16], W[j - 9]),
            _mm512_rol_epi32(W[j - 3], 15));
        W[j] = _mm512_xor_epi32(
            _mm512_xor_epi32(P1(tmp), _mm512_rol_epi32(W[j - 13], 7)),
            W[j - 6]);
    }

    // ---- Initialise state (SM3 IV broadcast to all 16 lanes) ----
    __m512i A = _mm512_set1_epi32(static_cast<int>(0x7380166Fu));
    __m512i B = _mm512_set1_epi32(static_cast<int>(0x4914B2B9u));
    __m512i C = _mm512_set1_epi32(static_cast<int>(0x172442D7u));
    __m512i D = _mm512_set1_epi32(static_cast<int>(0xDA8A0600u));
    __m512i E = _mm512_set1_epi32(static_cast<int>(0xA96F30BCu));
    __m512i F = _mm512_set1_epi32(static_cast<int>(0x163138AAu));
    __m512i G = _mm512_set1_epi32(static_cast<int>(0xE38DEE4Du));
    __m512i H = _mm512_set1_epi32(static_cast<int>(0xB0FB0E4Eu));

    // Save IV for final XOR
    const __m512i ivA = A, ivB = B, ivC = C, ivD = D;
    const __m512i ivE = E, ivF = F, ivG = G, ivH = H;

    // ---- Compression: rounds 0..15 (FF0 / GG0 — XOR-based) ----
    for (int j = 0; j < 16; ++j) {
        const __m512i Wp = _mm512_xor_epi32(W[j], W[j + 4]);
        const __m512i A12 = _mm512_rol_epi32(A, 12);
        const __m512i SS1 = _mm512_rol_epi32(
            _mm512_add_epi32(
                _mm512_add_epi32(A12, E),
                _mm512_set1_epi32(static_cast<int>(T_CONST[j]))),
            7);
        const __m512i SS2 = _mm512_xor_epi32(SS1, A12);

        // FF0(A,B,C) = A ^ B ^ C
        const __m512i FF = _mm512_xor_epi32(_mm512_xor_epi32(A, B), C);
        // GG0(E,F,G) = E ^ F ^ G
        const __m512i GG = _mm512_xor_epi32(_mm512_xor_epi32(E, F), G);

        const __m512i TT1 = _mm512_add_epi32(
            _mm512_add_epi32(_mm512_add_epi32(FF, D), SS2), Wp);
        const __m512i TT2 = _mm512_add_epi32(
            _mm512_add_epi32(_mm512_add_epi32(GG, H), SS1), W[j]);

        D = C;
        C = _mm512_rol_epi32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = _mm512_rol_epi32(F, 19);
        F = E;
        E = P0(TT2);
    }

    // ---- Compression: rounds 16..63 (FF1 / GG1 — majority / choice) ----
    for (int j = 16; j < 64; ++j) {
        const __m512i Wp = _mm512_xor_epi32(W[j], W[j + 4]);
        const __m512i A12 = _mm512_rol_epi32(A, 12);
        const __m512i SS1 = _mm512_rol_epi32(
            _mm512_add_epi32(
                _mm512_add_epi32(A12, E),
                _mm512_set1_epi32(static_cast<int>(T_CONST[j]))),
            7);
        const __m512i SS2 = _mm512_xor_epi32(SS1, A12);

        // FF1(A,B,C) = (A & B) | (A & C) | (B & C)
        const __m512i FF = _mm512_or_epi32(
            _mm512_or_epi32(
                _mm512_and_epi32(A, B),
                _mm512_and_epi32(A, C)),
            _mm512_and_epi32(B, C));
        // GG1(E,F,G) = (E & F) | (~E & G)
        const __m512i GG = _mm512_or_epi32(
            _mm512_and_epi32(E, F),
            _mm512_andnot_epi32(E, G));

        const __m512i TT1 = _mm512_add_epi32(
            _mm512_add_epi32(_mm512_add_epi32(FF, D), SS2), Wp);
        const __m512i TT2 = _mm512_add_epi32(
            _mm512_add_epi32(_mm512_add_epi32(GG, H), SS1), W[j]);

        D = C;
        C = _mm512_rol_epi32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = _mm512_rol_epi32(F, 19);
        F = E;
        E = P0(TT2);
    }

    // ---- Final: state ^= IV ----
    A = _mm512_xor_epi32(A, ivA);
    B = _mm512_xor_epi32(B, ivB);
    C = _mm512_xor_epi32(C, ivC);
    D = _mm512_xor_epi32(D, ivD);
    E = _mm512_xor_epi32(E, ivE);
    F = _mm512_xor_epi32(F, ivF);
    G = _mm512_xor_epi32(G, ivG);
    H = _mm512_xor_epi32(H, ivH);

    // ---- Convert back to big-endian and scatter to output ----
    A = _mm512_shuffle_epi8(A, bswap32);
    B = _mm512_shuffle_epi8(B, bswap32);
    C = _mm512_shuffle_epi8(C, bswap32);
    D = _mm512_shuffle_epi8(D, bswap32);
    E = _mm512_shuffle_epi8(E, bswap32);
    F = _mm512_shuffle_epi8(F, bswap32);
    G = _mm512_shuffle_epi8(G, bswap32);
    H = _mm512_shuffle_epi8(H, bswap32);

    // Scatter: place word k of message i at output[i].data() + 4*k.
    // output[i] occupies bytes [32*i .. 32*i+31].
    __m512i off = _mm512_set_epi32(
        15*32, 14*32, 13*32, 12*32, 11*32, 10*32, 9*32, 8*32,
         7*32,  6*32,  5*32,  4*32,  3*32,  2*32, 1*32,    0);
    const __m512i four = _mm512_set1_epi32(4);

    _mm512_i32scatter_epi32(output, off, A, 1);
    off = _mm512_add_epi32(off, four);
    _mm512_i32scatter_epi32(output, off, B, 1);
    off = _mm512_add_epi32(off, four);
    _mm512_i32scatter_epi32(output, off, C, 1);
    off = _mm512_add_epi32(off, four);
    _mm512_i32scatter_epi32(output, off, D, 1);
    off = _mm512_add_epi32(off, four);
    _mm512_i32scatter_epi32(output, off, E, 1);
    off = _mm512_add_epi32(off, four);
    _mm512_i32scatter_epi32(output, off, F, 1);
    off = _mm512_add_epi32(off, four);
    _mm512_i32scatter_epi32(output, off, G, 1);
    off = _mm512_add_epi32(off, four);
    _mm512_i32scatter_epi32(output, off, H, 1);
}

} // namespace sm3_avx512

#endif // __AVX512F__
