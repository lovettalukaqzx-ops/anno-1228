#ifndef HEPSI_PSI_H
#define HEPSI_PSI_H

#include <cryptoTools/Common/block.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <map>
#include <random>

#include <coproto/Socket/LocalAsyncSock.h>
#include <coproto/Socket/AsioSocket.h>
#include <macoro/sync_wait.h>
#include <macoro/when_all.h>

#include "binfuse/filter.hpp"
#include "binfuse/additive_filter.hpp"

#include <seal/seal.h>

using namespace osuCrypto;

// ============================================================
//  Protocol Parameters
// ============================================================

extern int Number;

// BFV parameters
constexpr std::size_t kPolyModulusDegree = 8192;
constexpr int         kPlainModulusBits  = 41;

extern std::size_t gTargetBlockSize;

// Public seed for additive fuse filter construction.
constexpr uint64_t kFilterSeed = 0x50534946696C7472ULL;

// ============================================================
//  Type Aliases
// ============================================================

using sm3_digest_t = std::array<std::uint8_t, 32>;

// ============================================================
//  Utilities
// ============================================================

uint64_t sm3_hash_block_to_u64(const oc::block& blk);
std::vector<uint64_t> sm3_hash_keys(const std::vector<oc::block>& keys);
sm3_digest_t sm3_hash_u64(std::uint64_t value);
std::vector<uint64_t> truncate_to_plain(const std::vector<uint64_t>& hashed, uint64_t plain_modulus);
void key_init(std::vector<oc::block>& key, bool choose);
seal::EncryptionParameters make_he_params();
std::size_t compute_num_blocks(std::size_t n_receiver);
void validate_block_size_or_throw();
int expected_intersection_count(std::size_t sender_size);

void send_seal_obj(coproto::Socket& sock, const seal::PublicKey& obj);
void send_seal_obj(coproto::Socket& sock, const seal::GaloisKeys& obj);
void send_seal_obj(coproto::Socket& sock, const seal::Ciphertext& obj);
void recv_seal_obj(coproto::Socket& sock, seal::PublicKey& obj, const seal::SEALContext& ctx);
void recv_seal_obj(coproto::Socket& sock, seal::GaloisKeys& obj, const seal::SEALContext& ctx);
void recv_seal_obj(coproto::Socket& sock, seal::Ciphertext& obj, const seal::SEALContext& ctx);

// ============================================================
//  PSI Protocol (Sender / Receiver)
// ============================================================

class Sender {
public:
    std::vector<oc::block> keys;
    std::vector<uint64_t>  hashed_keys;

    // SEAL
    std::shared_ptr<seal::SEALContext> he_context;
    uint64_t plain_modulus = 0;
    seal::PublicKey recv_public_key;
    seal::GaloisKeys recv_galois_keys;

    // Block partition (determined by Receiver, received in init)
    std::size_t num_blocks = 0;
    std::vector<uint64_t>  block_filter_seeds;
    std::vector<uint32_t>  block_seg_len;
    std::vector<uint32_t>  block_seg_mask;
    std::vector<uint32_t>  block_seg_cl;
    std::vector<std::vector<std::size_t>> block_indices;

    void init(coproto::Socket& sock, std::vector<oc::block>& sendK);
    void output(coproto::Socket& sock);
};

class Receiver {
public:
    std::vector<oc::block> keys;
    std::vector<uint64_t>  hashed_keys;

    // SEAL
    std::shared_ptr<seal::SEALContext> he_context;
    uint64_t plain_modulus = 0;
    seal::SecretKey he_secret_key;
    seal::PublicKey he_public_key;
    seal::GaloisKeys he_galois_keys;

    // Block partition + per-block filter + batched encrypted ct
    std::size_t num_blocks = 0;
    std::vector<binfuse::additive_filter> block_filters;
    std::vector<seal::Ciphertext> block_encrypted_cts;  // 1 batched ct per block
    std::vector<std::vector<std::size_t>> block_indices;

    // Intersection output
    std::vector<oc::block>                 intersection;
    std::map<std::size_t, oc::block>       receiver_sender_psi;

    void init(coproto::Socket& sock, std::vector<oc::block>& recvK);
    void output(coproto::Socket& sock);
};

#endif //HEPSI_PSI_H
