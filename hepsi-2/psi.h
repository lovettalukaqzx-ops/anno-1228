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

// Runtime block-size knob (receiver decides partitioning)
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
//  Batched query layout for the fixed-shape Figure 4 rollback
// ============================================================

struct ReceiverQueryBatch {
    // One ciphertext per filter slot j. The k-th slot stores the 0/1 query bit
    // for the k-th receiver element packed into this batch.
    std::vector<seal::Ciphertext> c_hat_by_slot;

    // Batched Enc(y): the k-th slot stores the effective value y_k.
    seal::Ciphertext enc_y_batch;

    // Slot-to-receiver-element mapping for recovering the intersection.
    std::vector<std::size_t> receiver_indices;

    // Number of live slots in this batch (<= slot_count).
    std::size_t active_slots = 0;
};

struct SenderResponseBatch {
    // Batched c_bar result returned by Sender for one block batch.
    seal::Ciphertext enc_result_batch;

    // Number of live slots in this batch.
    std::size_t active_slots = 0;
};

// ============================================================
//  PSI Protocol (Sender / Receiver)
//  Based on Figure 4 of the HEPSI paper.
//  - init()   = offline stage
//  - output() = online stage
// ============================================================

class Sender {
public:
    std::vector<oc::block> keys;           // original input elements
    std::vector<uint64_t> hashed_keys;     // 40-bit effective values mod plain_modulus

    // SEAL context (shared BFV parameters)
    std::shared_ptr<seal::SEALContext> he_context;
    uint64_t plain_modulus = 0;
    seal::PublicKey recv_public_key;       // received from Receiver in init
    seal::GaloisKeys recv_galois_keys;     // received from Receiver in init

    // Block partition (h0-based, receiver decides num_blocks)
    std::size_t num_blocks = 0;
    std::vector<std::size_t> block_sizes;
    std::vector<std::vector<std::size_t>> block_indices;

    // Sender-side additive fuse filters (step 3.1)
    std::vector<binfuse::additive_filter> block_filters;
    std::vector<uint64_t> block_filter_seeds;
    std::vector<uint32_t> block_seg_len;
    std::vector<uint32_t> block_seg_mask;
    std::vector<uint32_t> block_seg_cl;

    // Fixed-shape query batch count shared during offline setup.
    std::size_t uniform_batch_count = 0;

    void init(coproto::Socket& sock, std::vector<oc::block>& sendK);
    void output(coproto::Socket& sock);
};

class Receiver {
public:
    std::vector<oc::block> keys;           // original input elements
    std::vector<uint64_t> hashed_keys;     // 40-bit effective values mod plain_modulus

    // SEAL keys (Receiver owns the secret key)
    std::shared_ptr<seal::SEALContext> he_context;
    uint64_t plain_modulus = 0;
    seal::SecretKey he_secret_key;
    seal::PublicKey he_public_key;
    seal::GaloisKeys he_galois_keys;

    // Block partition
    std::size_t num_blocks = 0;
    std::vector<std::size_t> block_sizes;
    std::vector<std::vector<std::size_t>> block_indices;

    // Sender's per-block filter metadata (received in init)
    std::vector<uint64_t> block_filter_seeds;
    std::vector<uint32_t> block_seg_len;
    std::vector<uint32_t> block_seg_mask;
    std::vector<uint32_t> block_seg_cl;

    // Precomputed receiver queries (step 3.2, built offline)
    std::vector<std::vector<ReceiverQueryBatch>> block_query_batches;

    // Sender's batched responses (received in output)
    std::vector<std::vector<SenderResponseBatch>> block_response_batches;

    // Number of fixed-shape query batches used for every block in the rollback version.
    std::size_t uniform_batch_count = 0;

    std::vector<oc::block> intersection;

    void init(coproto::Socket& sock, std::vector<oc::block>& recvK);
    void output(coproto::Socket& sock);
};

#endif // HEPSI_PSI_H
