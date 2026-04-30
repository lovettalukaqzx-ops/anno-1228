#ifndef HEPSI_PSI_V_H
#define HEPSI_PSI_V_H

#include "psi.h"

// ============================================================
//  Query-batched protocol structures for receiver-small / sender-large
// ============================================================

struct QueryBatchV {
    std::size_t receiver_index = 0;
    std::size_t target_block = 0;
    seal::Ciphertext enc_c_hat;
    seal::Ciphertext enc_y;
};


class SenderV {
public:
    std::vector<oc::block> keys;
    std::vector<uint64_t> hashed_keys;

    std::shared_ptr<seal::SEALContext> he_context;
    uint64_t plain_modulus = 0;
    seal::PublicKey recv_public_key;
    seal::GaloisKeys recv_galois_keys;

    std::size_t num_blocks = 0;
    std::vector<std::size_t> block_sizes;
    std::vector<std::vector<std::size_t>> block_indices;
    std::vector<binfuse::additive_filter> block_filters;
    std::vector<uint64_t> block_filter_seeds;
    std::vector<uint32_t> block_seg_len;
    std::vector<uint32_t> block_seg_mask;
    std::vector<uint32_t> block_seg_cl;
    std::vector<seal::Plaintext> block_filter_plaintexts;
    std::size_t receiver_query_count = 0;

    void init(coproto::Socket& sock, std::vector<oc::block>& sendK);
    void output(coproto::Socket& sock);
};

class ReceiverV {
public:
    std::vector<oc::block> keys;
    std::vector<uint64_t> hashed_keys;

    std::shared_ptr<seal::SEALContext> he_context;
    uint64_t plain_modulus = 0;
    seal::SecretKey he_secret_key;
    seal::PublicKey he_public_key;
    seal::GaloisKeys he_galois_keys;

    std::size_t num_blocks = 0;
    std::vector<uint64_t> block_filter_seeds;
    std::vector<uint32_t> block_seg_len;
    std::vector<uint32_t> block_seg_mask;
    std::vector<uint32_t> block_seg_cl;

    std::vector<std::vector<QueryBatchV>> queries_by_receiver;
    std::vector<oc::block> intersection;

    void init(coproto::Socket& sock, std::vector<oc::block>& recvK);
    void output(coproto::Socket& sock);
};

#endif // HEPSI_PSI_V_H
