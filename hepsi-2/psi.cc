#include "psi.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>

#include <gmssl/sm3.h>

using namespace std;
using namespace osuCrypto;

namespace {

size_t fixed_batch_count_for_blocks(const vector<vector<size_t>>& block_indices, size_t slot_count) {
    size_t max_batches = 0;
    for (const auto& indices : block_indices) {
        size_t batches = (indices.size() + slot_count - 1) / slot_count;
        max_batches = max(max_batches, batches);
    }
    return max_batches;
}

}

// ============================================================
//  Global parameter definitions
// ============================================================

int Number = 100;
std::size_t gTargetBlockSize = 6144;

// ============================================================
//  SM3 hashing utilities
// ============================================================

uint64_t sm3_hash_block_to_u64(const oc::block& blk) {
    uint8_t inputData[16];
    memcpy(inputData, &blk, sizeof(inputData));

    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, inputData, sizeof(inputData));

    uint8_t digest[32];
    sm3_finish(&ctx, digest);

    uint64_t out = 0;
    memcpy(&out, digest, sizeof(uint64_t));
    return out;
}

vector<uint64_t> sm3_hash_keys(const vector<oc::block>& keys) {
    vector<uint64_t> out(keys.size());
    for (size_t i = 0; i < keys.size(); ++i) {
        out[i] = sm3_hash_block_to_u64(keys[i]);
    }
    return out;
}

sm3_digest_t sm3_hash_u64(uint64_t value) {
    sm3_digest_t digest{};

    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
    sm3_finish(&ctx, digest.data());

    return digest;
}

// Truncate to 40-bit effective value and reduce mod plain_modulus.
vector<uint64_t> truncate_to_plain(const vector<uint64_t>& hashed, uint64_t plain_modulus) {
    constexpr uint64_t kMask40 = (UINT64_C(1) << 40) - 1;

    vector<uint64_t> out(hashed.size());
    for (size_t i = 0; i < hashed.size(); ++i) {
        out[i] = (hashed[i] & kMask40) % plain_modulus;
    }
    return out;
}

// ============================================================
//  Synthetic dataset generation
// ============================================================

int expected_intersection_count(std::size_t sender_size) {
    if (sender_size <= 1) return 1;
    if (sender_size <= 64) return 10;
    if (sender_size <= 256) return 10;
    return 100;
}

void key_init(vector<oc::block>& key, bool choose) {
    oc::PRNG prng_common(toBlock(123));
    oc::PRNG prng_recv_only(toBlock(456));
    oc::PRNG prng_send_only(toBlock(789));

    const size_t intersection = static_cast<size_t>(expected_intersection_count(key.size()));
    const size_t common = min(intersection, key.size());

    if (choose) {
        // Receiver: first `common` keys are shared, rest are receiver-only.
        for (size_t i = 0; i < common; ++i) key[i] = prng_common.get<oc::block>();
        for (size_t i = common; i < key.size(); ++i) key[i] = prng_recv_only.get<oc::block>();
    } else {
        // Sender: first `common` keys are shared, rest are sender-only.
        for (size_t i = 0; i < common; ++i) key[i] = prng_common.get<oc::block>();
        for (size_t i = common; i < key.size(); ++i) key[i] = prng_send_only.get<oc::block>();
    }
}

// ============================================================
//  BFV parameter setup
// ============================================================

seal::EncryptionParameters make_he_params() {
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(kPolyModulusDegree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(kPolyModulusDegree));
    parms.set_plain_modulus(seal::PlainModulus::Batching(kPolyModulusDegree, kPlainModulusBits));
    return parms;
}

// ============================================================
//  Block partitioning helpers
// ============================================================

size_t compute_num_blocks(size_t n_receiver) {
    return max<size_t>(1, (n_receiver + gTargetBlockSize - 1) / gTargetBlockSize);
}

void validate_block_size_or_throw() {
    if (gTargetBlockSize == 0) {
        throw invalid_argument("gTargetBlockSize must be positive.");
    }
}

// Compute the 3 additive-filter positions for a given key.
static array<size_t, 3> block_positions(uint64_t key,
                                        uint64_t seed,
                                        uint32_t segment_length,
                                        uint32_t segment_length_mask,
                                        uint32_t segment_count_length) {
    const uint64_t hash = binary_fuse_mix_split(key, seed);
    const auto h0 = static_cast<uint32_t>(binary_fuse_mulhi(hash, segment_count_length));
    const auto h1 = static_cast<uint32_t>(h0 + segment_length)
        ^ (static_cast<uint32_t>(hash >> 18U) & segment_length_mask);
    const auto h2 = static_cast<uint32_t>(h0 + 2 * segment_length)
        ^ (static_cast<uint32_t>(hash) & segment_length_mask);
    return {static_cast<size_t>(h0), static_cast<size_t>(h1), static_cast<size_t>(h2)};
}

// ============================================================
//  SEAL serialization helpers
// ============================================================

template<typename T>
static void send_seal_generic(coproto::Socket& sock, const T& obj) {
    stringstream ss;
    obj.save(ss);
    string s = ss.str();
    vector<uint8_t> buf(s.begin(), s.end());
    uint64_t len = buf.size();
    macoro::sync_wait(sock.send(move(len)));
    macoro::sync_wait(sock.send(move(buf)));
}

template<typename T>
static void recv_seal_generic(coproto::Socket& sock, T& obj, const seal::SEALContext& ctx) {
    uint64_t len = 0;
    macoro::sync_wait(sock.recv(len));
    vector<uint8_t> buf(len);
    macoro::sync_wait(sock.recv(buf));
    stringstream ss;
    ss.write(reinterpret_cast<const char*>(buf.data()), static_cast<streamsize>(buf.size()));
    obj.load(ctx, ss);
}

void send_seal_obj(coproto::Socket& sock, const seal::PublicKey& obj)  { send_seal_generic(sock, obj); }
void send_seal_obj(coproto::Socket& sock, const seal::GaloisKeys& obj) { send_seal_generic(sock, obj); }
void send_seal_obj(coproto::Socket& sock, const seal::Ciphertext& obj) { send_seal_generic(sock, obj); }
void recv_seal_obj(coproto::Socket& sock, seal::PublicKey& obj,  const seal::SEALContext& ctx) { recv_seal_generic(sock, obj, ctx); }
void recv_seal_obj(coproto::Socket& sock, seal::GaloisKeys& obj, const seal::SEALContext& ctx) { recv_seal_generic(sock, obj, ctx); }
void recv_seal_obj(coproto::Socket& sock, seal::Ciphertext& obj, const seal::SEALContext& ctx) { recv_seal_generic(sock, obj, ctx); }

// ============================================================
//  Receiver::init  (offline stage)
// ============================================================

void Receiver::init(coproto::Socket& sock, vector<oc::block>& recvK) {
    keys = recvK;

    // --- BFV setup ---
    auto parms = make_he_params();
    he_context = make_shared<seal::SEALContext>(parms);
    plain_modulus = parms.plain_modulus().value();

    // Receiver generates and owns the secret key.
    seal::KeyGenerator keygen(*he_context);
    he_secret_key = keygen.secret_key();
    keygen.create_public_key(he_public_key);
    keygen.create_galois_keys(he_galois_keys);

    // --- Effective value computation: oc::block -> SM3 -> 40-bit mod t ---
    auto raw_hashed = sm3_hash_keys(keys);
    hashed_keys = truncate_to_plain(raw_hashed, plain_modulus);

    // --- Block partition (h0 = hashed_key % num_blocks) ---
    num_blocks = compute_num_blocks(keys.size());
    block_indices.resize(num_blocks);
    for (size_t i = 0; i < hashed_keys.size(); ++i)
        block_indices[hashed_keys[i] % num_blocks].push_back(i);

    block_sizes.resize(num_blocks);
    for (size_t bi = 0; bi < num_blocks; ++bi)
        block_sizes[bi] = block_indices[bi].size();

    // --- Send HE public material to Sender ---
    send_seal_obj(sock, he_public_key);
    send_seal_obj(sock, he_galois_keys);

    // Send num_blocks so Sender knows the partitioning.
    uint64_t nb = static_cast<uint64_t>(num_blocks);
    macoro::sync_wait(sock.send(move(nb)));

    // Fixed-shape online width depends only on Receiver's own partition.
    seal::BatchEncoder encoder(*he_context);
    seal::Encryptor encryptor(*he_context, he_public_key);
    const size_t slot_count = encoder.slot_count();
    uniform_batch_count = fixed_batch_count_for_blocks(block_indices, slot_count);

    // Send fixed-shape batch count so Sender knows the online shape.
    uint64_t ubc = static_cast<uint64_t>(uniform_batch_count);
    macoro::sync_wait(sock.send(move(ubc)));

    // --- Receive per-block filter metadata from Sender ---
    block_filter_seeds.resize(num_blocks);
    block_seg_len.resize(num_blocks);
    block_seg_mask.resize(num_blocks);
    block_seg_cl.resize(num_blocks);
    for (size_t bi = 0; bi < num_blocks; ++bi) {
        macoro::sync_wait(sock.recv(block_filter_seeds[bi]));
        macoro::sync_wait(sock.recv(block_seg_len[bi]));
        macoro::sync_wait(sock.recv(block_seg_mask[bi]));
        macoro::sync_wait(sock.recv(block_seg_cl[bi]));
    }

    // --- Step 3.2 (offline): Generate fixed-shape batched queries for all blocks ---
    // For security rollback, Receiver prepares query containers for every block
    // rather than pruning to only active blocks. Empty blocks produce zero batches.
    block_query_batches.assign(num_blocks, {});
    block_response_batches.assign(num_blocks, {});
    for (size_t bi = 0; bi < num_blocks; ++bi) {
        auto& indices = block_indices[bi];
        auto& batches = block_query_batches[bi];

        const size_t block_query_width = (block_seg_len[bi] == 0 || block_seg_cl[bi] == 0)
            ? 0
            : static_cast<size_t>(block_seg_len[bi]) * 3;
        size_t start = 0;
        for (size_t batch_idx = 0; batch_idx < uniform_batch_count; ++batch_idx) {
            const bool has_real_batch = block_query_width > 0 && start < indices.size();
            size_t end = has_real_batch ? min(start + slot_count, indices.size()) : start;
            size_t batch_size = end - start;

            ReceiverQueryBatch batch;
            batch.active_slots = batch_size;
            batch.receiver_indices.resize(batch_size);
            batch.c_hat_by_slot.resize(block_query_width);

            vector<array<size_t, 3>> positions(batch_size);
            vector<uint64_t> y_slots(slot_count, 0);
            for (size_t k = 0; k < batch_size; ++k) {
                size_t recv_idx = indices[start + k];
                uint64_t y = hashed_keys[recv_idx];
                batch.receiver_indices[k] = recv_idx;
                y_slots[k] = y;
                positions[k] = block_positions(y,
                                               block_filter_seeds[bi],
                                               block_seg_len[bi],
                                               block_seg_mask[bi],
                                               block_seg_cl[bi]);
            }

            for (size_t j = 0; j < block_query_width; ++j) {
                vector<uint64_t> c_hat_slots(slot_count, 0);
                for (size_t k = 0; k < batch_size; ++k) {
                    if (j == positions[k][0] || j == positions[k][1] || j == positions[k][2]) {
                        c_hat_slots[k] = 1;
                    }
                }
                seal::Plaintext pt_c;
                encoder.encode(c_hat_slots, pt_c);
                encryptor.encrypt(pt_c, batch.c_hat_by_slot[j]);
            }

            seal::Plaintext pt_y;
            encoder.encode(y_slots, pt_y);
            encryptor.encrypt(pt_y, batch.enc_y_batch);

            batches.push_back(move(batch));
            start = end;
        }
    }
}

// ============================================================
//  Sender::init  (offline stage)
// ============================================================

void Sender::init(coproto::Socket& sock, vector<oc::block>& sendK) {
    keys = sendK;

    // --- BFV setup ---
    auto parms = make_he_params();
    he_context = make_shared<seal::SEALContext>(parms);
    plain_modulus = parms.plain_modulus().value();

    // --- Effective value computation ---
    auto raw_hashed = sm3_hash_keys(keys);
    hashed_keys = truncate_to_plain(raw_hashed, plain_modulus);

    // --- Receive HE public material from Receiver ---
    recv_seal_obj(sock, recv_public_key, *he_context);
    recv_seal_obj(sock, recv_galois_keys, *he_context);

    // Receive num_blocks decided by Receiver.
    uint64_t nb = 0;
    macoro::sync_wait(sock.recv(nb));
    num_blocks = static_cast<size_t>(nb);

    // Receive fixed-shape batch count decided by Receiver.
    uint64_t ubc = 0;
    macoro::sync_wait(sock.recv(ubc));
    uniform_batch_count = static_cast<size_t>(ubc);

    // --- Block partition (same h0 rule as Receiver) ---
    block_indices.resize(num_blocks);
    for (size_t i = 0; i < hashed_keys.size(); ++i)
        block_indices[hashed_keys[i] % num_blocks].push_back(i);

    // --- Step 3.1: Build per-block additive fuse filters ---
    block_sizes.resize(num_blocks);
    block_filters.resize(num_blocks);
    block_filter_seeds.resize(num_blocks);
    block_seg_len.resize(num_blocks);
    block_seg_mask.resize(num_blocks);
    block_seg_cl.resize(num_blocks);
    for (size_t bi = 0; bi < num_blocks; ++bi) {
        auto& indices = block_indices[bi];
        block_sizes[bi] = indices.size();
        if (indices.empty()) continue;

        vector<uint64_t> block_keys(indices.size());
        for (size_t j = 0; j < indices.size(); ++j)
            block_keys[j] = hashed_keys[indices[j]];

        block_filters[bi] = binfuse::additive_filter(block_keys, block_keys, kFilterSeed, plain_modulus);
        block_filter_seeds[bi] = block_filters[bi].seed();
        block_seg_len[bi] = block_filters[bi].segment_length();
        block_seg_mask[bi] = block_filters[bi].segment_length_mask();
        block_seg_cl[bi] = block_filters[bi].segment_count_length();
    }

    // --- Send per-block filter metadata to Receiver ---
    for (size_t bi = 0; bi < num_blocks; ++bi) {
        uint64_t fs = block_filters[bi].is_populated() ? block_filters[bi].seed() : 0;
        uint32_t sl = block_filters[bi].is_populated() ? block_filters[bi].segment_length() : 0;
        uint32_t sm = block_filters[bi].is_populated() ? block_filters[bi].segment_length_mask() : 0;
        uint32_t sc = block_filters[bi].is_populated() ? block_filters[bi].segment_count_length() : 0;
        macoro::sync_wait(sock.send(move(fs)));
        macoro::sync_wait(sock.send(move(sl)));
        macoro::sync_wait(sock.send(move(sm)));
        macoro::sync_wait(sock.send(move(sc)));
    }

    // cout << "[Sender] init: n=" << keys.size()
    //      << ", blocks=" << num_blocks << endl;
}

// ============================================================
//  Receiver::output  (online stage)
// ============================================================

void Receiver::output(coproto::Socket& sock) {
    intersection.clear();

    // --- Step 3.3 (online): Send fixed-shape batched queries for all blocks ---
    for (size_t bi = 0; bi < num_blocks; ++bi) {
        for (size_t qi = 0; qi < uniform_batch_count; ++qi) {
            auto& batch = block_query_batches[bi][qi];
            for (size_t j = 0; j < batch.c_hat_by_slot.size(); ++j) {
                send_seal_obj(sock, batch.c_hat_by_slot[j]);
            }
            send_seal_obj(sock, batch.enc_y_batch);
        }
    }

    // --- Step 3.5 (online): Receive fixed-shape responses and decrypt ---
    seal::Decryptor decryptor(*he_context, he_secret_key);
    seal::BatchEncoder encoder(*he_context);

    block_response_batches.assign(num_blocks, {});
    for (size_t bi = 0; bi < num_blocks; ++bi) {
        block_response_batches[bi].resize(uniform_batch_count);
        for (size_t qi = 0; qi < uniform_batch_count; ++qi) {
            auto& resp = block_response_batches[bi][qi];
            resp.active_slots = block_query_batches[bi][qi].active_slots;
            recv_seal_obj(sock, resp.enc_result_batch, *he_context);

            seal::Plaintext pt_result;
            decryptor.decrypt(resp.enc_result_batch, pt_result);
            vector<uint64_t> result_slots;
            encoder.decode(pt_result, result_slots);

            auto& query_batch = block_query_batches[bi][qi];
            for (size_t k = 0; k < resp.active_slots; ++k) {
                if (result_slots[k] == 0) {
                    size_t recv_idx = query_batch.receiver_indices[k];
                    intersection.push_back(keys[recv_idx]);
                }
            }
        }
    }
}

// ============================================================
//  Sender::output  (online stage)
// ============================================================

void Sender::output(coproto::Socket& sock) {
    seal::Evaluator evaluator(*he_context);
    seal::Encryptor encryptor(*he_context, recv_public_key);
    seal::BatchEncoder encoder(*he_context);
    const size_t slot_count = encoder.slot_count();

    mt19937_64 rng(42);
    uniform_int_distribution<uint64_t> dist(1, plain_modulus - 1);

    // --- Step 3.3 (online): Receive fixed-shape batched queries for all blocks ---
    vector<vector<ReceiverQueryBatch>> incoming_batches(num_blocks);
    for (size_t bi = 0; bi < num_blocks; ++bi) {
        incoming_batches[bi].resize(uniform_batch_count);
        const size_t block_query_width = (block_seg_len[bi] == 0 || block_seg_cl[bi] == 0)
            ? 0
            : static_cast<size_t>(block_seg_len[bi]) * 3;
        for (size_t qi = 0; qi < uniform_batch_count; ++qi) {
            auto& batch = incoming_batches[bi][qi];
            batch.c_hat_by_slot.resize(block_query_width);
            for (size_t j = 0; j < block_query_width; ++j) {
                recv_seal_obj(sock, batch.c_hat_by_slot[j], *he_context);
            }
            recv_seal_obj(sock, batch.enc_y_batch, *he_context);
        }
    }

    // --- Step 3.4 (online): Compute fixed-shape batched membership tests ---
    for (size_t bi = 0; bi < num_blocks; ++bi) {
        const auto* filter_data = block_filters[bi].is_populated() ? block_filters[bi].data() : nullptr;
        const size_t m = block_filters[bi].is_populated() ? block_filters[bi].array_length() : 0;

        for (size_t qi = 0; qi < uniform_batch_count; ++qi) {
            auto& batch = incoming_batches[bi][qi];

            seal::Ciphertext sum_ct;
            bool sum_init = false;

            for (size_t j = 0; j < batch.c_hat_by_slot.size(); ++j) {
                if (j >= m || filter_data == nullptr) continue;
                uint64_t filter_val = filter_data[j];
                if (filter_val == 0) continue;

                vector<uint64_t> filter_slots(slot_count, filter_val);
                seal::Plaintext pt_filter;
                encoder.encode(filter_slots, pt_filter);

                seal::Ciphertext term = batch.c_hat_by_slot[j];
                evaluator.multiply_plain_inplace(term, pt_filter);

                if (!sum_init) {
                    sum_ct = move(term);
                    sum_init = true;
                } else {
                    evaluator.add_inplace(sum_ct, term);
                }
            }

            if (!sum_init) {
                vector<uint64_t> zero_slots(slot_count, 0);
                seal::Plaintext pt_zero;
                encoder.encode(zero_slots, pt_zero);
                encryptor.encrypt(pt_zero, sum_ct);
            }

            evaluator.sub_inplace(sum_ct, batch.enc_y_batch);

            vector<uint64_t> r_slots(slot_count, 1);
            const size_t active_slots = min(slot_count, block_sizes[bi] > qi * slot_count ? block_sizes[bi] - qi * slot_count : size_t(0));
            for (size_t k = 0; k < active_slots; ++k) {
                r_slots[k] = dist(rng);
            }
            seal::Plaintext pt_r;
            encoder.encode(r_slots, pt_r);
            evaluator.multiply_plain_inplace(sum_ct, pt_r);

            send_seal_obj(sock, sum_ct);
        }
    }

    // cout << "[Sender] output: fixed-shape batched step 3.4 done" << endl;
}
