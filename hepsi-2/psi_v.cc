#include "psi_v.h"

#include <algorithm>
#include <iostream>
#include <random>
#include <stdexcept>

using namespace std;
using namespace osuCrypto;

namespace {

size_t sender_driven_num_blocks_v(size_t send_size) {
    return max<size_t>(1, (send_size + gTargetBlockSize - 1) / gTargetBlockSize);
}

array<size_t, 3> block_positions_v(uint64_t key,
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

void reduce_full_batch_inplace_v(seal::Ciphertext& ct,
                                 seal::Evaluator& evaluator,
                                 const seal::GaloisKeys& gk,
                                 size_t slot_count) {
    const size_t half_slots = slot_count / 2;
    for (size_t step = 1; step < half_slots; step <<= 1) {
        seal::Ciphertext rotated;
        evaluator.rotate_rows(ct, static_cast<int>(step), gk, rotated);
        evaluator.add_inplace(ct, rotated);
    }

    seal::Ciphertext swapped;
    evaluator.rotate_columns(ct, gk, swapped);
    evaluator.add_inplace(ct, swapped);
}

} // namespace

void ReceiverV::init(coproto::Socket& sock, vector<oc::block>& recvK) {
    keys = recvK;

    auto parms = make_he_params();
    he_context = make_shared<seal::SEALContext>(parms);
    plain_modulus = parms.plain_modulus().value();

    seal::KeyGenerator keygen(*he_context);
    he_secret_key = keygen.secret_key();
    keygen.create_public_key(he_public_key);
    keygen.create_galois_keys(he_galois_keys);

    auto raw_hashed = sm3_hash_keys(keys);
    hashed_keys = truncate_to_plain(raw_hashed, plain_modulus);

    send_seal_obj(sock, he_public_key);
    send_seal_obj(sock, he_galois_keys);

    uint64_t nb = 0;
    macoro::sync_wait(sock.recv(nb));
    num_blocks = static_cast<size_t>(nb);

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

    uint64_t query_count = static_cast<uint64_t>(keys.size());
    macoro::sync_wait(sock.send(move(query_count)));

    seal::BatchEncoder encoder(*he_context);
    seal::Encryptor encryptor(*he_context, he_public_key);
    const size_t slot_count = encoder.slot_count();

    queries_by_receiver.assign(keys.size(), {});
    for (size_t idx = 0; idx < hashed_keys.size(); ++idx) {
        const uint64_t y = hashed_keys[idx];
        const size_t target_block = y % num_blocks;
        auto& queries = queries_by_receiver[idx];
        queries.reserve(num_blocks);

        for (size_t bi = 0; bi < num_blocks; ++bi) {
            const bool has_block = (block_seg_len[bi] != 0 && block_seg_cl[bi] != 0);

            vector<uint64_t> c_hat_slots(slot_count, 0);
            vector<uint64_t> y_slots(slot_count, has_block ? y : 1);
            if (has_block) {
                auto positions = block_positions_v(y,
                                                   block_filter_seeds[bi],
                                                   block_seg_len[bi],
                                                   block_seg_mask[bi],
                                                   block_seg_cl[bi]);
                c_hat_slots[positions[0]] = 1;
                c_hat_slots[positions[1]] = 1;
                c_hat_slots[positions[2]] = 1;
            }

            QueryBatchV query;
            query.receiver_index = idx;
            query.target_block = target_block;

            seal::Plaintext pt_c_hat;
            encoder.encode(c_hat_slots, pt_c_hat);
            encryptor.encrypt(pt_c_hat, query.enc_c_hat);

            seal::Plaintext pt_y;
            encoder.encode(y_slots, pt_y);
            encryptor.encrypt(pt_y, query.enc_y);

            queries.push_back(move(query));
        }
    }
}


void ReceiverV::output(coproto::Socket& sock) {
    intersection.clear();

    for (size_t idx = 0; idx < queries_by_receiver.size(); ++idx) {
        for (size_t bi = 0; bi < num_blocks; ++bi) {
            auto& query = queries_by_receiver[idx][bi];
            send_seal_obj(sock, query.enc_c_hat);
            send_seal_obj(sock, query.enc_y);
        }
    }

    seal::Decryptor decryptor(*he_context, he_secret_key);
    seal::BatchEncoder encoder(*he_context);

    for (size_t idx = 0; idx < queries_by_receiver.size(); ++idx) {
        for (size_t bi = 0; bi < num_blocks; ++bi) {
            seal::Ciphertext enc_result;
            recv_seal_obj(sock, enc_result, *he_context);

            if (bi != queries_by_receiver[idx][bi].target_block) {
                continue;
            }

            seal::Plaintext pt_result;
            decryptor.decrypt(enc_result, pt_result);
            vector<uint64_t> result_slots;
            encoder.decode(pt_result, result_slots);

            if (!result_slots.empty() && result_slots[0] == 0) {
                intersection.push_back(keys[queries_by_receiver[idx][bi].receiver_index]);
            }
        }
    }
}


void SenderV::init(coproto::Socket& sock, vector<oc::block>& sendK) {
    keys = sendK;

    auto parms = make_he_params();
    he_context = make_shared<seal::SEALContext>(parms);
    plain_modulus = parms.plain_modulus().value();

    auto raw_hashed = sm3_hash_keys(keys);
    hashed_keys = truncate_to_plain(raw_hashed, plain_modulus);

    recv_seal_obj(sock, recv_public_key, *he_context);
    recv_seal_obj(sock, recv_galois_keys, *he_context);

    num_blocks = sender_driven_num_blocks_v(keys.size());
    block_indices.resize(num_blocks);
    for (size_t i = 0; i < hashed_keys.size(); ++i) {
        block_indices[hashed_keys[i] % num_blocks].push_back(i);
    }

    seal::BatchEncoder encoder(*he_context);
    const size_t slot_count = encoder.slot_count();

    block_sizes.resize(num_blocks);
    block_filters.resize(num_blocks);
    block_filter_seeds.resize(num_blocks);
    block_seg_len.resize(num_blocks);
    block_seg_mask.resize(num_blocks);
    block_seg_cl.resize(num_blocks);
    block_filter_plaintexts.resize(num_blocks);

    for (size_t bi = 0; bi < num_blocks; ++bi) {
        auto& indices = block_indices[bi];
        block_sizes[bi] = indices.size();
        if (indices.empty()) continue;

        vector<uint64_t> block_keys(indices.size());
        for (size_t j = 0; j < indices.size(); ++j) {
            block_keys[j] = hashed_keys[indices[j]];
        }

        block_filters[bi] = binfuse::additive_filter(block_keys, block_keys, kFilterSeed, plain_modulus);
        const size_t m = block_filters[bi].array_length();
        block_filter_seeds[bi] = block_filters[bi].seed();
        block_seg_len[bi] = block_filters[bi].segment_length();
        block_seg_mask[bi] = block_filters[bi].segment_length_mask();
        block_seg_cl[bi] = block_filters[bi].segment_count_length();

        if (m > slot_count) {
            throw runtime_error("PSI_v requires sender filter length <= slot_count");
        }

        vector<uint64_t> filter_slots(slot_count, 0);
        const auto* filter_data = block_filters[bi].data();
        for (size_t j = 0; j < m; ++j) filter_slots[j] = filter_data[j];
        encoder.encode(filter_slots, block_filter_plaintexts[bi]);
    }

    uint64_t nb = static_cast<uint64_t>(num_blocks);
    macoro::sync_wait(sock.send(move(nb)));
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

    uint64_t query_count = 0;
    macoro::sync_wait(sock.recv(query_count));
    receiver_query_count = static_cast<size_t>(query_count);
}

void SenderV::output(coproto::Socket& sock) {
    seal::Evaluator evaluator(*he_context);
    seal::BatchEncoder encoder(*he_context);
    const size_t slot_count = encoder.slot_count();

    mt19937_64 rng(42);
    uniform_int_distribution<uint64_t> dist(1, plain_modulus - 1);

    for (size_t idx = 0; idx < receiver_query_count; ++idx) {
        for (size_t bi = 0; bi < num_blocks; ++bi) {
            seal::Ciphertext enc_c_hat;
            seal::Ciphertext enc_y;
            recv_seal_obj(sock, enc_c_hat, *he_context);
            recv_seal_obj(sock, enc_y, *he_context);

            evaluator.multiply_plain_inplace(enc_c_hat, block_filter_plaintexts[bi]);
            reduce_full_batch_inplace_v(enc_c_hat, evaluator, recv_galois_keys, slot_count);
            evaluator.sub_inplace(enc_c_hat, enc_y);

            vector<uint64_t> r_slots(slot_count, dist(rng));
            seal::Plaintext pt_r;
            encoder.encode(r_slots, pt_r);
            evaluator.multiply_plain_inplace(enc_c_hat, pt_r);

            send_seal_obj(sock, enc_c_hat);
        }
    }
}

