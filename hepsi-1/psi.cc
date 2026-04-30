#include "psi.h"
#include <cstring>
#include <iostream>
#include <algorithm>
#include <numeric>
#include <stdexcept>
#include <sstream>
#include <random>
#include <unordered_map>
#include <map>
#include <sys/time.h>
#include <gmssl/sm3.h>
#include <immintrin.h>
#include "sm3_avx512.h"

using namespace std;
using namespace osuCrypto;

int Number = 100;
std::size_t gTargetBlockSize = 6144;

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
    for (size_t i = 0; i < keys.size(); i++) out[i] = sm3_hash_block_to_u64(keys[i]);
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

vector<uint64_t> truncate_to_plain(const vector<uint64_t>& hashed, uint64_t plain_modulus) {
    constexpr uint64_t kMask40 = (UINT64_C(1) << 40) - 1;
    vector<uint64_t> out(hashed.size());
    for (size_t i = 0; i < hashed.size(); ++i)
        out[i] = (hashed[i] & kMask40) % plain_modulus;
    return out;
}

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
        for (size_t i = 0; i < common; i++) key[i] = prng_common.get<oc::block>();
        for (size_t i = common; i < key.size(); i++) key[i] = prng_recv_only.get<oc::block>();
    } else {
        for (size_t i = 0; i < common; i++) key[i] = prng_common.get<oc::block>();
        for (size_t i = common; i < key.size(); i++) key[i] = prng_send_only.get<oc::block>();
    }
}

seal::EncryptionParameters make_he_params() {
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(kPolyModulusDegree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(kPolyModulusDegree));
    parms.set_plain_modulus(seal::PlainModulus::Batching(kPolyModulusDegree, kPlainModulusBits));
    return parms;
}

size_t compute_num_blocks(size_t n_receiver) {
    return max<size_t>(1, (n_receiver + gTargetBlockSize - 1) / gTargetBlockSize);
}

void validate_block_size_or_throw() {
    // Current batched-slot implementation assumes one ciphertext per block.
    // Additive filter size is approximately 1.27 * block_size, so we require
    // that it fits within the 8192 batching slots.
    const double estimated_filter_slots = 1.27 * static_cast<double>(gTargetBlockSize);
    if (estimated_filter_slots > static_cast<double>(kPolyModulusDegree)) {
        std::ostringstream oss;
        oss << "gTargetBlockSize=" << gTargetBlockSize
            << " is too large for the current 1-block=1-ciphertext implementation: "
            << "estimated filter slots 1.27*block_size=" << estimated_filter_slots
            << " exceed kPolyModulusDegree=" << kPolyModulusDegree
            << ". Use a smaller block size (recommended <= 6144) or redesign blocks to span multiple ciphertexts.";
        throw std::invalid_argument(oss.str());
    }
}


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

void send_seal_obj(coproto::Socket& sock, const seal::PublicKey& obj) { send_seal_generic(sock, obj); }
void send_seal_obj(coproto::Socket& sock, const seal::GaloisKeys& obj) { send_seal_generic(sock, obj); }
void send_seal_obj(coproto::Socket& sock, const seal::Ciphertext& obj) { send_seal_generic(sock, obj); }
void recv_seal_obj(coproto::Socket& sock, seal::PublicKey& obj, const seal::SEALContext& ctx) { recv_seal_generic(sock, obj, ctx); }
void recv_seal_obj(coproto::Socket& sock, seal::GaloisKeys& obj, const seal::SEALContext& ctx) { recv_seal_generic(sock, obj, ctx); }
void recv_seal_obj(coproto::Socket& sock, seal::Ciphertext& obj, const seal::SEALContext& ctx) { recv_seal_generic(sock, obj, ctx); }

void Receiver::init(coproto::Socket& sock, vector<oc::block>& recvK) {
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

    num_blocks = compute_num_blocks(keys.size());
    block_indices.resize(num_blocks);
    for (size_t i = 0; i < hashed_keys.size(); ++i)
        block_indices[hashed_keys[i] % num_blocks].push_back(i);

    seal::Encryptor encryptor(*he_context, he_public_key);
    seal::BatchEncoder encoder(*he_context);
    const size_t N = encoder.slot_count();

    block_filters.resize(num_blocks);
    block_encrypted_cts.resize(num_blocks);
    for (size_t bi = 0; bi < num_blocks; ++bi) {
        auto& indices = block_indices[bi];
        if (indices.empty()) continue;
        vector<uint64_t> block_keys(indices.size());
        for (size_t j = 0; j < indices.size(); ++j)
            block_keys[j] = hashed_keys[indices[j]];
        block_filters[bi] = binfuse::additive_filter(block_keys, block_keys, kFilterSeed, plain_modulus);
        size_t m = block_filters[bi].array_length();
        vector<uint64_t> batch(N, 0);
        for (size_t j = 0; j < m; ++j) batch[j] = block_filters[bi].data()[j];
        seal::Plaintext pt;
        encoder.encode(batch, pt);
        encryptor.encrypt(pt, block_encrypted_cts[bi]);
    }

    send_seal_obj(sock, he_public_key);
    send_seal_obj(sock, he_galois_keys);
    {
        uint64_t nb = static_cast<uint64_t>(num_blocks);
        macoro::sync_wait(sock.send(move(nb)));
    }
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

    // cout << "[Receiver] init: n=" << keys.size() << ", blocks=" << num_blocks << ", t=" << plain_modulus << endl;
}

void Sender::init(coproto::Socket& sock, vector<oc::block>& sendK) {
    keys = sendK;
    auto parms = make_he_params();
    he_context = make_shared<seal::SEALContext>(parms);
    plain_modulus = parms.plain_modulus().value();
    auto raw_hashed = sm3_hash_keys(keys);
    hashed_keys = truncate_to_plain(raw_hashed, plain_modulus);

    recv_seal_obj(sock, recv_public_key, *he_context);
    recv_seal_obj(sock, recv_galois_keys, *he_context);
    {
        uint64_t nb = 0;
        macoro::sync_wait(sock.recv(nb));
        num_blocks = static_cast<size_t>(nb);
    }
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
    block_indices.resize(num_blocks);
    for (size_t i = 0; i < hashed_keys.size(); ++i)
        block_indices[hashed_keys[i] % num_blocks].push_back(i);

    // cout << "[Sender] init: n=" << keys.size() << ", blocks=" << num_blocks << endl;
}

void Receiver::output(coproto::Socket& sock) {
    seal::Decryptor decryptor(*he_context, he_secret_key);
    seal::BatchEncoder encoder(*he_context);
    const size_t N = encoder.slot_count();

    for (size_t bi = 0; bi < num_blocks; ++bi)
        send_seal_obj(sock, block_encrypted_cts[bi]);

    uint64_t total_pairs = 0;
    macoro::sync_wait(sock.recv(total_pairs));

    unordered_map<uint64_t, size_t> hash_to_index;
    hash_to_index.reserve(keys.size());
    for (size_t i = 0; i < keys.size(); ++i) hash_to_index[hashed_keys[i]] = i;

    intersection.clear();
    for (uint64_t p = 0; p < total_pairs; ++p) {
        seal::Ciphertext c1, c2;
        recv_seal_obj(sock, c1, *he_context);
        recv_seal_obj(sock, c2, *he_context);
        seal::Plaintext pt1, pt2;
        decryptor.decrypt(c1, pt1);
        decryptor.decrypt(c2, pt2);
        vector<uint64_t> p1, p2;
        encoder.decode(pt1, p1);
        encoder.decode(pt2, p2);
        for (size_t i = 0; i < N; ++i) {
            if (p1[i] == 0 && p2[i] != 0) {
                auto it = hash_to_index.find(p2[i]);
                if (it != hash_to_index.end()) intersection.push_back(keys[it->second]);
            }
        }
    }
}

void Sender::output(coproto::Socket& sock) {
    seal::BatchEncoder encoder(*he_context);
    seal::Evaluator evaluator(*he_context);
    seal::Encryptor encryptor(*he_context, recv_public_key);
    const size_t N = encoder.slot_count();
    const size_t half_N = N / 2;
    const uint64_t t = plain_modulus;
    mt19937_64 rng(42);

    vector<seal::Ciphertext> recv_block_cts(num_blocks);
    for (size_t bi = 0; bi < num_blocks; ++bi)
        recv_seal_obj(sock, recv_block_cts[bi], *he_context);

    // Collect all sender elements across blocks and pack them into fuller global batches.
    struct PackedElem {
        size_t sender_idx;
        size_t block_idx;
        uint64_t key;
        array<uint32_t,3> pos;
    };
    vector<PackedElem> packed;
    packed.reserve(hashed_keys.size());
    for (size_t bi = 0; bi < num_blocks; ++bi) {
        for (size_t sender_idx : block_indices[bi]) {
            uint64_t key = hashed_keys[sender_idx];
            uint64_t hash = binary_fuse_mix_split(key, block_filter_seeds[bi]);
            uint64_t hi = binary_fuse_mulhi(hash, block_seg_cl[bi]);
            uint32_t h0 = static_cast<uint32_t>(hi);
            uint32_t h1 = h0 + block_seg_len[bi];
            uint32_t h2 = h1 + block_seg_len[bi];
            h1 ^= static_cast<uint32_t>(hash >> 18U) & block_seg_mask[bi];
            h2 ^= static_cast<uint32_t>(hash) & block_seg_mask[bi];
            packed.push_back({sender_idx, bi, key, {h0,h1,h2}});
        }
    }

    vector<seal::Ciphertext> all_c1, all_c2;

    // Use full N-slot batches across blocks
    for (size_t batch_start = 0; batch_start < packed.size(); batch_start += N) {
        size_t batch_end = min(batch_start + N, packed.size());
        size_t batch_size = batch_end - batch_start;

        seal::Ciphertext sum_ct;
        bool sum_init = false;

        for (int r = 0; r < 3; ++r) {
            // Group by (block_idx, need_col, row_rot)
            map<tuple<size_t,int,int>, vector<size_t>> rot_groups;
            for (size_t local_i = 0; local_i < batch_size; ++local_i) {
                const auto& e = packed[batch_start + local_i];
                uint32_t slot_offset = e.pos[r];
                size_t src_row = slot_offset / half_N;
                size_t src_col = slot_offset % half_N;
                size_t dst_row = local_i / half_N;
                size_t dst_col = local_i % half_N;
                int need_col = (src_row != dst_row) ? 1 : 0;
                int row_rot = static_cast<int>((src_col - dst_col + half_N) % half_N);
                rot_groups[{e.block_idx, need_col, row_rot}].push_back(local_i);
            }

            seal::Ciphertext agg_r;
            bool agg_init = false;

            for (auto& [key_tuple, indices] : rot_groups) {
                size_t block_idx = get<0>(key_tuple);
                int need_col = get<1>(key_tuple);
                int row_rot = get<2>(key_tuple);

                vector<uint64_t> mask(N, 0);
                for (size_t idx : indices) mask[idx] = 1;
                seal::Plaintext mask_pt;
                encoder.encode(mask, mask_pt);

                seal::Ciphertext rotated = recv_block_cts[block_idx];
                if (need_col) {
                    seal::Ciphertext tmp;
                    evaluator.rotate_columns(rotated, recv_galois_keys, tmp);
                    rotated = move(tmp);
                }
                if (row_rot != 0) {
                    seal::Ciphertext tmp;
                    evaluator.rotate_rows(rotated, row_rot, recv_galois_keys, tmp);
                    rotated = move(tmp);
                }

                evaluator.multiply_plain_inplace(rotated, mask_pt);
                if (!agg_init) {
                    agg_r = move(rotated);
                    agg_init = true;
                } else {
                    evaluator.add_inplace(agg_r, rotated);
                }
            }

            if (agg_init) {
                if (!sum_init) {
                    sum_ct = move(agg_r);
                    sum_init = true;
                } else {
                    evaluator.add_inplace(sum_ct, agg_r);
                }
            }
        }

        vector<uint64_t> x_batch(N, 0);
        for (size_t i = 0; i < batch_size; ++i) x_batch[i] = packed[batch_start + i].key;
        seal::Plaintext x_pt;
        encoder.encode(x_batch, x_pt);

        seal::Ciphertext diff;
        if (sum_init) {
            diff = sum_ct;
            evaluator.sub_plain_inplace(diff, x_pt);
        } else {
            encryptor.encrypt(x_pt, diff);
            evaluator.negate_inplace(diff);
        }

        vector<uint64_t> r1v(N, 0), r2v(N, 0);
        for (size_t i = 0; i < batch_size; ++i) {
            r1v[i] = (rng() % (t - 1)) + 1;
            r2v[i] = (rng() % (t - 1)) + 1;
        }
        seal::Plaintext r1_pt, r2_pt;
        encoder.encode(r1v, r1_pt);
        encoder.encode(r2v, r2_pt);

        seal::Ciphertext c1, c2;
        evaluator.multiply_plain(diff, r1_pt, c1);
        evaluator.multiply_plain(diff, r2_pt, c2);
        evaluator.add_plain_inplace(c2, x_pt);

        all_c1.push_back(move(c1));
        all_c2.push_back(move(c2));
    }

    {
        size_t np = all_c1.size();
        vector<size_t> perm(np);
        iota(perm.begin(), perm.end(), 0);
        shuffle(perm.begin(), perm.end(), rng);
        vector<seal::Ciphertext> shuf_c1(np), shuf_c2(np);
        for (size_t i = 0; i < np; ++i) {
            shuf_c1[i] = move(all_c1[perm[i]]);
            shuf_c2[i] = move(all_c2[perm[i]]);
        }
        all_c1 = move(shuf_c1);
        all_c2 = move(shuf_c2);
    }

    {
        uint64_t total = static_cast<uint64_t>(all_c1.size());
        macoro::sync_wait(sock.send(move(total)));
        for (size_t i = 0; i < all_c1.size(); ++i) {
            send_seal_obj(sock, all_c1[i]);
            send_seal_obj(sock, all_c2[i]);
        }
    }
}
