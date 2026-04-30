#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "psi.h"
#include "psi_v.h"

using namespace std;

static double elapsed_ms(const chrono::steady_clock::time_point& s,
                         const chrono::steady_clock::time_point& e) {
    return chrono::duration<double, milli>(e - s).count();
}

struct HeSetup {
    size_t degree = 0;
    seal::EncryptionParameters parms{seal::scheme_type::bfv};
    shared_ptr<seal::SEALContext> context;
    uint64_t plain_modulus = 0;
    unique_ptr<seal::KeyGenerator> keygen;
    seal::SecretKey sk;
    seal::PublicKey pk;
    seal::GaloisKeys gk;
    unique_ptr<seal::BatchEncoder> encoder;
    unique_ptr<seal::Encryptor> encryptor;
    unique_ptr<seal::Evaluator> evaluator;
};

struct PrimitiveStats {
    double rotate_rows_ms = 0.0;
    double rotate_cols_ms = 0.0;
    double mulplain_ms = 0.0;
    double add_ms = 0.0;
    double ct_kb = -1.0;
};

struct CompareRow {
    string impl_name;
    string role_mode;
    size_t recv_size = 0;
    size_t send_size = 0;
    double recv_to_send_mb = 0.0;
    double send_to_recv_mb = 0.0;
    double sender_he_ms = 0.0;
    string note;
};

struct BlockQueryCandidateRow {
    size_t recv_size = 0;
    size_t send_size = 0;
    size_t num_blocks = 0;
    size_t queries_per_block = 0;
    size_t batches_per_block = 0;
    size_t filter_length = 0;
    double recv_to_send_mb = 0.0;
    double send_to_recv_mb = 0.0;
    double sender_he_ms = 0.0;
};

static optional<HeSetup> make_he_setup(size_t degree, int plain_bits) {
    try {
        HeSetup hs;
        hs.degree = degree;
        hs.parms = seal::EncryptionParameters(seal::scheme_type::bfv);
        hs.parms.set_poly_modulus_degree(degree);
        hs.parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(degree));
        hs.parms.set_plain_modulus(seal::PlainModulus::Batching(degree, plain_bits));
        hs.context = make_shared<seal::SEALContext>(hs.parms);
        hs.plain_modulus = hs.parms.plain_modulus().value();
        hs.keygen = make_unique<seal::KeyGenerator>(*hs.context);
        hs.sk = hs.keygen->secret_key();
        hs.keygen->create_public_key(hs.pk);
        hs.keygen->create_galois_keys(hs.gk);
        hs.encoder = make_unique<seal::BatchEncoder>(*hs.context);
        hs.encryptor = make_unique<seal::Encryptor>(*hs.context, hs.pk);
        hs.evaluator = make_unique<seal::Evaluator>(*hs.context);
        return hs;
    } catch (const exception&) {
        return nullopt;
    }
}

static PrimitiveStats measure_primitives(HeSetup& hs) {
    PrimitiveStats stats;
    const size_t N = hs.encoder->slot_count();
    const size_t half_N = N / 2;
    mt19937_64 rng(42);

    vector<uint64_t> data(N, 0);
    for (size_t i = 0; i < N; ++i) data[i] = rng() % hs.plain_modulus;

    seal::Plaintext pt;
    hs.encoder->encode(data, pt);
    seal::Ciphertext ct;
    hs.encryptor->encrypt(pt, ct);

    const int ITERS = 20;

    for (int i = 0; i < ITERS; ++i) {
        seal::Ciphertext r;
        auto t0 = chrono::steady_clock::now();
        hs.evaluator->rotate_rows(ct, static_cast<int>((i + 1) % max<size_t>(1, half_N - 1) + 1), hs.gk, r);
        stats.rotate_rows_ms += elapsed_ms(t0, chrono::steady_clock::now());
    }
    stats.rotate_rows_ms /= ITERS;

    for (int i = 0; i < ITERS; ++i) {
        seal::Ciphertext r;
        auto t0 = chrono::steady_clock::now();
        hs.evaluator->rotate_columns(ct, hs.gk, r);
        stats.rotate_cols_ms += elapsed_ms(t0, chrono::steady_clock::now());
    }
    stats.rotate_cols_ms /= ITERS;

    vector<uint64_t> mask(N, 0);
    mask[0] = 1;
    seal::Plaintext mpt;
    hs.encoder->encode(mask, mpt);
    for (int i = 0; i < ITERS; ++i) {
        seal::Ciphertext r = ct;
        auto t0 = chrono::steady_clock::now();
        hs.evaluator->multiply_plain_inplace(r, mpt);
        stats.mulplain_ms += elapsed_ms(t0, chrono::steady_clock::now());
    }
    stats.mulplain_ms /= ITERS;

    seal::Ciphertext ct2 = ct;
    for (int i = 0; i < ITERS; ++i) {
        seal::Ciphertext r = ct;
        auto t0 = chrono::steady_clock::now();
        hs.evaluator->add_inplace(r, ct2);
        stats.add_ms += elapsed_ms(t0, chrono::steady_clock::now());
    }
    stats.add_ms /= ITERS;

    stringstream ss;
    ct.save(ss);
    stats.ct_kb = ss.str().size() / 1024.0;
    return stats;
}

static size_t estimate_filter_length(size_t sender_block_size, uint64_t plain_modulus) {
    if (sender_block_size == 0) return 0;
    vector<uint64_t> keys(sender_block_size);
    for (size_t i = 0; i < sender_block_size; ++i) keys[i] = static_cast<uint64_t>(i + 1);
    binfuse::additive_filter filter(keys, keys, kFilterSeed, plain_modulus);
    return filter.array_length();
}

static size_t estimate_query_width(size_t sender_block_size, uint64_t plain_modulus) {
    if (sender_block_size == 0) return 0;
    vector<uint64_t> keys(sender_block_size);
    for (size_t i = 0; i < sender_block_size; ++i) keys[i] = static_cast<uint64_t>(i + 1);
    binfuse::additive_filter filter(keys, keys, kFilterSeed, plain_modulus);
    return static_cast<size_t>(filter.segment_length()) * 3;
}

static int sum_tree_rotations(size_t slot_count) {
    int rots = 0;
    for (size_t step = 1; step < slot_count; step <<= 1) ++rots;
    return rots;
}

static CompareRow current_main_row(size_t degree,
                                   uint64_t plain_modulus,
                                   const PrimitiveStats& stats,
                                   size_t recv_size,
                                   size_t send_size,
                                   size_t target_block_size) {
    CompareRow row;
    row.impl_name = "PSI";
    row.role_mode = "receiver-large";
    row.recv_size = recv_size;
    row.send_size = send_size;

    const size_t num_blocks = max<size_t>(1, (recv_size + target_block_size - 1) / target_block_size);
    const size_t recv_per_block = (recv_size + num_blocks - 1) / num_blocks;
    const size_t sender_per_block = (send_size + num_blocks - 1) / num_blocks;
    const size_t uniform_batch_count = (recv_per_block + degree - 1) / degree;
    const size_t query_width = estimate_query_width(sender_per_block, plain_modulus);
    const size_t filter_length = estimate_filter_length(sender_per_block, plain_modulus);
    if (uniform_batch_count == 0) return row;

    row.recv_to_send_mb = (static_cast<double>(num_blocks) * static_cast<double>(uniform_batch_count) *
                           static_cast<double>(query_width + 1) * stats.ct_kb) / 1024.0;
    row.send_to_recv_mb = (static_cast<double>(num_blocks) * static_cast<double>(uniform_batch_count) *
                           stats.ct_kb) / 1024.0;
    const double per_batch_ms = static_cast<double>(filter_length) * stats.mulplain_ms
                              + static_cast<double>(max<size_t>(0, filter_length - 1)) * stats.add_ms
                              + stats.add_ms + stats.mulplain_ms;
    row.sender_he_ms = static_cast<double>(num_blocks) * static_cast<double>(uniform_batch_count) * per_batch_ms;
    row.note = "receiver large / sender small / fixed-shape";
    return row;
}

static CompareRow v1_row(size_t degree,
                         uint64_t plain_modulus,
                         const PrimitiveStats& stats,
                         size_t recv_size,
                         size_t send_size,
                         size_t target_block_size) {
    CompareRow row;
    row.impl_name = "PSI_v";
    row.role_mode = "receiver-small";
    row.recv_size = recv_size;
    row.send_size = send_size;

    const size_t num_blocks = max<size_t>(1, (send_size + target_block_size - 1) / target_block_size);
    const size_t send_per_block = (send_size + num_blocks - 1) / num_blocks;
    const size_t filter_length = estimate_filter_length(send_per_block, plain_modulus);
    if (recv_size == 0 || filter_length == 0) return row;

    row.recv_to_send_mb = (2.0 * static_cast<double>(recv_size) * static_cast<double>(num_blocks) * stats.ct_kb) / 1024.0;
    row.send_to_recv_mb = (1.0 * static_cast<double>(recv_size) * static_cast<double>(num_blocks) * stats.ct_kb) / 1024.0;
    const double reduce_cost = stats.rotate_rows_ms * static_cast<double>(sum_tree_rotations(degree / 2))
                             + ((filter_length > degree / 2) ? stats.rotate_cols_ms : 0.0)
                             + stats.add_ms * static_cast<double>(sum_tree_rotations(degree / 2) + 1);
    const double per_query_ms = stats.mulplain_ms + reduce_cost + stats.add_ms + stats.mulplain_ms;
    row.sender_he_ms = per_query_ms * static_cast<double>(recv_size) * static_cast<double>(num_blocks);
    row.note = "receiver small / sender large / fixed-shape";
    return row;
}

static BlockQueryCandidateRow v1_block_query_candidate(size_t degree,
                                                       uint64_t plain_modulus,
                                                       const PrimitiveStats& stats,
                                                       size_t recv_size,
                                                       size_t send_size,
                                                       size_t target_block_size) {
    BlockQueryCandidateRow row;
    row.recv_size = recv_size;
    row.send_size = send_size;

    row.num_blocks = max<size_t>(1, (send_size + target_block_size - 1) / target_block_size);
    row.queries_per_block = (recv_size + row.num_blocks - 1) / row.num_blocks;
    const size_t send_per_block = (send_size + row.num_blocks - 1) / row.num_blocks;
    row.filter_length = estimate_filter_length(send_per_block, plain_modulus);
    if (recv_size == 0 || row.filter_length == 0) return row;

    row.batches_per_block = (row.queries_per_block + degree - 1) / degree;
    row.recv_to_send_mb = (static_cast<double>(row.num_blocks) * static_cast<double>(row.batches_per_block) *
                           static_cast<double>(row.filter_length + 1) * stats.ct_kb) / 1024.0;
    row.send_to_recv_mb = (static_cast<double>(row.num_blocks) * static_cast<double>(row.batches_per_block) *
                           stats.ct_kb) / 1024.0;
    const double per_batch_ms = static_cast<double>(row.filter_length) * stats.mulplain_ms
                              + static_cast<double>(max<size_t>(0, row.filter_length - 1)) * stats.add_ms
                              + stats.add_ms + stats.mulplain_ms;
    row.sender_he_ms = static_cast<double>(row.num_blocks) * static_cast<double>(row.batches_per_block) * per_batch_ms;
    return row;
}

static void print_row(const CompareRow& row) {
    cout << setw(16) << row.impl_name
         << setw(18) << row.role_mode
         << setw(12) << row.recv_size
         << setw(12) << row.send_size
         << setw(14) << setprecision(1) << row.recv_to_send_mb
         << setw(14) << row.send_to_recv_mb
         << setw(14) << row.sender_he_ms
         << "  " << row.note
         << endl;
}

int main() {
    cout << fixed << setprecision(2);
    cout << "============================================================" << endl;
    cout << "  HEPSI formal protocol comparison bench" << endl;
    cout << "============================================================" << endl;
    cout << endl;

    const size_t degree = 8192;
    auto setup = make_he_setup(degree, 41);
    if (!setup) {
        cout << "degree=8192, plain_bits=41 is unavailable" << endl;
        return 0;
    }

    auto stats = measure_primitives(*setup);
    const size_t target_block_size = 6144;

    cout << "degree=" << degree << ", plain_modulus=" << setup->plain_modulus << endl;
    cout << "rotate_rows=" << stats.rotate_rows_ms << " ms, rotate_columns=" << stats.rotate_cols_ms
         << " ms, multiply_plain=" << stats.mulplain_ms << " ms, add=" << stats.add_ms
         << " ms, ct=" << stats.ct_kb << " KB" << endl;
    cout << endl;

    cout << setw(16) << "implementation"
         << setw(18) << "role_mode"
         << setw(12) << "|Y|"
         << setw(12) << "|X|"
         << setw(14) << "R->S MB"
         << setw(14) << "S->R MB"
         << setw(14) << "S HE ms"
         << "  note"
         << endl;

    vector<size_t> sender_small = {1, 64, 256, 1024};
    for (size_t send_size : sender_small) {
        print_row(current_main_row(degree, setup->plain_modulus, stats, 1UL << 20, send_size, target_block_size));
    }
    cout << endl;

    vector<size_t> receiver_small = {1, 64, 256, 1024};
    for (size_t recv_size : receiver_small) {
        print_row(v1_row(degree, setup->plain_modulus, stats, recv_size, 1UL << 20, target_block_size));
    }
    cout << endl;

    cout << "Block-query candidate for PSI_v (theoretical only):" << endl;
    cout << setw(12) << "|Y|"
         << setw(12) << "|X|"
         << setw(12) << "blocks"
         << setw(12) << "q/block"
         << setw(12) << "b/block"
         << setw(12) << "m"
         << setw(14) << "R->S MB"
         << setw(14) << "S->R MB"
         << setw(14) << "S HE ms"
         << endl;
    for (size_t recv_size : receiver_small) {
        auto cand = v1_block_query_candidate(degree, setup->plain_modulus, stats, recv_size, 1UL << 20, target_block_size);
        cout << setw(12) << cand.recv_size
             << setw(12) << cand.send_size
             << setw(12) << cand.num_blocks
             << setw(12) << cand.queries_per_block
             << setw(12) << cand.batches_per_block
             << setw(12) << cand.filter_length
             << setw(14) << setprecision(1) << cand.recv_to_send_mb
             << setw(14) << cand.send_to_recv_mb
             << setw(14) << cand.sender_he_ms
             << endl;
    }

    cout << endl;
    cout << "PSI   : formal receiver-large / sender-small protocol" << endl;
    cout << "PSI_v : formal receiver-small / sender-large protocol" << endl;
    return 0;
}
