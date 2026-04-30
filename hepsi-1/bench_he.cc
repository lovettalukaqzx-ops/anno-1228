#include <chrono>
#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <unordered_map>
#include <set>
#include <cmath>

#include "psi.h"

using namespace std;

static double elapsed_ms(const chrono::steady_clock::time_point& s,
                         const chrono::steady_clock::time_point& e) {
    return chrono::duration<double, milli>(e - s).count();
}

int main() {
    auto parms = make_he_params();
    seal::SEALContext context(parms);
    uint64_t t = parms.plain_modulus().value();
    size_t N = kPolyModulusDegree;      // 8192
    size_t half_N = N / 2;              // 4096

    seal::KeyGenerator keygen(context);
    auto sk = keygen.secret_key();
    seal::PublicKey pk; keygen.create_public_key(pk);
    seal::GaloisKeys gk; keygen.create_galois_keys(gk);
    seal::BatchEncoder encoder(context);
    seal::Encryptor encryptor(context, pk);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, sk);

    mt19937_64 rng(42);

    // Measure primitive op costs
    vector<uint64_t> data(N, 0);
    for (size_t i = 0; i < N; ++i) data[i] = rng() % t;
    seal::Plaintext pt; encoder.encode(data, pt);
    seal::Ciphertext ct; encryptor.encrypt(pt, ct);

    double rotate_rows_ms = 0, rotate_cols_ms = 0, mulplain_ms = 0, add_ms = 0;
    const int ITERS = 20;

    for (int i = 0; i < ITERS; ++i) {
        seal::Ciphertext r;
        auto t0 = chrono::steady_clock::now();
        evaluator.rotate_rows(ct, (i+1) % (int)(half_N-1) + 1, gk, r);
        rotate_rows_ms += elapsed_ms(t0, chrono::steady_clock::now());
    }
    rotate_rows_ms /= ITERS;

    for (int i = 0; i < ITERS; ++i) {
        seal::Ciphertext r;
        auto t0 = chrono::steady_clock::now();
        evaluator.rotate_columns(ct, gk, r);
        rotate_cols_ms += elapsed_ms(t0, chrono::steady_clock::now());
    }
    rotate_cols_ms /= ITERS;

    {
        vector<uint64_t> mask(N, 0); mask[0] = 1; mask[7] = 1;
        seal::Plaintext mpt; encoder.encode(mask, mpt);
        for (int i = 0; i < ITERS; ++i) {
            seal::Ciphertext r = ct;
            auto t0 = chrono::steady_clock::now();
            evaluator.multiply_plain_inplace(r, mpt);
            mulplain_ms += elapsed_ms(t0, chrono::steady_clock::now());
        }
        mulplain_ms /= ITERS;
    }

    {
        seal::Ciphertext ct2 = ct;
        for (int i = 0; i < ITERS; ++i) {
            seal::Ciphertext r = ct;
            auto t0 = chrono::steady_clock::now();
            evaluator.add_inplace(r, ct2);
            add_ms += elapsed_ms(t0, chrono::steady_clock::now());
        }
        add_ms /= ITERS;
    }

    stringstream ss; ct.save(ss);
    double ct_kb = ss.str().size() / 1024.0;

    cout << fixed << setprecision(2);
    cout << "degree=" << N << ", half_N=" << half_N << ", t=" << t << endl;
    cout << "rotate_rows:    " << rotate_rows_ms << " ms" << endl;
    cout << "rotate_columns: " << rotate_cols_ms << " ms" << endl;
    cout << "multiply_plain: " << mulplain_ms << " ms" << endl;
    cout << "add:            " << add_ms << " ms" << endl;
    cout << "ct size:        " << ct_kb << " KB" << endl;
    cout << endl;

    // ============================================================
    // Compare extraction strategies for one block
    // ============================================================
    // Strategy A: single-row (slots restricted to [0,4096))
    //   Only rotate_rows needed.
    // Strategy B: dual-row (slots in [0,8192))
    //   If source row != target row: rotate_columns + rotate_rows.
    //
    // Sender batch positions:
    //   single-row: batch_size <= 4096
    //   dual-row:   batch_size <= 8192 (but two rows of 4096 each)
    //
    // For dual-row extraction:
    //   src_row = pos / 4096, src_col = pos % 4096
    //   dst_row = i   / 4096, dst_col = i   % 4096
    //   if src_row != dst_row: rotate_columns
    //   then row-rotate by (src_col - dst_col + 4096) % 4096
    //

    struct Case {
        size_t n_sender;
        size_t m_block;
    };

    vector<Case> cases = {
        {1, 1301},
        {64, 1301},
        {256, 1301},
        {1024, 1301},
        {4096, 3900},
        {8192, 7800}
    };

    cout << "============================================================" << endl;
    cout << "  One-block extraction: single-row vs dual-row" << endl;
    cout << "============================================================" << endl;
    cout << setw(10) << "n_s"
         << setw(10) << "m"
         << setw(14) << "single_rots"
         << setw(14) << "single_ms"
         << setw(14) << "dual_rows"
         << setw(14) << "dual_cols"
         << setw(14) << "dual_ms"
         << endl;

    for (auto [n_s, m] : cases) {
        // Simulate sender positions
        vector<array<size_t,3>> pos(n_s);
        for (size_t i = 0; i < n_s; ++i) {
            pos[i][0] = rng() % m;
            pos[i][1] = rng() % m;
            pos[i][2] = rng() % m;
        }

        // Single-row
        // valid only if m <= 4096 and n_s <= 4096
        size_t single_unique_rot = 0;
        double single_ms = -1;
        if (m <= half_N && n_s <= half_N) {
            set<int> rots;
            for (size_t i = 0; i < n_s; ++i) {
                for (int r = 0; r < 3; ++r) {
                    int rot = static_cast<int>((pos[i][r] - i + half_N) % half_N);
                    rots.insert(rot);
                }
            }
            single_unique_rot = rots.size();
            single_ms = single_unique_rot * (rotate_rows_ms + mulplain_ms + add_ms);
        }

        // Dual-row
        set<pair<int,int>> dual_groups; // (need_col_rot, row_rot)
        size_t dual_col_rot_count = 0;
        size_t dual_total_groups = 0;

        // sender batch positions fill full 8192 slots: first 4096 in row0, next 4096 in row1
        for (size_t i = 0; i < n_s; ++i) {
            size_t dst_row = i / half_N;
            size_t dst_col = i % half_N;
            for (int r = 0; r < 3; ++r) {
                size_t src_row = pos[i][r] / half_N;
                size_t src_col = pos[i][r] % half_N;
                int need_col = (src_row != dst_row) ? 1 : 0;
                int row_rot = static_cast<int>((src_col - dst_col + half_N) % half_N);
                dual_groups.insert({need_col, row_rot});
            }
        }
        for (auto& [need_col, row_rot] : dual_groups) {
            (void)row_rot;
            if (need_col) dual_col_rot_count++;
        }
        dual_total_groups = dual_groups.size();
        size_t dual_row_only = dual_total_groups - dual_col_rot_count;
        double dual_ms = dual_row_only * (rotate_rows_ms + mulplain_ms + add_ms)
                       + dual_col_rot_count * (rotate_cols_ms + rotate_rows_ms + mulplain_ms + add_ms);

        cout << setw(10) << n_s
             << setw(10) << m;
        if (single_ms >= 0) {
            cout << setw(14) << single_unique_rot
                 << setw(14) << setprecision(1) << single_ms;
        } else {
            cout << setw(14) << "-"
                 << setw(14) << "-";
        }
        cout << setw(14) << dual_row_only
             << setw(14) << dual_col_rot_count
             << setw(14) << setprecision(1) << dual_ms
             << endl;
    }

    cout << endl;

    // ============================================================
    // Projected for your non-balanced benchmark set
    // Receiver = 2^20, 2^22, 2^24
    // Sender   = 1, 64, 256, 1024
    // Using ceil-based block count.
    //
    // Choose targetBlockSize to fill single-row vs full 8192:
    //   single-row target ≈ 3072  (m≈3900 < 4096)
    //   dual-row   target ≈ 6144  (m≈7800 < 8192)
    //
    // Compare total online time & R->S communication.
    //
    cout << "============================================================" << endl;
    cout << "  Your non-balanced benchmark set" << endl;
    cout << "  Compare: single-row target=3072 vs dual-row target=6144" << endl;
    cout << "============================================================" << endl;
    cout << setw(12) << "recv_n"
         << setw(10) << "send_n"
         << setw(10) << "blocks1"
         << setw(12) << "R->S1 MB"
         << setw(12) << "HE1 sec"
         << setw(10) << "blocks2"
         << setw(12) << "R->S2 MB"
         << setw(12) << "HE2 sec"
         << endl;

    vector<size_t> recv_sizes = {1UL<<20, 1UL<<22, 1UL<<24};
    vector<size_t> send_sizes = {1UL, 64UL, 256UL, 1024UL};

    auto ceil_div = [](size_t a, size_t b) { return (a + b - 1) / b; };

    for (size_t nr : recv_sizes) {
        for (size_t ns : send_sizes) {
            // Strategy 1: single-row target=3072
            size_t b1 = ceil_div(nr, 3072);
            double rs1_mb = b1 * ct_kb / 1024.0; // 1 ct/block
            // Active blocks ≈ min(ns, b1)
            size_t active1 = min(ns, b1);
            size_t s_per_block1 = max<size_t>(1, ns / active1);
            // For s_per_block small, rotations ≈ 3*s_per_block
            double he_per_block1 = (3*s_per_block1) * (rotate_rows_ms + mulplain_ms + add_ms)
                                 + 2*mulplain_ms + 0.3;
            double he1_sec = active1 * he_per_block1 / 1000.0;

            // Strategy 2: dual-row target=6144
            size_t b2 = ceil_div(nr, 6144);
            double rs2_mb = b2 * ct_kb / 1024.0;
            size_t active2 = min(ns, b2);
            size_t s_per_block2 = max<size_t>(1, ns / active2);
            // For small sender, roughly half queries need column rotation
            double avg_rot_cost = 0.5*(rotate_rows_ms + mulplain_ms + add_ms)
                                + 0.5*(rotate_cols_ms + rotate_rows_ms + mulplain_ms + add_ms);
            double he_per_block2 = (3*s_per_block2) * avg_rot_cost + 2*mulplain_ms + 0.3;
            double he2_sec = active2 * he_per_block2 / 1000.0;

            cout << setw(12) << nr
                 << setw(10) << ns
                 << setw(10) << b1
                 << setw(12) << setprecision(1) << rs1_mb
                 << setw(12) << he1_sec
                 << setw(10) << b2
                 << setw(12) << rs2_mb
                 << setw(12) << he2_sec
                 << endl;
        }
    }

    cout << endl;
    cout << "Interpretation:" << endl;
    cout << "  - dual-row 8192 roughly halves R->S communication (fewer blocks)" << endl;
    cout << "  - but introduces rotate_columns for cross-row extraction" << endl;
    cout << "  - in non-balanced settings (sender=1/64/256/1024), sender cost stays small" << endl;
    cout << "    because each active block has only ~1 sender element on average" << endl;

    return 0;
}
