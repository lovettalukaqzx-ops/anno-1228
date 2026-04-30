#include <algorithm>
#include <barrier>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "psi.h"

using namespace std;
using namespace osuCrypto;

struct BeaverPhaseTimings {
    double base_ot_setup = 0.0;
    double random_ot = 0.0;
    double correction_build = 0.0;
    double correction_exchange = 0.0;
    double share_assembly = 0.0;
};

struct BeaverTimings {
    BeaverPhaseTimings phase1;
    BeaverPhaseTimings phase2;
    double local_term = 0.0;
    double total = 0.0;
};

struct StageTimings {
    double key_setup = 0.0;
    double hash_and_filter = 0.0;
    double local_share_sampling = 0.0;
    double beaver_triple = 0.0;
    BeaverTimings beaver_details;
    double open_local_prep = 0.0;
    double table_prep = 0.0;
    double offline_total = 0.0;
    double online_total = 0.0;
};

static double elapsed_seconds(const chrono::steady_clock::time_point& start,
                              const chrono::steady_clock::time_point& end) {
    return chrono::duration<double>(end - start).count();
}

macoro::task<void> beaver_triple_sender_profiled_ot(
    coproto::Socket sock,
    const vector<uint64_t>& a, const vector<uint64_t>& b,
    vector<uint64_t>& c,
    BeaverTimings& timings)
{
    const auto totalStart = chrono::steady_clock::now();
    size_t m = a.size();
    size_t numOTs = m * 64;
    c.assign(m, 0);

    oc::PRNG prng(toBlock(1000));

    {
        const auto t0 = chrono::steady_clock::now();
        IknpOtExtSender extSender;
        co_await extSender.genBaseOts(prng, sock);
        const auto t1 = chrono::steady_clock::now();
        timings.phase1.base_ot_setup = elapsed_seconds(t0, t1);

        vector<array<oc::block, 2>> otMsgs(numOTs);
        const auto t2 = chrono::steady_clock::now();
        co_await extSender.send(otMsgs, prng, sock);
        const auto t3 = chrono::steady_clock::now();
        timings.phase1.random_ot = elapsed_seconds(t2, t3);

        BitVector dCorr(numOTs);
        const auto t4 = chrono::steady_clock::now();
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
        const auto t5 = chrono::steady_clock::now();
        timings.phase1.correction_build = elapsed_seconds(t4, t5);

        BitVector eCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(dCorr)),
            sock.recv(eCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase1.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
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
        const auto t9 = chrono::steady_clock::now();
        timings.phase1.share_assembly = elapsed_seconds(t8, t9);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        IknpOtExtReceiver extRecv;
        co_await extRecv.genBaseOts(prng, sock);
        const auto t1 = chrono::steady_clock::now();
        timings.phase2.base_ot_setup = elapsed_seconds(t0, t1);

        BitVector choices(numOTs);
        choices.randomize(prng);
        vector<oc::block> otMsgs(numOTs);
        const auto t2 = chrono::steady_clock::now();
        co_await extRecv.receive(choices, otMsgs, prng, sock);
        const auto t3 = chrono::steady_clock::now();
        timings.phase2.random_ot = elapsed_seconds(t2, t3);

        BitVector eCorr(numOTs);
        const auto t4 = chrono::steady_clock::now();
        for (size_t i = 0; i < m; i++)
            for (size_t j = 0; j < 64; j++)
                eCorr[i * 64 + j] = ((b[i] >> j) & 1) ^ choices[i * 64 + j];
        const auto t5 = chrono::steady_clock::now();
        timings.phase2.correction_build = elapsed_seconds(t4, t5);

        BitVector dCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(eCorr)),
            sock.recv(dCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase2.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
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
        const auto t9 = chrono::steady_clock::now();
        timings.phase2.share_assembly = elapsed_seconds(t8, t9);
    }

    const auto t0 = chrono::steady_clock::now();
    for (size_t i = 0; i < m; i++) c[i] ^= (a[i] & b[i]);
    const auto t1 = chrono::steady_clock::now();
    timings.local_term = elapsed_seconds(t0, t1);
    timings.total = elapsed_seconds(totalStart, chrono::steady_clock::now());
}

macoro::task<void> beaver_triple_receiver_profiled_ot(
    coproto::Socket sock,
    const vector<uint64_t>& a, const vector<uint64_t>& b,
    vector<uint64_t>& c,
    BeaverTimings& timings)
{
    const auto totalStart = chrono::steady_clock::now();
    size_t m = a.size();
    size_t numOTs = m * 64;
    c.assign(m, 0);

    oc::PRNG prng(toBlock(2000));

    {
        const auto t0 = chrono::steady_clock::now();
        IknpOtExtReceiver extRecv;
        co_await extRecv.genBaseOts(prng, sock);
        const auto t1 = chrono::steady_clock::now();
        timings.phase1.base_ot_setup = elapsed_seconds(t0, t1);

        BitVector choices(numOTs);
        choices.randomize(prng);
        vector<oc::block> otMsgs(numOTs);
        const auto t2 = chrono::steady_clock::now();
        co_await extRecv.receive(choices, otMsgs, prng, sock);
        const auto t3 = chrono::steady_clock::now();
        timings.phase1.random_ot = elapsed_seconds(t2, t3);

        BitVector eCorr(numOTs);
        const auto t4 = chrono::steady_clock::now();
        for (size_t i = 0; i < m; i++)
            for (size_t j = 0; j < 64; j++)
                eCorr[i * 64 + j] = ((b[i] >> j) & 1) ^ choices[i * 64 + j];
        const auto t5 = chrono::steady_clock::now();
        timings.phase1.correction_build = elapsed_seconds(t4, t5);

        BitVector dCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(eCorr)),
            sock.recv(dCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase1.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
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
        const auto t9 = chrono::steady_clock::now();
        timings.phase1.share_assembly = elapsed_seconds(t8, t9);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        IknpOtExtSender extSender;
        co_await extSender.genBaseOts(prng, sock);
        const auto t1 = chrono::steady_clock::now();
        timings.phase2.base_ot_setup = elapsed_seconds(t0, t1);

        vector<array<oc::block, 2>> otMsgs(numOTs);
        const auto t2 = chrono::steady_clock::now();
        co_await extSender.send(otMsgs, prng, sock);
        const auto t3 = chrono::steady_clock::now();
        timings.phase2.random_ot = elapsed_seconds(t2, t3);

        BitVector dCorr(numOTs);
        const auto t4 = chrono::steady_clock::now();
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
        const auto t5 = chrono::steady_clock::now();
        timings.phase2.correction_build = elapsed_seconds(t4, t5);

        BitVector eCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(dCorr)),
            sock.recv(eCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase2.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
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
        const auto t9 = chrono::steady_clock::now();
        timings.phase2.share_assembly = elapsed_seconds(t8, t9);
    }

    const auto t0 = chrono::steady_clock::now();
    for (size_t i = 0; i < m; i++) c[i] ^= (a[i] & b[i]);
    const auto t1 = chrono::steady_clock::now();
    timings.local_term = elapsed_seconds(t0, t1);
    timings.total = elapsed_seconds(totalStart, chrono::steady_clock::now());
}

macoro::task<void> beaver_triple_sender_profiled_vole(
    coproto::Socket sock,
    const vector<uint64_t>& a, const vector<uint64_t>& b,
    vector<uint64_t>& c,
    BeaverTimings& timings)
{
    const auto totalStart = chrono::steady_clock::now();
    size_t m = a.size();
    size_t numOTs = m * 64;
    c.assign(m, 0);

    oc::PRNG prng(toBlock(1000));

    {
        const auto t0 = chrono::steady_clock::now();
        SilentOtExtSender extSender;
        co_await extSender.genBaseOts(prng, sock);
        const auto t1 = chrono::steady_clock::now();
        timings.phase1.base_ot_setup = elapsed_seconds(t0, t1);

        vector<array<oc::block, 2>> otMsgs(numOTs);
        const auto t2 = chrono::steady_clock::now();
        co_await extSender.send(otMsgs, prng, sock);
        const auto t3 = chrono::steady_clock::now();
        timings.phase1.random_ot = elapsed_seconds(t2, t3);

        BitVector dCorr(numOTs);
        const auto t4 = chrono::steady_clock::now();
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
        const auto t5 = chrono::steady_clock::now();
        timings.phase1.correction_build = elapsed_seconds(t4, t5);

        BitVector eCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(dCorr)),
            sock.recv(eCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase1.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
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
        const auto t9 = chrono::steady_clock::now();
        timings.phase1.share_assembly = elapsed_seconds(t8, t9);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        SilentOtExtReceiver extRecv;
        co_await extRecv.genBaseOts(prng, sock);
        const auto t1 = chrono::steady_clock::now();
        timings.phase2.base_ot_setup = elapsed_seconds(t0, t1);

        BitVector choices(numOTs);
        choices.randomize(prng);
        vector<oc::block> otMsgs(numOTs);
        const auto t2 = chrono::steady_clock::now();
        co_await extRecv.receive(choices, otMsgs, prng, sock);
        const auto t3 = chrono::steady_clock::now();
        timings.phase2.random_ot = elapsed_seconds(t2, t3);

        BitVector eCorr(numOTs);
        const auto t4 = chrono::steady_clock::now();
        for (size_t i = 0; i < m; i++)
            for (size_t j = 0; j < 64; j++)
                eCorr[i * 64 + j] = ((b[i] >> j) & 1) ^ choices[i * 64 + j];
        const auto t5 = chrono::steady_clock::now();
        timings.phase2.correction_build = elapsed_seconds(t4, t5);

        BitVector dCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(eCorr)),
            sock.recv(dCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase2.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
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
        const auto t9 = chrono::steady_clock::now();
        timings.phase2.share_assembly = elapsed_seconds(t8, t9);
    }

    const auto t0 = chrono::steady_clock::now();
    for (size_t i = 0; i < m; i++) c[i] ^= (a[i] & b[i]);
    const auto t1 = chrono::steady_clock::now();
    timings.local_term = elapsed_seconds(t0, t1);
    timings.total = elapsed_seconds(totalStart, chrono::steady_clock::now());
}

macoro::task<void> beaver_triple_receiver_profiled_vole(
    coproto::Socket sock,
    const vector<uint64_t>& a, const vector<uint64_t>& b,
    vector<uint64_t>& c,
    BeaverTimings& timings)
{
    const auto totalStart = chrono::steady_clock::now();
    size_t m = a.size();
    size_t numOTs = m * 64;
    c.assign(m, 0);

    oc::PRNG prng(toBlock(2000));

    {
        const auto t0 = chrono::steady_clock::now();
        SilentOtExtReceiver extRecv;
        co_await extRecv.genBaseOts(prng, sock);
        const auto t1 = chrono::steady_clock::now();
        timings.phase1.base_ot_setup = elapsed_seconds(t0, t1);

        BitVector choices(numOTs);
        choices.randomize(prng);
        vector<oc::block> otMsgs(numOTs);
        const auto t2 = chrono::steady_clock::now();
        co_await extRecv.receive(choices, otMsgs, prng, sock);
        const auto t3 = chrono::steady_clock::now();
        timings.phase1.random_ot = elapsed_seconds(t2, t3);

        BitVector eCorr(numOTs);
        const auto t4 = chrono::steady_clock::now();
        for (size_t i = 0; i < m; i++)
            for (size_t j = 0; j < 64; j++)
                eCorr[i * 64 + j] = ((b[i] >> j) & 1) ^ choices[i * 64 + j];
        const auto t5 = chrono::steady_clock::now();
        timings.phase1.correction_build = elapsed_seconds(t4, t5);

        BitVector dCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(eCorr)),
            sock.recv(dCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase1.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
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
        const auto t9 = chrono::steady_clock::now();
        timings.phase1.share_assembly = elapsed_seconds(t8, t9);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        SilentOtExtSender extSender;
        co_await extSender.genBaseOts(prng, sock);
        const auto t1 = chrono::steady_clock::now();
        timings.phase2.base_ot_setup = elapsed_seconds(t0, t1);

        vector<array<oc::block, 2>> otMsgs(numOTs);
        const auto t2 = chrono::steady_clock::now();
        co_await extSender.send(otMsgs, prng, sock);
        const auto t3 = chrono::steady_clock::now();
        timings.phase2.random_ot = elapsed_seconds(t2, t3);

        BitVector dCorr(numOTs);
        const auto t4 = chrono::steady_clock::now();
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
        const auto t5 = chrono::steady_clock::now();
        timings.phase2.correction_build = elapsed_seconds(t4, t5);

        BitVector eCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(dCorr)),
            sock.recv(eCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase2.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
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
        const auto t9 = chrono::steady_clock::now();
        timings.phase2.share_assembly = elapsed_seconds(t8, t9);
    }

    const auto t0 = chrono::steady_clock::now();
    for (size_t i = 0; i < m; i++) c[i] ^= (a[i] & b[i]);
    const auto t1 = chrono::steady_clock::now();
    timings.local_term = elapsed_seconds(t0, t1);
    timings.total = elapsed_seconds(totalStart, chrono::steady_clock::now());
}

// ============================================================
//  Merged-phase SilentOT Beaver triple (profiling-only)
// ============================================================
//
//  Instead of 4 separate SilentOT instances (2 per party),
//  each party does ONE sender call + ONE receiver call for
//  2*numOTs OTs total. The two calls run concurrently via
//  when_all_ready. Then the OT outputs are split locally:
//  first numOTs -> phase1, second numOTs -> phase2.
//
//  This halves the number of genBaseOts + PPRF expand + compress
//  passes from 4 to 2 (per party).
//

macoro::task<void> beaver_triple_sender_profiled_merged(
    coproto::Socket sock,
    const vector<uint64_t>& a, const vector<uint64_t>& b,
    vector<uint64_t>& c,
    BeaverTimings& timings)
{
    const auto totalStart = chrono::steady_clock::now();
    size_t m = a.size();
    size_t numOTs = m * 64;
    size_t totalOTs = 2 * numOTs;
    c.assign(m, 0);

    oc::PRNG prng(toBlock(1000));

    // ---- Step 1: generate all OTs concurrently ----
    // P0 as sender: 2*numOTs pairs (t0, t1)
    // P0 as receiver: 2*numOTs choices + messages
    vector<array<oc::block, 2>> sendOtMsgs(totalOTs);
    BitVector recvChoices(totalOTs);
    recvChoices.randomize(prng);
    vector<oc::block> recvOtMsgs(totalOTs);

    SilentOtExtSender extSender;
    SilentOtExtReceiver extRecv;

    const auto t_base0 = chrono::steady_clock::now();
    {
        auto sock2 = sock.fork();
        auto prng2 = prng.fork();
        co_await macoro::when_all_ready(
            extSender.genBaseOts(prng, sock),
            extRecv.genBaseOts(prng2, sock2)
        );
    }
    const auto t_base1 = chrono::steady_clock::now();
    timings.phase1.base_ot_setup = elapsed_seconds(t_base0, t_base1);

    const auto t_ot0 = chrono::steady_clock::now();
    {
        auto sock2 = sock.fork();
        auto prng2 = prng.fork();
        co_await macoro::when_all_ready(
            extSender.send(sendOtMsgs, prng, sock),
            extRecv.receive(recvChoices, recvOtMsgs, prng2, sock2)
        );
    }
    const auto t_ot1 = chrono::steady_clock::now();
    timings.phase1.random_ot = elapsed_seconds(t_ot0, t_ot1);

    // ---- Step 2: use first numOTs as phase1 (P0=sender), ----
    //              second numOTs as phase2 (P0=receiver)

    // Phase 1: cross term (a_sender & b_receiver), P0 = OT sender
    {
        const auto t4 = chrono::steady_clock::now();
        BitVector dCorr(numOTs);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low, t1_low;
                memcpy(&t0_low, &sendOtMsgs[k][0], sizeof(uint64_t));
                memcpy(&t1_low, &sendOtMsgs[k][1], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                dCorr[k] = x_bit ^ ((t0_low ^ t1_low) & 1);
            }
        }
        const auto t5 = chrono::steady_clock::now();
        timings.phase1.correction_build = elapsed_seconds(t4, t5);

        BitVector eCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(dCorr)),
            sock.recv(eCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase1.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low;
                memcpy(&t0_low, &sendOtMsgs[k][0], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                uint64_t s = (t0_low & 1) ^ (x_bit & (uint64_t)eCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
        const auto t9 = chrono::steady_clock::now();
        timings.phase1.share_assembly = elapsed_seconds(t8, t9);
    }

    // Phase 2: cross term (a_receiver & b_sender), P0 = OT receiver
    // Use recvOtMsgs[numOTs .. 2*numOTs-1] and recvChoices[numOTs .. 2*numOTs-1]
    {
        const auto t4 = chrono::steady_clock::now();
        BitVector eCorr(numOTs);
        for (size_t i = 0; i < m; i++)
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                eCorr[k] = ((b[i] >> j) & 1) ^ recvChoices[numOTs + k];
            }
        const auto t5 = chrono::steady_clock::now();
        timings.phase2.correction_build = elapsed_seconds(t4, t5);

        BitVector dCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(eCorr)),
            sock.recv(dCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase2.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t tc_low;
                memcpy(&tc_low, &recvOtMsgs[numOTs + k], sizeof(uint64_t));
                uint64_t s = (tc_low & 1) ^ ((uint64_t)recvChoices[numOTs + k] & (uint64_t)dCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
        const auto t9 = chrono::steady_clock::now();
        timings.phase2.share_assembly = elapsed_seconds(t8, t9);
    }

    const auto t0 = chrono::steady_clock::now();
    for (size_t i = 0; i < m; i++) c[i] ^= (a[i] & b[i]);
    const auto t1 = chrono::steady_clock::now();
    timings.local_term = elapsed_seconds(t0, t1);
    timings.phase2.base_ot_setup = 0.0;
    timings.phase2.random_ot = 0.0;
    timings.total = elapsed_seconds(totalStart, chrono::steady_clock::now());
}

macoro::task<void> beaver_triple_receiver_profiled_merged(
    coproto::Socket sock,
    const vector<uint64_t>& a, const vector<uint64_t>& b,
    vector<uint64_t>& c,
    BeaverTimings& timings)
{
    const auto totalStart = chrono::steady_clock::now();
    size_t m = a.size();
    size_t numOTs = m * 64;
    size_t totalOTs = 2 * numOTs;
    c.assign(m, 0);

    oc::PRNG prng(toBlock(2000));

    // P1 as receiver: 2*numOTs choices + messages
    // P1 as sender: 2*numOTs pairs
    BitVector recvChoices(totalOTs);
    recvChoices.randomize(prng);
    vector<oc::block> recvOtMsgs(totalOTs);
    vector<array<oc::block, 2>> sendOtMsgs(totalOTs);

    SilentOtExtReceiver extRecv;
    SilentOtExtSender extSender;

    const auto t_base0 = chrono::steady_clock::now();
    {
        auto sock2 = sock.fork();
        auto prng2 = prng.fork();
        co_await macoro::when_all_ready(
            extRecv.genBaseOts(prng, sock),
            extSender.genBaseOts(prng2, sock2)
        );
    }
    const auto t_base1 = chrono::steady_clock::now();
    timings.phase1.base_ot_setup = elapsed_seconds(t_base0, t_base1);

    const auto t_ot0 = chrono::steady_clock::now();
    {
        auto sock2 = sock.fork();
        auto prng2 = prng.fork();
        co_await macoro::when_all_ready(
            extRecv.receive(recvChoices, recvOtMsgs, prng, sock),
            extSender.send(sendOtMsgs, prng2, sock2)
        );
    }
    const auto t_ot1 = chrono::steady_clock::now();
    timings.phase1.random_ot = elapsed_seconds(t_ot0, t_ot1);

    // Phase 1: cross term (a_sender & b_receiver), P1 = OT receiver
    // Use recvOtMsgs[0..numOTs-1]
    {
        const auto t4 = chrono::steady_clock::now();
        BitVector eCorr(numOTs);
        for (size_t i = 0; i < m; i++)
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                eCorr[k] = ((b[i] >> j) & 1) ^ recvChoices[k];
            }
        const auto t5 = chrono::steady_clock::now();
        timings.phase1.correction_build = elapsed_seconds(t4, t5);

        BitVector dCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(eCorr)),
            sock.recv(dCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase1.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t tc_low;
                memcpy(&tc_low, &recvOtMsgs[k], sizeof(uint64_t));
                uint64_t s = (tc_low & 1) ^ ((uint64_t)recvChoices[k] & (uint64_t)dCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
        const auto t9 = chrono::steady_clock::now();
        timings.phase1.share_assembly = elapsed_seconds(t8, t9);
    }

    // Phase 2: cross term (a_receiver & b_sender), P1 = OT sender
    // Use sendOtMsgs[numOTs .. 2*numOTs-1]
    {
        const auto t4 = chrono::steady_clock::now();
        BitVector dCorr(numOTs);
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low, t1_low;
                memcpy(&t0_low, &sendOtMsgs[numOTs + k][0], sizeof(uint64_t));
                memcpy(&t1_low, &sendOtMsgs[numOTs + k][1], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                dCorr[k] = x_bit ^ ((t0_low ^ t1_low) & 1);
            }
        }
        const auto t5 = chrono::steady_clock::now();
        timings.phase2.correction_build = elapsed_seconds(t4, t5);

        BitVector eCorr(numOTs);
        const auto t6 = chrono::steady_clock::now();
        co_await macoro::when_all_ready(
            sock.send(std::move(dCorr)),
            sock.recv(eCorr)
        );
        const auto t7 = chrono::steady_clock::now();
        timings.phase2.correction_exchange = elapsed_seconds(t6, t7);

        vector<uint64_t> shares(m, 0);
        const auto t8 = chrono::steady_clock::now();
        for (size_t i = 0; i < m; i++) {
            for (size_t j = 0; j < 64; j++) {
                size_t k = i * 64 + j;
                uint64_t t0_low;
                memcpy(&t0_low, &sendOtMsgs[numOTs + k][0], sizeof(uint64_t));
                uint64_t x_bit = (a[i] >> j) & 1;
                uint64_t s = (t0_low & 1) ^ (x_bit & (uint64_t)eCorr[k]);
                shares[i] |= (s << j);
            }
        }
        for (size_t i = 0; i < m; i++) c[i] ^= shares[i];
        const auto t9 = chrono::steady_clock::now();
        timings.phase2.share_assembly = elapsed_seconds(t8, t9);
    }

    const auto t0 = chrono::steady_clock::now();
    for (size_t i = 0; i < m; i++) c[i] ^= (a[i] & b[i]);
    const auto t1 = chrono::steady_clock::now();
    timings.local_term = elapsed_seconds(t0, t1);
    timings.phase2.base_ot_setup = 0.0;
    timings.phase2.random_ot = 0.0;
    timings.total = elapsed_seconds(totalStart, chrono::steady_clock::now());
}

void runReceiverProfile(int n,
                        const string& mode,
                        std::barrier<>& phaseBarrier,
                        StageTimings& timings,
                        std::size_t& receiverOffSent,
                        std::size_t& receiverOffRecv,
                        std::size_t& receiverTotalSent,
                        std::size_t& receiverTotalRecv,
                        std::size_t& intersectionSize,
                        bool& intersectionOk) {
    coproto::AsioSocket sock = coproto::asioConnect("127.0.0.1:12345", false);
    Receiver receiver;

    const auto offlineStart = chrono::steady_clock::now();

    {
        const auto t0 = chrono::steady_clock::now();
        vector<oc::block> recvK(n);
        key_init(recvK, true);
        receiver.keys = std::move(recvK);
        const auto t1 = chrono::steady_clock::now();
        timings.key_setup = elapsed_seconds(t0, t1);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        receiver.hashed_keys = sm3_hash_keys(receiver.keys);
        receiver.filter.populate(receiver.hashed_keys, kFilterSeed);
        receiver.m = receiver.filter.array_length();
        const auto t1 = chrono::steady_clock::now();
        timings.hash_and_filter = elapsed_seconds(t0, t1);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        oc::PRNG gen1(toBlock(888));
        receiver.a_share.resize(receiver.m);
        receiver.b_share.resize(receiver.m);
        for (size_t i = 0; i < receiver.m; i++) {
            receiver.a_share[i] = gen1.get<uint64_t>();
            receiver.b_share[i] = gen1.get<uint64_t>();
        }
        receiver.random_mask = gen1.get<uint64_t>();
        const auto t1 = chrono::steady_clock::now();
        timings.local_share_sampling = elapsed_seconds(t0, t1);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        if (mode == "vole") {
            macoro::sync_wait(beaver_triple_receiver_profiled_vole(sock, receiver.a_share, receiver.b_share, receiver.c_share, timings.beaver_details));
        } else if (mode == "merged") {
            macoro::sync_wait(beaver_triple_receiver_profiled_merged(sock, receiver.a_share, receiver.b_share, receiver.c_share, timings.beaver_details));
        } else {
            macoro::sync_wait(beaver_triple_receiver_profiled_ot(sock, receiver.a_share, receiver.b_share, receiver.c_share, timings.beaver_details));
        }
        const auto t1 = chrono::steady_clock::now();
        timings.beaver_triple = elapsed_seconds(t0, t1);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        const uint64_t* ty = receiver.filter.data();
        receiver.open_local.resize(2 * receiver.m);
        for (size_t i = 0; i < receiver.m; ++i) {
            receiver.open_local[i] = ty[i] ^ receiver.a_share[i];
            receiver.open_local[receiver.m + i] = receiver.random_mask ^ receiver.b_share[i];
        }
        const auto t1 = chrono::steady_clock::now();
        timings.open_local_prep = elapsed_seconds(t0, t1);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        CuckooIndex<ThreadSafe> location_helper;
        location_helper.init(make_cuckoo_param(receiver.keys.size()));
        location_helper.insert(osuCrypto::span<oc::block>(receiver.keys.data(), receiver.keys.size()), kCuckooHashSeed);

        const size_t num_bins = location_helper.mBins.size();
        receiver.simple_item_indices.assign(num_bins, {});
        for (size_t item_idx = 0; item_idx < receiver.keys.size(); ++item_idx) {
            for (u64 hash_idx = 0; hash_idx < kCuckooNumHashes; ++hash_idx) {
                const auto bin_idx = static_cast<size_t>(location_helper.mLocations(item_idx, hash_idx));
                receiver.simple_item_indices[bin_idx].push_back(item_idx);
            }
        }

        receiver.flat_bin_offsets.resize(num_bins + 1);
        receiver.flat_bin_offsets[0] = 0;
        for (size_t i = 0; i < num_bins; ++i) {
            receiver.flat_bin_offsets[i + 1] = receiver.flat_bin_offsets[i] + receiver.simple_item_indices[i].size();
        }
        receiver.flat_total_entries = receiver.flat_bin_offsets[num_bins];
        receiver.flat_values.resize(receiver.flat_total_entries);
        receiver.flat_hashes.resize(receiver.flat_total_entries);
        receiver.mult_share.resize(receiver.m);
        receiver.associated_values.resize(receiver.keys.size());
        receiver.sender_payload_hashes.resize(num_bins);
        const auto t1 = chrono::steady_clock::now();
        timings.table_prep = elapsed_seconds(t0, t1);
    }

    timings.offline_total = elapsed_seconds(offlineStart, chrono::steady_clock::now());

    macoro::sync_wait(sock.flush());
    phaseBarrier.arrive_and_wait();
    receiverOffSent = sock.bytesSent();
    receiverOffRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    const auto onlineStart = chrono::steady_clock::now();
    receiver.output(sock);
    macoro::sync_wait(sock.flush());
    timings.online_total = elapsed_seconds(onlineStart, chrono::steady_clock::now());

    phaseBarrier.arrive_and_wait();
    receiverTotalSent = sock.bytesSent();
    receiverTotalRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    intersectionSize = receiver.intersection.size();
    receiver.receiver_sender_psi.clear();
    for (size_t idx = 0; idx < receiver.keys.size(); ++idx) {
        if (find(receiver.intersection.begin(), receiver.intersection.end(), receiver.keys[idx]) != receiver.intersection.end()) {
            receiver.receiver_sender_psi[idx] = receiver.keys[idx];
        }
    }

    intersectionOk = (intersectionSize == static_cast<size_t>(Number));
    if (intersectionOk) {
        for (int expected = 0; expected < Number; ++expected) {
            if (!receiver.receiver_sender_psi.count(static_cast<size_t>(expected))) {
                intersectionOk = false;
                break;
            }
        }
    }

    macoro::sync_wait(sock.close());
}

void runSenderProfile(int n,
                      const string& mode,
                      std::barrier<>& phaseBarrier,
                      StageTimings& timings,
                      std::size_t& senderOffSent,
                      std::size_t& senderOffRecv,
                      std::size_t& senderTotalSent,
                      std::size_t& senderTotalRecv) {
    coproto::AsioSocket sock = coproto::asioConnect("127.0.0.1:12345", true);
    Sender sender;

    const auto offlineStart = chrono::steady_clock::now();

    {
        const auto t0 = chrono::steady_clock::now();
        vector<oc::block> sendK(n);
        key_init(sendK, false);
        sender.keys = std::move(sendK);
        const auto t1 = chrono::steady_clock::now();
        timings.key_setup = elapsed_seconds(t0, t1);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        sender.hashed_keys = sm3_hash_keys(sender.keys);
        sender.filter.populate(sender.hashed_keys, kFilterSeed);
        sender.m = sender.filter.array_length();
        const auto t1 = chrono::steady_clock::now();
        timings.hash_and_filter = elapsed_seconds(t0, t1);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        oc::PRNG gen0(toBlock(666));
        sender.a_share.resize(sender.m);
        sender.b_share.resize(sender.m);
        for (size_t i = 0; i < sender.m; i++) {
            sender.a_share[i] = gen0.get<uint64_t>();
            sender.b_share[i] = gen0.get<uint64_t>();
        }
        sender.random_mask = gen0.get<uint64_t>();
        const auto t1 = chrono::steady_clock::now();
        timings.local_share_sampling = elapsed_seconds(t0, t1);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        if (mode == "vole") {
            macoro::sync_wait(beaver_triple_sender_profiled_vole(sock, sender.a_share, sender.b_share, sender.c_share, timings.beaver_details));
        } else if (mode == "merged") {
            macoro::sync_wait(beaver_triple_sender_profiled_merged(sock, sender.a_share, sender.b_share, sender.c_share, timings.beaver_details));
        } else {
            macoro::sync_wait(beaver_triple_sender_profiled_ot(sock, sender.a_share, sender.b_share, sender.c_share, timings.beaver_details));
        }
        const auto t1 = chrono::steady_clock::now();
        timings.beaver_triple = elapsed_seconds(t0, t1);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        const uint64_t* tx = sender.filter.data();
        sender.open_local.resize(2 * sender.m);
        for (size_t i = 0; i < sender.m; ++i) {
            sender.open_local[i] = tx[i] ^ sender.a_share[i];
            sender.open_local[sender.m + i] = sender.random_mask ^ sender.b_share[i];
        }
        const auto t1 = chrono::steady_clock::now();
        timings.open_local_prep = elapsed_seconds(t0, t1);
    }

    {
        const auto t0 = chrono::steady_clock::now();
        sender.cuckoo.init(make_cuckoo_param(sender.keys.size()));
        sender.cuckoo.insert(osuCrypto::span<oc::block>(sender.keys.data(), sender.keys.size()), kCuckooHashSeed);

        oc::PRNG prng_dummy(toBlock(321));
        sender.cuckoo_table.resize(sender.cuckoo.mBins.size());
        for (size_t i = 0; i < sender.cuckoo.mBins.size(); ++i) {
            sender.cuckoo_table[i] = prng_dummy.get<uint64_t>();
        }
        sender.cuckoo_table_hashes.resize(sender.cuckoo.mBins.size());
        sender.mult_share.resize(sender.m);
        sender.associated_values.resize(sender.keys.size());
        const auto t1 = chrono::steady_clock::now();
        timings.table_prep = elapsed_seconds(t0, t1);
    }

    timings.offline_total = elapsed_seconds(offlineStart, chrono::steady_clock::now());

    macoro::sync_wait(sock.flush());
    phaseBarrier.arrive_and_wait();
    senderOffSent = sock.bytesSent();
    senderOffRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    const auto onlineStart = chrono::steady_clock::now();
    sender.output(sock);
    macoro::sync_wait(sock.flush());
    timings.online_total = elapsed_seconds(onlineStart, chrono::steady_clock::now());

    phaseBarrier.arrive_and_wait();
    senderTotalSent = sock.bytesSent();
    senderTotalRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    macoro::sync_wait(sock.close());
}

static void print_beaver_phase_lines(const string& prefix, const string& phase, const BeaverPhaseTimings& t) {
    cout << prefix << "_" << phase << "_BASE_OT_SETUP=" << t.base_ot_setup << endl;
    cout << prefix << "_" << phase << "_RANDOM_OT=" << t.random_ot << endl;
    cout << prefix << "_" << phase << "_CORRECTION_BUILD=" << t.correction_build << endl;
    cout << prefix << "_" << phase << "_CORRECTION_EXCHANGE=" << t.correction_exchange << endl;
    cout << prefix << "_" << phase << "_SHARE_ASSEMBLY=" << t.share_assembly << endl;
}

static void print_stage_lines(const string& prefix, const StageTimings& t) {
    cout << prefix << "_KEY_SETUP=" << t.key_setup << endl;
    cout << prefix << "_HASH_AND_FILTER=" << t.hash_and_filter << endl;
    cout << prefix << "_LOCAL_SHARE_SAMPLING=" << t.local_share_sampling << endl;
    cout << prefix << "_BEAVER_TRIPLE=" << t.beaver_triple << endl;
    print_beaver_phase_lines(prefix, "PHASE1", t.beaver_details.phase1);
    print_beaver_phase_lines(prefix, "PHASE2", t.beaver_details.phase2);
    cout << prefix << "_BEAVER_LOCAL_TERM=" << t.beaver_details.local_term << endl;
    cout << prefix << "_BEAVER_TOTAL_INNER=" << t.beaver_details.total << endl;
    cout << prefix << "_OPEN_LOCAL_PREP=" << t.open_local_prep << endl;
    cout << prefix << "_TABLE_PREP=" << t.table_prep << endl;
    cout << prefix << "_OFFLINE_TOTAL=" << t.offline_total << endl;
    cout << prefix << "_ONLINE_TOTAL=" << t.online_total << endl;
}

int main(int argc, char** argv) {
    int n = 1 << 20;
    string mode = "vole";

    if (argc >= 2) n = stoi(argv[1]);
    if (argc >= 3) mode = argv[2];

    bool useVole = false;
    if (mode == "ot") {
        useVole = false;
    } else if (mode == "vole") {
        useVole = true;
    } else if (mode == "merged") {
        useVole = true; // merged is a VOLE variant
    } else {
        cerr << "Usage: ./build/PSI_profile [n] [ot|vole|merged]" << endl;
        return 1;
    }

    StageTimings senderTimings, receiverTimings;
    std::size_t senderOffSent = 0, senderOffRecv = 0, senderTotalSent = 0, senderTotalRecv = 0;
    std::size_t receiverOffSent = 0, receiverOffRecv = 0, receiverTotalSent = 0, receiverTotalRecv = 0;
    std::size_t intersectionSize = 0;
    bool intersectionOk = false;
    std::barrier phaseBarrier(2);

    thread receiverThread(runReceiverProfile, n, mode,
                          std::ref(phaseBarrier),
                          std::ref(receiverTimings),
                          std::ref(receiverOffSent), std::ref(receiverOffRecv),
                          std::ref(receiverTotalSent), std::ref(receiverTotalRecv),
                          std::ref(intersectionSize), std::ref(intersectionOk));
    thread senderThread(runSenderProfile, n, mode,
                        std::ref(phaseBarrier),
                        std::ref(senderTimings),
                        std::ref(senderOffSent), std::ref(senderOffRecv),
                        std::ref(senderTotalSent), std::ref(senderTotalRecv));

    receiverThread.join();
    senderThread.join();

    const double senderOnlineSend = static_cast<double>(senderTotalSent - senderOffSent);
    const double receiverOnlineSend = static_cast<double>(receiverTotalSent - receiverOffSent);
    const double offlineData = static_cast<double>(senderOffSent + receiverOffSent);
    const double onlineData = senderOnlineSend + receiverOnlineSend;

    cout << "MODE=" << mode << endl;
    cout << "N=" << n << endl;
    cout << "INTERSECTION_SIZE=" << intersectionSize << endl;
    cout << "INTERSECTION_OK=" << (intersectionOk ? 1 : 0) << endl;
    print_stage_lines("SENDER", senderTimings);
    print_stage_lines("RECEIVER", receiverTimings);
    cout << "PROTOCOL_OFFLINE_MB=" << offlineData / 1024.0 / 1024.0 << endl;
    cout << "PROTOCOL_ONLINE_MB=" << onlineData / 1024.0 / 1024.0 << endl;
    cout << "SENDER_ONLINE_MB=" << senderOnlineSend / 1024.0 / 1024.0 << endl;
    cout << "RECEIVER_ONLINE_MB=" << receiverOnlineSend / 1024.0 / 1024.0 << endl;
    cout << "PROTOCOL_OFFLINE_WALL_ESTIMATE=" << max(senderTimings.offline_total, receiverTimings.offline_total) << endl;
    cout << "PROTOCOL_ONLINE_WALL_ESTIMATE=" << max(senderTimings.online_total, receiverTimings.online_total) << endl;

    return 0;
}
