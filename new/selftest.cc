#include <cstdint>
#include <iostream>
#include <thread>
#include <vector>

#include "psi.h"

using namespace std;
using namespace osuCrypto;

void test_binfuse_filter64() {
    cout << "=== binfuse filter64 test ===" << endl;

    vector<uint64_t> data = {
        0x0000000000000001,
        0x0000000000000002,
        0x0000000000000003,
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
    };

    binfuse::filter64 f(data);

    bool all_ok = true;
    for (auto v : data) {
        if (!f.contains(v)) {
            cout << "  FAIL: false negative for 0x" << hex << v << dec << endl;
            all_ok = false;
        }
    }

    uint64_t absent = 0xAAAABBBBCCCCDDDD;
    bool fp = f.contains(absent);

    if (all_ok) {
        cout << "  All " << data.size() << " elements found (no false negatives)." << endl;
    }
    cout << "  contains(0xAAAABBBBCCCCDDDD) = " << fp
         << " (expected false, fp rate ~1/2^64)" << endl;
    cout << "  filter size: " << f.size() << " elements, "
         << f.serialization_bytes() << " bytes serialized" << endl;
    cout << "=== binfuse filter64 test done ===" << endl;
}

void test_channel() {
    cout << "=== cryptoTools channel test ===" << endl;

    IOService ios;
    bool ok = false;

    auto server_fn = [&]() {
        Session session(ios, "127.0.0.1", 23456, EpMode::Server);
        Channel ch = session.addChannel();
        vector<uint8_t> buf;
        ch.recv(buf);
        ch.send(buf);
        ch.close();
    };

    auto client_fn = [&]() {
        Session session(ios, "127.0.0.1", 23456, EpMode::Client);
        Channel ch = session.addChannel();
        vector<uint8_t> msg = {0xDE, 0xAD, 0xBE, 0xEF};
        ch.send(msg);
        vector<uint8_t> reply;
        ch.recv(reply);
        ok = (reply == msg);
        ch.close();
    };

    thread srv(server_fn);
    thread cli(client_fn);
    srv.join();
    cli.join();
    ios.stop();

    cout << "  echo round-trip: " << (ok ? "PASS" : "FAIL") << endl;
    cout << "=== cryptoTools channel test done ===" << endl;
}

void test_beaver_triple() {
    cout << "=== Beaver Triple (IKNP OT) test ===" << endl;

    const size_t m = 1 << 10;

    oc::PRNG gen0(toBlock(42));
    vector<uint64_t> a1(m), b1(m);
    for (size_t i = 0; i < m; i++) {
        a1[i] = gen0.get<uint64_t>();
        b1[i] = gen0.get<uint64_t>();
    }

    oc::PRNG gen1(toBlock(99));
    vector<uint64_t> a2(m), b2(m);
    for (size_t i = 0; i < m; i++) {
        a2[i] = gen1.get<uint64_t>();
        b2[i] = gen1.get<uint64_t>();
    }

    vector<uint64_t> c1, c2;
    auto socks = coproto::LocalAsyncSocket::makePair();

    cout << "  Sender and Receiver communicating via OT..." << endl;
    macoro::sync_wait(macoro::when_all_ready(
        beaver_triple_sender(std::move(socks[0]), a1, b1, c1),
        beaver_triple_receiver(std::move(socks[1]), a2, b2, c2)
    ));

    bool pass = true;
    for (size_t i = 0; i < m; i++) {
        uint64_t expected = (a1[i] ^ a2[i]) & (b1[i] ^ b2[i]);
        uint64_t actual   = c1[i] ^ c2[i];
        if (actual != expected) {
            cout << "  FAIL at triple " << i << ": expected 0x" << hex << expected
                 << ", got 0x" << actual << dec << endl;
            pass = false;
        }
    }

    cout << "  " << m << " Beaver triples verified: " << (pass ? "ALL PASS" : "FAILED") << endl;
    cout << "=== Beaver Triple test done ===" << endl;
}

void test_beaver_triple_vole() {
    cout << "=== Beaver Triple (SilentOT / VOLE) test ===" << endl;

    const size_t m = 1 << 10;

    oc::PRNG gen0(toBlock(42));
    vector<uint64_t> a1(m), b1(m);
    for (size_t i = 0; i < m; i++) {
        a1[i] = gen0.get<uint64_t>();
        b1[i] = gen0.get<uint64_t>();
    }

    oc::PRNG gen1(toBlock(99));
    vector<uint64_t> a2(m), b2(m);
    for (size_t i = 0; i < m; i++) {
        a2[i] = gen1.get<uint64_t>();
        b2[i] = gen1.get<uint64_t>();
    }

    vector<uint64_t> c1, c2;
    auto socks = coproto::LocalAsyncSocket::makePair();

    cout << "  Sender and Receiver communicating via SilentOT..." << endl;
    macoro::sync_wait(macoro::when_all_ready(
        beaver_triple_sender_vole(std::move(socks[0]), a1, b1, c1),
        beaver_triple_receiver_vole(std::move(socks[1]), a2, b2, c2)
    ));

    bool pass = true;
    for (size_t i = 0; i < m; i++) {
        uint64_t expected = (a1[i] ^ a2[i]) & (b1[i] ^ b2[i]);
        uint64_t actual   = c1[i] ^ c2[i];
        if (actual != expected) {
            cout << "  FAIL at triple " << i << ": expected 0x" << hex << expected
                 << ", got 0x" << actual << dec << endl;
            pass = false;
        }
    }

    cout << "  " << m << " Beaver triples verified: " << (pass ? "ALL PASS" : "FAILED") << endl;
    cout << "=== Beaver Triple (SilentOT / VOLE) test done ===" << endl;
}

int main() {
    test_binfuse_filter64();
    cout << endl;

    test_channel();
    cout << endl;

    test_beaver_triple();
    cout << endl;

    test_beaver_triple_vole();
    return 0;
}
