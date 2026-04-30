// main.cc
// End-to-end local runner for the HE-based PSI protocol (Figure 4).
// Runs both Sender and Receiver in separate threads, connected over
// coproto::AsioSocket on localhost, and reports timing/communication.

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <barrier>
#include <map>
#include <thread>
#include <vector>
#include <string>
#include <sys/time.h>

#include "psi.h"

using namespace std;
using namespace osuCrypto;

// ============================================================
//  Receiver thread
// ============================================================

void runReceiver(int n_recv,
                 int n_send,
                 int port,
                 std::barrier<>& phaseBarrier,
                 double& offTime, double& onTime,
                 std::size_t& receiverOffSent, std::size_t& receiverOffRecv,
                 std::size_t& receiverTotalSent, std::size_t& receiverTotalRecv,
                 std::size_t& intersectionSize,
                 bool& intersectionOk) {
    // Connect as the "client" side (false = connect, not listen).
    coproto::AsioSocket sock = coproto::asioConnect("127.0.0.1:" + to_string(port), false);

    Receiver receiver;
    vector<oc::block> recvK(n_recv);
    key_init(recvK, true);

    // --- Offline stage ---
    struct timeval t0, t1, t2;
    gettimeofday(&t0, NULL);
    receiver.init(sock, recvK);
    macoro::sync_wait(sock.flush());

    // Synchronize with Sender to snapshot offline bytes.
    phaseBarrier.arrive_and_wait();
    receiverOffSent = sock.bytesSent();
    receiverOffRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    gettimeofday(&t1, NULL);
    offTime = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;

    // --- Online stage ---
    receiver.output(sock);
    macoro::sync_wait(sock.flush());

    // Synchronize with Sender to snapshot total bytes.
    phaseBarrier.arrive_and_wait();
    receiverTotalSent = sock.bytesSent();
    receiverTotalRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    gettimeofday(&t2, NULL);
    onTime = (t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec) / 1e6;

    intersectionSize = receiver.intersection.size();

    // Verify intersection correctness (same logic as hepsi-1).
    map<size_t, oc::block> receiver_sender_psi;
    for (size_t idx = 0; idx < receiver.keys.size(); ++idx) {
        if (find(receiver.intersection.begin(), receiver.intersection.end(), receiver.keys[idx])
            != receiver.intersection.end()) {
            receiver_sender_psi[idx] = receiver.keys[idx];
        }
    }

    const int expectedIntersection = expected_intersection_count(static_cast<size_t>(n_send));
    intersectionOk = (intersectionSize == static_cast<size_t>(expectedIntersection));
    if (intersectionOk) {
        for (int expected = 0; expected < expectedIntersection; ++expected) {
            if (!receiver_sender_psi.count(static_cast<size_t>(expected))) {
                intersectionOk = false;
                break;
            }
        }
    }

    macoro::sync_wait(sock.close());
}

// ============================================================
//  Sender thread
// ============================================================

void runSender(int n_send,
               int port,
               std::barrier<>& phaseBarrier,
               std::size_t& senderOffSent, std::size_t& senderOffRecv,
               std::size_t& senderTotalSent, std::size_t& senderTotalRecv) {
    // Connect as the "server" side (true = listen).
    coproto::AsioSocket sock = coproto::asioConnect("127.0.0.1:" + to_string(port), true);

    Sender sender;
    vector<oc::block> sendK(n_send);
    key_init(sendK, false);

    // --- Offline stage ---
    sender.init(sock, sendK);
    macoro::sync_wait(sock.flush());

    // Synchronize with Receiver to snapshot offline bytes.
    phaseBarrier.arrive_and_wait();
    senderOffSent = sock.bytesSent();
    senderOffRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    // --- Online stage ---
    sender.output(sock);
    macoro::sync_wait(sock.flush());

    // Synchronize with Receiver to snapshot total bytes.
    phaseBarrier.arrive_and_wait();
    senderTotalSent = sock.bytesSent();
    senderTotalRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    macoro::sync_wait(sock.close());
}

// ============================================================
//  Main entry point
//  Usage: ./PSI [n_recv_log2] [n_send_log2] [targetBlockSize|0=auto] [port]
// ============================================================

// Heuristic default block size for current secure PSI benchmarks.
static size_t default_block_size_for_recv_log(int recvLog) {
    // For receiver-large regimes with |Y| >= 2^20, empirical sweeps showed
    // 7680 gives the best online-time tradeoff for the current secure PSI.
    if (recvLog >= 20) return 7680;

    // Fallback to the long-used default outside the tuned receiver-large regime.
    return 6144;
}

int main(int argc, char** argv) {
    int recvLog = 10;
    int sendLog = -1;
    int port = 12345;
    bool hasBlockSizeOverride = false;

    if (argc >= 2) recvLog = stoi(argv[1]);
    if (argc >= 3) sendLog = stoi(argv[2]);
    if (argc >= 4) {
        size_t requestedBlockSize = static_cast<size_t>(stoull(argv[3]));
        if (requestedBlockSize != 0) {
            gTargetBlockSize = requestedBlockSize;
            hasBlockSizeOverride = true;
        }
    }
    if (argc >= 5) port = stoi(argv[4]);

    if (!hasBlockSizeOverride) {
        gTargetBlockSize = default_block_size_for_recv_log(recvLog);
    }

    if (sendLog < 0) sendLog = recvLog;
    validate_block_size_or_throw();

    int n_recv = 1 << recvLog;
    int n_send = 1 << sendLog;

    // Shared state for collecting timing / communication / correctness.
    double offTime = 0.0, onTime = 0.0;
    std::size_t senderOffSent = 0, senderOffRecv = 0, senderTotalSent = 0, senderTotalRecv = 0;
    std::size_t receiverOffSent = 0, receiverOffRecv = 0, receiverTotalSent = 0, receiverTotalRecv = 0;
    std::size_t intersectionSize = 0;
    bool intersectionOk = false;
    std::barrier phaseBarrier(2);

    // Launch both parties.
    thread receiverThread(runReceiver, n_recv, n_send, port,
                          std::ref(phaseBarrier),
                          std::ref(offTime), std::ref(onTime),
                          std::ref(receiverOffSent), std::ref(receiverOffRecv),
                          std::ref(receiverTotalSent), std::ref(receiverTotalRecv),
                          std::ref(intersectionSize), std::ref(intersectionOk));
    thread senderThread(runSender, n_send, port,
                        std::ref(phaseBarrier),
                        std::ref(senderOffSent), std::ref(senderOffRecv),
                        std::ref(senderTotalSent), std::ref(senderTotalRecv));

    receiverThread.join();
    senderThread.join();

    // Compute online-only communication.
    const double senderOnlineSend = static_cast<double>(senderTotalSent - senderOffSent);
    const double receiverOnlineSend = static_cast<double>(receiverTotalSent - receiverOffSent);
    const double offlineData = static_cast<double>(senderOffSent + receiverOffSent);
    const double onlineData = senderOnlineSend + receiverOnlineSend;

    // Print summary.
    cout << fixed << setprecision(4);
    cout << "===============================================" << endl;
    cout << "  Receiver set:              2^" << recvLog << " = " << n_recv << endl;
    cout << "  Sender   set:              2^" << sendLog << " = " << n_send << endl;
    cout << "  Target block size:         " << gTargetBlockSize << endl;
    cout << "  Expected intersection:     " << expected_intersection_count(static_cast<size_t>(n_send)) << endl;
    cout << "  Port:                      " << port << endl;
    cout << "  Intersection size:         " << intersectionSize << endl;
    cout << "  Intersection correct:      " << (intersectionOk ? "YES" : "NO") << endl;
    cout << "===============================================" << endl;
    cout << "  Receiver offline time:     " << setw(10) << offTime            << " seconds" << endl;
    cout << "  Receiver online  time:     " << setw(10) << onTime             << " seconds" << endl;
    cout << "  Protocol total   time:     " << setw(10) << (offTime + onTime) << " seconds" << endl;
    cout << "===============================================" << endl;
    cout << "  Protocol offline data:     " << setw(10) << offlineData / 1024.0 / 1024.0 << " MB" << endl;
    cout << "  Protocol online  data:     " << setw(10) << onlineData / 1024.0 / 1024.0 << " MB" << endl;
    cout << "  Sender   online  data:     " << setw(10) << senderOnlineSend / 1024.0 / 1024.0 << " MB" << endl;
    cout << "  Receiver online  data:     " << setw(10) << receiverOnlineSend / 1024.0 / 1024.0 << " MB" << endl;
    cout << "===============================================" << endl;

    return 0;
}
