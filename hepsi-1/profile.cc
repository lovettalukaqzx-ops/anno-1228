#include <chrono>
#include <iostream>
#include <iomanip>
#include <barrier>
#include <thread>
#include <vector>
#include <string>

#include "psi.h"

using namespace std;
using namespace osuCrypto;

static double elapsed_ms(const chrono::steady_clock::time_point& start,
                         const chrono::steady_clock::time_point& end) {
    return chrono::duration<double, milli>(end - start).count();
}

struct PhaseTimings {
    double init_ms        = 0.0;
    double output_ms      = 0.0;
    double total_ms       = 0.0;
    size_t off_sent       = 0;
    size_t off_recv       = 0;
    size_t total_sent     = 0;
    size_t total_recv     = 0;
};

void profileReceiver(int n_recv, int n_send, int port,
                     std::barrier<>& barrier,
                     PhaseTimings& timings,
                     size_t& intersectionSize,
                     bool& intersectionOk) {
    coproto::AsioSocket sock = coproto::asioConnect("127.0.0.1:" + to_string(port), false);
    Receiver receiver;
    vector<oc::block> recvK(n_recv);
    key_init(recvK, true);

    auto t0 = chrono::steady_clock::now();
    receiver.init(sock, recvK);
    macoro::sync_wait(sock.flush());

    barrier.arrive_and_wait();
    timings.off_sent = sock.bytesSent();
    timings.off_recv = sock.bytesReceived();
    barrier.arrive_and_wait();

    auto t1 = chrono::steady_clock::now();
    timings.init_ms = elapsed_ms(t0, t1);

    receiver.output(sock);
    macoro::sync_wait(sock.flush());

    barrier.arrive_and_wait();
    timings.total_sent = sock.bytesSent();
    timings.total_recv = sock.bytesReceived();
    barrier.arrive_and_wait();

    auto t2 = chrono::steady_clock::now();
    timings.output_ms = elapsed_ms(t1, t2);
    timings.total_ms  = elapsed_ms(t0, t2);

    intersectionSize = receiver.intersection.size();
    receiver.receiver_sender_psi.clear();
    for (size_t idx = 0; idx < receiver.keys.size(); ++idx) {
        if (find(receiver.intersection.begin(), receiver.intersection.end(), receiver.keys[idx])
            != receiver.intersection.end()) {
            receiver.receiver_sender_psi[idx] = receiver.keys[idx];
        }
    }
    const int expectedIntersection = expected_intersection_count(static_cast<size_t>(n_send));
    intersectionOk = (intersectionSize == static_cast<size_t>(expectedIntersection));
    if (intersectionOk) {
        for (int expected = 0; expected < expectedIntersection; ++expected) {
            if (!receiver.receiver_sender_psi.count(static_cast<size_t>(expected))) {
                intersectionOk = false;
                break;
            }
        }
    }

    macoro::sync_wait(sock.close());
}

void profileSender(int n_send, int port,
                   std::barrier<>& barrier,
                   PhaseTimings& timings) {
    coproto::AsioSocket sock = coproto::asioConnect("127.0.0.1:" + to_string(port), true);
    Sender sender;
    vector<oc::block> sendK(n_send);
    key_init(sendK, false);

    auto t0 = chrono::steady_clock::now();
    sender.init(sock, sendK);
    macoro::sync_wait(sock.flush());

    barrier.arrive_and_wait();
    timings.off_sent = sock.bytesSent();
    timings.off_recv = sock.bytesReceived();
    barrier.arrive_and_wait();

    auto t1 = chrono::steady_clock::now();
    timings.init_ms = elapsed_ms(t0, t1);

    sender.output(sock);
    macoro::sync_wait(sock.flush());

    barrier.arrive_and_wait();
    timings.total_sent = sock.bytesSent();
    timings.total_recv = sock.bytesReceived();
    barrier.arrive_and_wait();

    auto t2 = chrono::steady_clock::now();
    timings.output_ms = elapsed_ms(t1, t2);
    timings.total_ms  = elapsed_ms(t0, t2);

    macoro::sync_wait(sock.close());
}

int main(int argc, char** argv) {
    // Usage: ./PSI_profile [n_recv_log2] [n_send_log2] [targetBlockSize] [port]
    int recvLog = 10;
    int sendLog = -1;
    int port = 12399;

    if (argc >= 2) recvLog = stoi(argv[1]);
    if (argc >= 3) sendLog = stoi(argv[2]);
    if (argc >= 4) gTargetBlockSize = static_cast<size_t>(stoull(argv[3]));
    if (argc >= 5) port = stoi(argv[4]);
    if (sendLog < 0) sendLog = recvLog;
    validate_block_size_or_throw();

    int n_recv = 1 << recvLog;
    int n_send = 1 << sendLog;

    PhaseTimings sender_t, receiver_t;
    size_t intersectionSize = 0;
    bool intersectionOk = false;
    std::barrier phaseBarrier(2);

    thread recvThread(profileReceiver, n_recv, n_send, port,
                      ref(phaseBarrier), ref(receiver_t),
                      ref(intersectionSize), ref(intersectionOk));
    thread sendThread(profileSender, n_send, port,
                      ref(phaseBarrier), ref(sender_t));

    recvThread.join();
    sendThread.join();

    double offlineData  = static_cast<double>(sender_t.off_sent + receiver_t.off_sent);
    double onlineDataS  = static_cast<double>(sender_t.total_sent - sender_t.off_sent);
    double onlineDataR  = static_cast<double>(receiver_t.total_sent - receiver_t.off_sent);
    double onlineData   = onlineDataS + onlineDataR;

    cout << fixed << setprecision(2);
    cout << "============================================================" << endl;
    cout << "  HE-PSI Profile   |  recv=2^" << recvLog << " = " << n_recv
         << "  send=2^" << sendLog << " = " << n_send
         << "  |  block=" << gTargetBlockSize
         << "  |  port " << port << endl;
    cout << "  Expected intersection: " << expected_intersection_count(static_cast<size_t>(n_send)) << endl;
    cout << "  Intersection:    " << intersectionSize
         << "  (" << (intersectionOk ? "CORRECT" : "WRONG") << ")" << endl;
    cout << "============================================================" << endl;
    cout << "                        Sender          Receiver" << endl;
    cout << "  init  (offline):  " << setw(10) << sender_t.init_ms
         << " ms    " << setw(10) << receiver_t.init_ms << " ms" << endl;
    cout << "  output (online):  " << setw(10) << sender_t.output_ms
         << " ms    " << setw(10) << receiver_t.output_ms << " ms" << endl;
    cout << "  total:            " << setw(10) << sender_t.total_ms
         << " ms    " << setw(10) << receiver_t.total_ms << " ms" << endl;
    cout << "============================================================" << endl;
    cout << "  Offline data:     " << setw(10) << offlineData / 1024.0 / 1024.0 << " MB" << endl;
    cout << "  Online  data:     " << setw(10) << onlineData / 1024.0 / 1024.0 << " MB" << endl;
    cout << "    Sender  online: " << setw(10) << onlineDataS / 1024.0 / 1024.0 << " MB" << endl;
    cout << "    Receiver online:" << setw(10) << onlineDataR / 1024.0 / 1024.0 << " MB" << endl;
    cout << "============================================================" << endl;

    return 0;
}
