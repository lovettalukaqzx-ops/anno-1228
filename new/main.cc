#include <iostream>
#include <iomanip>
#include <algorithm>
#include <barrier>
#include <thread>
#include <vector>
#include <string>
#include <sys/time.h>

#include "psi.h"

using namespace std;
using namespace osuCrypto;

// ============================================================
//  PSI Protocol Runner (coproto::Socket)
// ============================================================
//
//  Sender and Receiver communicate via coproto::AsioSocket over TCP.
//  One side calls asioConnect(addr, true)  -> acts as server (acceptor)
//  Other side calls asioConnect(addr, false) -> acts as client (connector)
//
//  Data statistics: sock.bytesSent() / sock.bytesReceived()
//  (These include protocol framing overhead, not just raw payload.)
//

void runReceiver(int n,
                 int port,
                 std::barrier<>& phaseBarrier,
                 double& offTime, double& onTime,
                 std::size_t& receiverOffSent, std::size_t& receiverOffRecv,
                 std::size_t& receiverTotalSent, std::size_t& receiverTotalRecv,
                 std::size_t& intersectionSize,
                 bool& intersectionOk) {

    coproto::AsioSocket sock = coproto::asioConnect("127.0.0.1:" + to_string(port), false);

    Receiver receiver;
    vector<oc::block> recvK(n);
    key_init(recvK, true);

    struct timeval t0, t1, t2;
    gettimeofday(&t0, NULL);

    receiver.init(sock, recvK);
    macoro::sync_wait(sock.flush());

    phaseBarrier.arrive_and_wait();
    receiverOffSent = sock.bytesSent();
    receiverOffRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    gettimeofday(&t1, NULL);
    offTime = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;

    receiver.output(sock);
    macoro::sync_wait(sock.flush());

    phaseBarrier.arrive_and_wait();
    receiverTotalSent = sock.bytesSent();
    receiverTotalRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    gettimeofday(&t2, NULL);
    onTime = (t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec) / 1e6;

    intersectionSize = receiver.intersection.size();
    receiver.receiver_sender_psi.clear();
    for (size_t idx = 0; idx < receiver.keys.size(); ++idx) {
        if (find(receiver.intersection.begin(), receiver.intersection.end(), receiver.keys[idx])
            != receiver.intersection.end()) {
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

void runSender(int n,
               int port,
               std::barrier<>& phaseBarrier,
               std::size_t& senderOffSent, std::size_t& senderOffRecv,
               std::size_t& senderTotalSent, std::size_t& senderTotalRecv) {

    coproto::AsioSocket sock = coproto::asioConnect("127.0.0.1:" + to_string(port), true);

    Sender sender;
    vector<oc::block> sendK(n);
    key_init(sendK, false);

    sender.init(sock, sendK);
    macoro::sync_wait(sock.flush());

    phaseBarrier.arrive_and_wait();
    senderOffSent = sock.bytesSent();
    senderOffRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    sender.output(sock);
    macoro::sync_wait(sock.flush());

    phaseBarrier.arrive_and_wait();
    senderTotalSent = sock.bytesSent();
    senderTotalRecv = sock.bytesReceived();
    phaseBarrier.arrive_and_wait();

    macoro::sync_wait(sock.close());
}

int main(int argc, char** argv) {
    int setSize = 16;
    string mode = "vole";
    int port = 12345;

    if (argc >= 2) setSize = stoi(argv[1]);
    if (argc >= 3) mode = argv[2];
    if (argc >= 4) port = stoi(argv[3]);

    int n = 1 << setSize;

    if (mode == "ot") {
        use_vole = false;
    } else if (mode == "vole") {
        use_vole = true;
    } else {
        cerr << "Usage: ./build/PSI [n](i.e., 2^n) [ot|vole] [port]" << endl;
        return 1;
    }

    // Time variables to be collected and traffic snapshots from both parties
    double offTime = 0.0, onTime = 0.0;
    std::size_t senderOffSent = 0, senderOffRecv = 0, senderTotalSent = 0, senderTotalRecv = 0;
    std::size_t receiverOffSent = 0, receiverOffRecv = 0, receiverTotalSent = 0, receiverTotalRecv = 0;
    std::size_t intersectionSize = 0;
    bool intersectionOk = false;
    std::barrier phaseBarrier(2);

    thread receiverThread(runReceiver, n, port,
                          std::ref(phaseBarrier),
                          std::ref(offTime), std::ref(onTime),
                          std::ref(receiverOffSent), std::ref(receiverOffRecv),
                          std::ref(receiverTotalSent), std::ref(receiverTotalRecv),
                          std::ref(intersectionSize), std::ref(intersectionOk));
    thread senderThread(runSender, n, port,
                        std::ref(phaseBarrier),
                        std::ref(senderOffSent), std::ref(senderOffRecv),
                        std::ref(senderTotalSent), std::ref(senderTotalRecv));

    receiverThread.join();
    senderThread.join();

    const double senderOnlineSend   = static_cast<double>(senderTotalSent - senderOffSent);
    const double receiverOnlineSend = static_cast<double>(receiverTotalSent - receiverOffSent);
    const double offlineData        = static_cast<double>(senderOffSent + receiverOffSent);
    const double onlineData         = senderOnlineSend + receiverOnlineSend;

    cout << fixed << setprecision(4);
    cout << "==============================================="  << endl;
    cout << "  Mode:                      " << mode     << endl;
    cout << "  Dataset size:              2^" << setSize << " = " << n << endl;
    cout << "  Port:                      " << port << endl;
    cout << "  Intersection size:         " << intersectionSize << endl;
    cout << "  Intersection correct:      " << (intersectionOk ? "YES" : "NO") << endl;
    cout << "===============================================" << endl;
    cout << "  Receiver offline time:     " << setw(10) << offTime              << " seconds" << endl;
    cout << "  Receiver online  time:     " << setw(10) << onTime               << " seconds" << endl;
    cout << "  Protocol total   time:     " << setw(10) << (offTime + onTime)   << " seconds" << endl;
    cout << "===============================================" << endl;
    cout << "  Protocol offline data:     " << setw(10) << offlineData  / 1024.0 / 1024.0 << " MB" << endl;
    cout << "  Protocol online  data:     " << setw(10) << onlineData   / 1024.0 / 1024.0 << " MB" << endl;
    cout << "  Sender   online  data:     " << setw(10) << senderOnlineSend   / 1024.0 / 1024.0 << " MB" << endl;
    cout << "  Receiver online  data:     " << setw(10) << receiverOnlineSend / 1024.0 / 1024.0 << " MB" << endl;
    cout << "===============================================" << endl;

    return 0;
}
