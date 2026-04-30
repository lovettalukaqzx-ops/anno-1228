#include <iostream>
#include "psi.h"
#include "band_okvs.h"
#include "uint.h"
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <thread>
#include <random>
#include <sys/time.h>
#include <fstream>

using namespace std;
using namespace osuCrypto;
using namespace band_okvs;

void runReceiver(IOService& ios, int n, 
                 double& offTime, double& onTime, 
                 double& dataSent, double& dataRecv,
                 double& offSent, double& offRecv) {

    Session receiverSession(ios, "127.0.0.1", 12345, EpMode::Client);
    Channel receiverCh = receiverSession.addChannel();

    Receiver receiver;
    vector<oc::block> recvK(n);
    key_init(recvK, true);
    vector<oc::block> recvV(3 * n);
    // random_device rd;
    // uniform_int_distribution<uint64_t> dist;
    // GenRandomValuesBlocks(recvV, dist(rd), dist(rd));
    oc::PRNG prng(toBlock(666));
    prng.get<oc::block>(recvV);

    receiver.init(receiverCh, n, recvK, recvV, offTime);

    offSent = receiverCh.getTotalDataSent();
	offRecv = receiverCh.getTotalDataRecv();

    receiver.output(receiverCh, onTime);

    dataSent = receiverCh.getTotalDataSent();
	dataRecv = receiverCh.getTotalDataRecv();

    receiverCh.close();

}

void runSender(IOService& ios, int n) {

    Session senderSession(ios, "127.0.0.1", 12345, EpMode::Server);
    Channel senderCh = senderSession.addChannel();

    Sender sender;
    vector<oc::block> sendK(n);
    key_init(sendK, false);

    sender.init(senderCh, n, sendK);
    sender.output(senderCh);

    senderCh.close();

}

int main() {
    
    // Setting
    int n = 1 << 16;
    // cin >> Number;
    cin >> Div_num;
    
    // Time variables to be collected and Data
    double offTime, onTime, dataSent, dataRecv, offSent, offRecv;
    
    // Receiver and Sender
    IOService ios;
    thread receiverThread(runReceiver, std::ref(ios), n,
                          std::ref(offTime), std::ref(onTime), 
                          std::ref(dataSent), std::ref(dataRecv),
                          std::ref(offSent), std::ref(offRecv));
    thread senderThread(runSender, std::ref(ios), n);

    receiverThread.join();
    senderThread.join();

    ios.stop();

    cout << "Receiver  offline       time: " << offTime << " seconds" << endl;
    cout << "Receiver  online        time: " << onTime << " seconds" << endl;
    cout << "Protocol  total         time: " << offTime + onTime << " seconds" << endl;
    cout << "Sender    transferring  data: " << (dataRecv - offRecv) / 1048.0 / 1048.0 << " MB" << endl;
    cout << "Receiver  transferring  data: " << (dataSent - offSent) / 1048.0 / 1048.0 << " MB" << endl;
    cout << "Protocol  total         data: " << (dataRecv + dataSent - offRecv - offSent) / 1048.0 / 1048.0 << " MB" << endl;

    return 0;
}