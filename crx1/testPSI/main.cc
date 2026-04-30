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

void runReceiver(IOService& ios, BandOkvs& okvs, oc::block seed_okvs,
                 int n, int m, int band_length, double& duringTime2, double& duringTime4, double& dataSize_server) {

    Session receiverSession(ios, "localhost", 1213, SessionMode::Server);
    Channel receiverCh = receiverSession.addChannel();

    Receiver receiver;
    
    // Receiver Init
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);

    receiver.init(okvs, seed_okvs, n, m, band_length);

    gettimeofday(&end1, NULL);
    duringTime2 = (end1.tv_sec - start1.tv_sec) + 
                  ((end1.tv_usec - start1.tv_usec) / 1000000.0);
    // cout << "Receiver_init time: " << duringTime2 << " seconds" << endl;
    
    // Receiver Output
    struct timeval start2, end2;
    gettimeofday(&start2, NULL);

    receiver.output(receiverCh, end2, dataSize_server);

    duringTime4 = (end2.tv_sec - start2.tv_sec) + 
                  ((end2.tv_usec - start2.tv_usec) / 1000000.0);
    // cout << "Receiver_output time: " << duringTime4 << " seconds" << endl;

    receiverCh.close();

}

void runSender(IOService& ios, BandOkvs& OKVS, oc::block seed_okvs,
               int n, int m, int band_length, double& duringTime1, double& duringTime3, double& dataSize_client) {

    Session senderSession(ios, "localhost", 1213, SessionMode::Client);
    Channel senderCh = senderSession.addChannel();

    Sender sender;

    // Sender Init
    struct timeval start3, end3;
    gettimeofday(&start3, NULL);

    sender.init(OKVS, seed_okvs, n, m, band_length);

    gettimeofday(&end3, NULL);
    duringTime1 = (end3.tv_sec - start3.tv_sec) + 
                  ((end3.tv_usec - start3.tv_usec) / 1000000.0);
    // cout << "Sender_init time: " << duringTime1 << " seconds" << endl;

    // Sender Output
    struct timeval start4, end4;
    gettimeofday(&start4, NULL);

    sender.output(senderCh, OKVS, dataSize_client);

    gettimeofday(&end4, NULL);
    duringTime3 = (end4.tv_sec - start4.tv_sec) + 
                  ((end4.tv_usec - start4.tv_usec) / 1000000.0);
    // cout << "Sender_output time: " << duringTime3 << " seconds" << endl;

    senderCh.close();

}

int main() {
    
    // Setting
    double epsilon = 0.05;
    int n = 1 << 20;
    int m = static_cast<int>((1 + epsilon) * n);
    int band_length = 377;
    
    // OKVS object
    random_device rd_okvs;
    uniform_int_distribution<uint64_t> dist_okvs;
    oc::block seed_okvs = oc::block(dist_okvs(rd_okvs), dist_okvs(rd_okvs));
    BandOkvs okvs, OKVS;
    
    // Time variables to be collected and Data
    double duringTime1, duringTime2, duringTime3, duringTime4, dataSize_server, dataSize_client;
    
    // Receiver and Sender
    IOService ios;
    thread receiverThread(runReceiver, std::ref(ios), std::ref(okvs),
                          seed_okvs, n, m, band_length, std::ref(duringTime2), std::ref(duringTime4), std::ref(dataSize_server));
    thread senderThread(runSender, std::ref(ios), std::ref(OKVS),
                        seed_okvs, n, m, band_length, std::ref(duringTime1), std::ref(duringTime3), std::ref(dataSize_client));

    receiverThread.join();
    senderThread.join();

    ios.stop();
    
    // Write all times to file in a single line
    // ofstream outfile("times_output.txt", ios::app);
    // outfile << duringTime1 << " " << duringTime2 << " " << duringTime3 << " " << duringTime4 << endl;
    // outfile.close();

    cout << "Sender Offline time: " << duringTime1 << " seconds" << endl;
    cout << "Sender Online time: " << duringTime3 << " seconds" << endl;
    cout << "Receiver Offline time: " << duringTime2 << " seconds" << endl;
    cout << "Receiver Online time: " << duringTime4 << " seconds" << endl;
    cout << "Sender Transferring Data: " << dataSize_client << " MB" << endl;
    cout << "Receiver Transferring Data: " << dataSize_server << " MB" << endl;

    return 0;
}