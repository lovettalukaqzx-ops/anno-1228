#include <iostream>
#include "psi.h"
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <thread>
#include <random>
#include <sys/time.h>
#include <fstream>
#include <functional>
#include <exception>
#include <limits>
#include "seal/seal.h"

using namespace std;
using namespace osuCrypto;
using namespace seal;

int main() {

    size_t sender_exponent;
    size_t receiver_exponent;

    cout << "Enter sender exponent: ";
    if (!(cin >> sender_exponent)) {
        cerr << "Failed to read sender exponent." << endl;
        return 1;
    }

    cout << "Enter receiver exponent: ";
    if (!(cin >> receiver_exponent)) {
        cerr << "Failed to read receiver exponent." << endl;
        return 1;
    }

    if (sender_exponent >= numeric_limits<size_t>::digits || receiver_exponent >= numeric_limits<size_t>::digits) {
        cerr << "Exponent is too large for size_t." << endl;
        return 1;
    }

    size_t sender_size = size_t{1} << sender_exponent;
    size_t receiver_size = size_t{1} << receiver_exponent;

    ProtocolConfig config{};
    try {
        config = make_protocol_config(sender_size, receiver_size);
    }
    catch (const exception& ex) {
        cerr << ex.what() << endl;
        return 1;
    }

    cout << "Using parameters: sender size=2^" << sender_exponent
         << "=" << config.sender_size
         << ", receiver size=2^" << receiver_exponent
         << "=" << config.receiver_size
         << ", hashLen=" << config.hash_len
         << ", parmLen=" << config.parm_len
         << ", intersection size=" << config.intersection_size << endl;

    double offTime, onTime, sendTime, dataSent, dataRecv, offSent, offRecv;

    IOService ios;
    thread receiverThread(runReceiver, std::ref(ios), std::cref(config),
                          std::ref(offTime), std::ref(onTime), std::ref(sendTime),
                          std::ref(dataSent), std::ref(dataRecv),
                          std::ref(offSent), std::ref(offRecv));
    thread senderThread(runSender, std::ref(ios), std::cref(config));

    receiverThread.join();
    senderThread.join();

    ios.stop();

    cout << "Receiver  preprocess    time: " << offTime + sendTime << " seconds" << endl;
    cout << "Receiver  online        time: " << onTime << " seconds" << endl;
    cout << "Sender    transferring  data: " << (dataRecv - offRecv) / 1048.0 / 1048.0 << " MB" << endl;
    cout << "Receiver  transferring  data: " << (dataSent - offSent) / 1048.0 / 1048.0 << " MB" << endl;
    cout << "Protocol  total         data: " << (dataRecv + dataSent - offRecv - offSent) / 1048.0 / 1048.0 << " MB" << endl;

    return 0;
}
