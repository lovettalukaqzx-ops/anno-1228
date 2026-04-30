#ifndef PSI_PSI_H
#define PSI_PSI_H

#include "band_okvs.h"
#include "uint.h"
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <vector>

using namespace std;
using namespace osuCrypto;
using namespace band_okvs;

void runReceiver(IOService& ios, BandOkvs& okvs, oc::block seed_okvs,
                 int n, int m, int band_length, double& duringTime2, double& duringTime4, double& dataSize_server);
void runSender(IOService& ios, BandOkvs& OKVS, oc::block seed_okvs,
               int n, int m, int band_length, double& duringTime1, double& duringTime3, double& dataSize_client);
array<uint8_t, 32> sm3_encrypt_block(const oc::block &inputBlock);

class Sender {
public:
    
    vector<oc::block> in;
    vector<oc::block> keyss;
    vector<oc::block> decoded;
    vector<array<uint8_t, 32>> decoded_sm3;

    void init(BandOkvs& OKVS, oc::block seed_okvs, int n, int m, int band_length);
    void output(Channel& chls, BandOkvs OKVS, double& dataSize_client);
    vector<uint8_t> serializeDecoded_sm3();

};

class Receiver {
public:
    
    vector<oc::block> keys;
    vector<oc::block> values;
    vector<oc::block> out;
    vector<array<uint8_t, 32>> values_sm3;
    vector<array<uint8_t, 32>> sender_sm3;
    vector<size_t> matchedIndices;
    vector<oc::block> receiver_sender_psi;

    void init(BandOkvs& okvs, oc::block seed_okvs, int n, int m, int band_length);
    void output(Channel& chls, struct timeval& end, double& dataSize_server);
    vector<uint8_t> serializeOut();
    void psi(Channel& ch, struct timeval& end);
    
};

#endif //PSI_PSI_H