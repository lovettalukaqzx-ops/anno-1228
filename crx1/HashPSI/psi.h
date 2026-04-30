#ifndef PSI_PSI_H
#define PSI_PSI_H

#include "band_okvs.h"
#include "uint.h"
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <vector>
#include <map>
#include "CuckooIndex.h"
#include "SimpleIndex.h"

using namespace std;
using namespace osuCrypto;
using namespace band_okvs;

extern int Number, Div_num;

void key_init(vector<oc::block>& key, bool choose);

void runReceiver(IOService& ios, int n,
                 double& offTime, double& onTime, 
                 double& dataSent, double& dataRecv,
                 double& offSent, double& offRecv);

void runSender(IOService& ios, int n);

inline array<uint8_t, 32> sm3_encrypt_block(const oc::block &inputBlock);

class Sender {
public:
    
    vector<oc::block> keyss;
    CuckooIndex<oc::ThreadSafe> cuckoo;
    vector<oc::block> after_cuckoo_set;
    vector<int> cuckoo_count; 
    vector<oc::block> in;
    vector<BandOkvs> OKVS;
    vector<oc::block> decoded;
    vector<array<uint8_t, 32>> decoded_sm3;

    void init(Channel& chls, int n, vector<oc::block>& sendK);
    void output(Channel& chls);

};

class Receiver {
public:
    
    vector<oc::block> keys;
    vector<vector<oc::block>> simple;
    vector<int> simple_count;
    vector<oc::block> after_divide_set;
    vector<oc::block> values;
    vector<BandOkvs> okvs;
    vector<oc::block> out;
    vector<array<uint8_t, 32>> values_sm3;
    vector<array<uint8_t, 32>> sender_sm3;

    vector<size_t> matchedIndices;
    vector<vector<size_t>> save_index;
    vector<size_t> real_index;
    map<size_t, oc::block> receiver_sender_psi;

    void init(Channel& chls, int n, vector<oc::block>& recvK, vector<oc::block>& recvV, double& offTime);
    void output(Channel& chls, double& onTime);
    
};

inline int okvsBandLength(int n) {
    if (n <= (1 << 14)) {
        return 339;
    }
    else if (n <= (1 << 16)) {
        return 350;
    }
    else if (n <= (1 << 18)) {
        return 366;
    }
    else if (n <= (1 << 20)) {
        return 377;
    }
    else if (n <= (1 << 22)) {
        return 396;
    }
    else if (n <= (1 << 24)) {
        return 413;
    }
    else {
        cout << "No valid band length for okvs!" << endl;
        exit(-1);
    }
  }

#endif //PSI_PSI_H