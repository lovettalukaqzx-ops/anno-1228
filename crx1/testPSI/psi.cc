#include "psi.h"
#include "band_okvs.h"
#include "uint.h"
#include <random>
#include <cstring>
#include <cstddef>
#include <vector>
#include <gmssl/sm3.h>
#include <unordered_map>

using namespace std;
using namespace osuCrypto;
using namespace band_okvs;

// random_device rd;
// uniform_int_distribution<uint64_t> dist;
// oc::block seed = oc::block(dist(rd), dist(rd));

array<uint8_t, 32> sm3_encrypt_block(const oc::block &inputBlock) {

    uint8_t inputData[16];
    memcpy(inputData, &inputBlock, 16);

    SM3_CTX ctx;
    sm3_init(&ctx);

    sm3_update(&ctx, inputData, sizeof(inputData));

    array<uint8_t, 32> outputHash;
    sm3_finish(&ctx, outputHash.data());

    return outputHash;

}

void Sender::init(BandOkvs& OKVS, oc::block seed_okvs, int n, int m, int band_length) {
    
    // Randomly generate keyss
    random_device rd;
    uniform_int_distribution<uint64_t> dist;
    oc::PRNG prng(oc::block(dist(rd), dist(rd)));
    // oc::PRNG prng(seed);
    keyss = vector<oc::block>(n);
    prng.get<oc::block>(keyss);

    // OKVS initialization
    OKVS.Init(n, m, band_length, seed_okvs);

}

void Sender::output(Channel& chls, BandOkvs OKVS, double& dataSize_client) {

    // Receive data
    vector<uint8_t> receivedData(OKVS.Size() * sizeof(oc::block));
    chls.recv(receivedData.data(), receivedData.size());
    
    // // Deserialize data into in
    in.resize(OKVS.Size());
    for (size_t i = 0; i < OKVS.Size(); i++) {
        in[i] = *reinterpret_cast<oc::block*>(&receivedData[i * sizeof(oc::block)]);
    }
    
    // OKVS Decode(keyss, in) = decoded
    int n = OKVS.NumEqns(); 
    decoded = vector<oc::block>(n);
    OKVS.Decode(keyss.data(), in.data(), decoded.data());

    // SM3 encrypted decoded
    decoded_sm3 = vector<array<uint8_t, 32>>(decoded.size());
    for (size_t i = 0; i < decoded_sm3.size(); i++) {
        decoded_sm3[i] = sm3_encrypt_block(decoded[i]);
    }
     
    // Random permutation
    random_device r_d;
    mt19937 gen(r_d());
    shuffle(decoded_sm3.begin(), decoded_sm3.end(), gen);
    
    // Send data
    vector<uint8_t> serializedData = serializeDecoded_sm3();
    chls.send(serializedData.data(), serializedData.size());
    dataSize_client = static_cast<double>(serializedData.size()) / (1024 * 1024);
    // cout << "Sender sent: " << dataSize_client << " MB" << endl;

}

vector<uint8_t> Sender::serializeDecoded_sm3() {
    
    vector<uint8_t> serializedData(decoded_sm3.size() * 32);

    for (size_t i = 0; i < decoded_sm3.size(); i++) {
        copy(decoded_sm3[i].begin(), decoded_sm3[i].end(), serializedData.begin() + i * 32);
    }

    return serializedData;

}

void Receiver::init(BandOkvs& okvs, oc::block seed_okvs, int n, int m, int band_length) {
  
    // Randomly generate keys
    random_device rd;
    uniform_int_distribution<uint64_t> dist;
    oc::PRNG prng(oc::block(dist(rd), dist(rd)));
    // oc::PRNG prng(seed);
    keys = vector<oc::block>(n);
    prng.get<oc::block>(keys);
  
    // Randomly generate values
    values = vector<oc::block>(n);
    GenRandomValuesBlocks(values, dist(rd), dist(rd));
  
    // okvs initialization
    okvs.Init(n, m, band_length, seed_okvs);

    // okvs Encode(keys, values) = out
    out = vector<oc::block>(okvs.Size());
    if (!okvs.Encode(keys.data(), values.data(), out.data())) {
        cout << "Failed to encode!" << endl;
        exit(0);
    }

}

void Receiver::output(Channel& chls, struct timeval& end, double& dataSize_server) {
    
    // Sendand data
    vector<uint8_t> serializedData = serializeOut();
    chls.send(serializedData.data(), serializedData.size());
    dataSize_server = static_cast<double>(serializedData.size()) / (1024 * 1024);
    // cout << "Receiver sent: " << dataSize_server << " MB" << endl;

    // SM3 encrypted values
    values_sm3 = vector<array<uint8_t, 32>>(values.size());
    for (size_t i = 0; i < values_sm3.size(); i++) {
        values_sm3[i] = sm3_encrypt_block(values[i]);
    }

    // Receive data
    vector<uint8_t> receivedData(values.size() * 32);
    chls.recv(receivedData.data(), receivedData.size());

    // Deserialize data into sender_sm3
    sender_sm3.resize(values.size());
    for (size_t i = 0; i < values.size(); i++) {
        sender_sm3[i] = *reinterpret_cast<array<uint8_t, 32>*>(&receivedData[i * 32]);
    }

    // PSI
    psi(chls, end);

}

vector<uint8_t> Receiver::serializeOut() {

    vector<uint8_t> serializedData(out.size() * sizeof(oc::block));

    for (size_t i = 0; i < out.size(); i++) {
        const uint8_t* blockData = reinterpret_cast<const uint8_t*>(&out[i]);
        copy(blockData, blockData + sizeof(oc::block), serializedData.begin() + i * sizeof(oc::block));
    }

    return serializedData;

}

void Receiver::psi(Channel& ch, struct timeval& end) {

    // Use an unordered_map to optimize comparison
    unordered_map<string, size_t> values_map;
    for (size_t j = 0; j < values_sm3.size(); j++) {
        values_map[string(reinterpret_cast<const char*>(values_sm3[j].data()), 32)] = j;
    }

    for (size_t i = 0; i < sender_sm3.size(); i++) {
        string hash_str(reinterpret_cast<const char*>(sender_sm3[i].data()), 32);
        if (values_map.find(hash_str) != values_map.end()) {
            matchedIndices.push_back(values_map[hash_str]);
        }
    }

    // Get endtime
    gettimeofday(&end, NULL);

    // Create receiver_sender_psi and output information
    if (matchedIndices.empty()) {
        cout << "PSI empty!" << endl;
    }
    else {
        for (const auto& idx : matchedIndices) {
            receiver_sender_psi.push_back(keys[idx]);
            cout << "PSI index: " << idx << "  PSI element: " << keys[idx] << endl;
        }
    }
    cout << "*****************************************************************" << endl;

    // cout << receiver_sender_psi.size() << endl;

}