#include "psi.h"
#include "band_okvs.h"
#include "uint.h"
#include <random>
#include <cstring>
#include <cstddef>
#include <vector>
#include <gmssl/sm3.h>
#include <unordered_map>
#include <map>
#include "CuckooIndex.h"
#include "SimpleIndex.h"

using namespace std;
using namespace osuCrypto;
using namespace band_okvs;

int Number = 100;

int Div_num;

void key_init(vector<oc::block>& key, bool choose) {

    oc::PRNG prng(toBlock(123));
    oc::PRNG prng0(toBlock(456));
    oc::PRNG prng1(toBlock(789));
    
    if (choose) {
        for (int i = 0; i < Number; i++) {
            oc::block same_value = prng.get<oc::block>();
            key[i] = same_value;
        }
        for (int i = Number; i < key.size(); i++) {
            key[i] = prng0.get<oc::block>();
        }
    }
    else {
        for (int i = 0; i < Number; i++) {
            oc::block same_value = prng.get<oc::block>();
            key[i] = same_value;
        }
        for (int i = Number; i < key.size(); i++) {
            key[i] = prng1.get<oc::block>();
        }
    }
}

inline array<uint8_t, 32> sm3_encrypt_block(const oc::block &inputBlock) {

    uint8_t inputData[16];
    memcpy(inputData, &inputBlock, 16);

    SM3_CTX ctx;
    sm3_init(&ctx);

    sm3_update(&ctx, inputData, sizeof(inputData));

    array<uint8_t, 32> outputHash;
    sm3_finish(&ctx, outputHash.data());

    return outputHash;

}

void Sender::init(Channel& chls, int n, vector<oc::block>& sendK) {

    keyss = sendK;

    // Cuckoo hash operation
    CuckooParam param = {0, 1.27, 3, static_cast<u64>(n)};
	cuckoo.init(param);
    vector<size_t> indexes(n);
	for (size_t i = 0; i < n; i++) {
        indexes[i] = i;
    }
	cuckoo.insert(indexes, keyss);
    after_cuckoo_set.resize(cuckoo.mBins.size());
    oc::PRNG prng_dummy(toBlock(321));
	for (size_t i = 0; i < cuckoo.mBins.size(); i++) {
		auto& bin = cuckoo.mBins[i];
		if (bin.isEmpty()) {
            after_cuckoo_set[i] = prng_dummy.get<oc::block>();
        }
		else {
            after_cuckoo_set[i] = keyss[bin.idx()] ^ toBlock(bin.hashIdx());
        }
	}

    vector<uint8_t> recvBuff;
    chls.recv(recvBuff);
    cuckoo_count.resize(recvBuff.size() / sizeof(int));
    memcpy(cuckoo_count.data(), recvBuff.data(), recvBuff.size());

    // OKVS initialization
    OKVS.resize(cuckoo_count.size());
    for (size_t i = 0; i < cuckoo_count.size(); i++) {
        int temp_n = cuckoo_count[i];
        int temp_m = static_cast<int>(1.05 * temp_n);
        OKVS[i].Init(temp_n, temp_m, okvsBandLength(temp_n), toBlock(888));
    }

}

void Sender::output(Channel& chls) {

    // Receive data
    vector<uint8_t> recvData;
    chls.recv(recvData);
    in.resize(recvData.size() / sizeof(oc::block));
    memcpy(in.data(), recvData.data(), recvData.size());

    // OKVS decoding
    int divide_num = cuckoo_count.size();
    size_t cuckoo_bin_num = after_cuckoo_set.size();
    size_t len1 = cuckoo_bin_num / divide_num; 
    size_t len2 = cuckoo_bin_num - (divide_num - 1) * len1;
    size_t in_index = 0;
    size_t start_index = 0;
    size_t end_index = 0;
    for (size_t i = 0; i < divide_num; i++) {
        int temp_m = static_cast<int>(1.05 * cuckoo_count[i]);
        vector<oc::block> temp_in(temp_m);
        memcpy(temp_in.data(), &in[in_index], temp_m * sizeof(oc::block));
        in_index += temp_m;
        if (end_index < (divide_num - 1) * len1) {
            end_index += len1;
        }
        else {
            end_index += len2;
        }
        vector<oc::block> temp_keyss;
        vector<oc::block> temp_decoded;
        for (size_t j = start_index; j < end_index; j++) {
            temp_keyss.emplace_back(after_cuckoo_set[j]);
        }
        start_index += end_index - start_index;
        temp_decoded.resize(temp_keyss.size());
        OKVS[i].Decode(temp_keyss.data(), temp_in.data(), temp_decoded.data(), temp_decoded.size());
        decoded.insert(decoded.end(), temp_decoded.begin(), temp_decoded.end());
    }

    // SM3 encrypted decoded
    decoded_sm3.resize(decoded.size());
    for (size_t i = 0; i < decoded_sm3.size(); i++) {
        decoded_sm3[i] = sm3_encrypt_block(decoded[i]);
    }

    // Send data back
    vector<uint8_t> sendData(decoded_sm3.size() * sizeof(array<uint8_t, 32>));
    memcpy(sendData.data(), decoded_sm3.data(), sendData.size());
    chls.send(sendData);

}

void Receiver::init(Channel& chls, int n, vector<oc::block>& recvK, vector<oc::block>& recvV, double& offTime) {

    struct timeval start, end;
    gettimeofday(&start, NULL);

    keys = recvK;
    values = recvV;

    // Simple hash operation
    size_t cuckoo_bin_num = ceil(1.27 * n);
	simple.resize(cuckoo_bin_num);
    // int divide_num = 256;
    int divide_num = Div_num;
    size_t len1 = cuckoo_bin_num / divide_num; 
    size_t len2 = cuckoo_bin_num - (divide_num - 1) * len1;
    simple_count.resize(divide_num, 0);
    for (auto& y : keys) {
		for (size_t i = 0; i < 3; i++) {
			size_t idx = CuckooIndex<ThreadSafe>::getHash(y, i, cuckoo_bin_num);
			simple[idx].emplace_back(y ^ toBlock(i));
            if (idx / len1 >= divide_num - 1) {
                simple_count[divide_num - 1]++; 
            }
            else {
                simple_count[idx / len1]++;
            }
		}
	}
    for (size_t i = 0; i < cuckoo_bin_num; i++) {
        if (simple[i].size()) {
            for (size_t j = 0; j < simple[i].size(); j++) {
                after_divide_set.emplace_back(simple[i][j]);
            }
        }
    }

    // for (const auto& i : simple_count) {
    //     cout << i << endl;
    // }

    vector<uint8_t> sendBuff(simple_count.size() * sizeof(int));
    memcpy(sendBuff.data(), simple_count.data(), sendBuff.size());
    chls.send(sendBuff);

    // okvs initialization and encoding
    okvs.resize(divide_num);
    size_t start_index = 0;
    for (size_t i = 0; i < divide_num; i++) {
        int temp_n = simple_count[i];
        int temp_m = static_cast<int>(1.05 * temp_n);
        okvs[i].Init(temp_n, temp_m, okvsBandLength(temp_n), toBlock(888));
        vector<oc::block> temp_keys(temp_n);
        vector<oc::block> temp_values(temp_n);
        vector<oc::block> temp_out(temp_m);
        memcpy(temp_keys.data(), &after_divide_set[start_index], temp_n * sizeof(oc::block));
        memcpy(temp_values.data(), &values[start_index], temp_n * sizeof(oc::block));
        if (!okvs[i].Encode(temp_keys.data(), temp_values.data(), temp_out.data())) {
            cout << "Failed to encode!" << endl;
            exit(0);
        }
        out.insert(out.end(), temp_out.begin(), temp_out.end());
        start_index += temp_n;
    }

    // SM3 encrypted values
    values_sm3.resize(values.size());
    for (size_t i = 0; i < values_sm3.size(); i++) {
        values_sm3[i] = sm3_encrypt_block(values[i]);
    }

    gettimeofday(&end, NULL);
    offTime = (end.tv_sec - start.tv_sec) + ((end.tv_usec - start.tv_usec) / 1000000.0);

}

void Receiver::output(Channel& chls, double& onTime) {

    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    // Sendand data
    vector<uint8_t> sendData(out.size() * sizeof(oc::block));
    memcpy(sendData.data(), out.data(), sendData.size());
    chls.send(sendData);

    // Receive data
    vector<uint8_t> recvData;
    chls.recv(recvData);
    sender_sm3.resize(recvData.size() / sizeof(array<uint8_t, 32>));
    memcpy(sender_sm3.data(), recvData.data(), recvData.size());

    // Use an unordered_map to optimize comparison (PSI)
    size_t values_index = 0;
    for (size_t d = 0; d < simple.size(); d++) {
        if (simple[d].size() == 0) {
            continue;
        }
        unordered_map<string, size_t> values_map;
        for (size_t j = values_index; j < values_index + simple[d].size(); j++) {
            values_map[string(reinterpret_cast<const char*>(values_sm3[j].data()), 32)] = j;
        }
        values_index += simple[d].size();
        string hash_str(reinterpret_cast<const char*>(sender_sm3[d].data()), 32);
        if (values_map.find(hash_str) != values_map.end()) {
            matchedIndices.emplace_back(values_map[hash_str]);
        }
    }

    gettimeofday(&end, NULL);
    onTime = (end.tv_sec - start.tv_sec) + ((end.tv_usec - start.tv_usec) / 1000000.0);

    // Create receiver_sender_psi and output information (Addtional test)
    save_index.resize(simple.size());
    for (size_t index = 0; index < keys.size(); index++) {
		for (size_t i = 0; i < 3; i++) {
			size_t idx = CuckooIndex<ThreadSafe>::getHash(keys[index], i, simple.size());
			save_index[idx].emplace_back(index);
		}
	}
    for (size_t i = 0; i < save_index.size(); i++) {
        if (save_index[i].size()) {
            for (size_t j = 0; j < save_index[i].size(); j++) {
                real_index.emplace_back(save_index[i][j]);
            }
        }
    }

    if (matchedIndices.empty()) {
        cout << "PSI Empty!" << endl;
    }
    else if (matchedIndices.size() == keys.size()) {
        cout << "PSI Full!" << endl;
        for (const auto& idx : matchedIndices) {
            receiver_sender_psi[real_index[idx]] = keys[real_index[idx]];
        }
    }
    else {
        for (const auto& idx : matchedIndices) {
            receiver_sender_psi[real_index[idx]] = keys[real_index[idx]];
        }
        for (const auto& [idx, blk] : receiver_sender_psi) {
            cout << "PSI Index: " << idx << "  Element: " << blk << endl;
        }
        cout << "PSI Partial: " << receiver_sender_psi.size() << endl;
    }
    // cout << "*****************************************************************" << endl;

}