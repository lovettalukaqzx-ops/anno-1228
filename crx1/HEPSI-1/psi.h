#ifndef PSI_PSI_H
#define PSI_PSI_H

#include <cryptoTools/Common/block.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/AES.h>
#include <vector>
#include <string>
#include <map>
#include <utility>
#include <cstddef>
#include "seal/seal.h"
#include "CuckooIndex.h"
#include "SimpleIndex.h"
#include <random>
#include <memory>

using namespace std;
using namespace osuCrypto;
using namespace seal;

struct ProtocolConfig {
    size_t sender_size;
    size_t receiver_size;
    size_t hash_len;
    size_t parm_len;
    size_t intersection_size;
    size_t slot_bits;
    size_t poly_modulus_degree;

    size_t p_b() const {
        return size_t{1} << parm_len;
    }
};

inline string uint64_to_hex_string(uint64_t value);

inline uint64_t truncate_hash(const oc::block& hashed_block, size_t len);

inline uint64_t encode_index(uint64_t i, uint64_t j, size_t slot_bits);

inline void decode_index(uint64_t index, size_t slot_bits, uint64_t& i, uint64_t& j);

ProtocolConfig make_protocol_config(size_t sender_size, size_t receiver_size);

void key_init(vector<oc::block>& key, bool choose, size_t intersection_size);

void runReceiver(IOService& ios, const ProtocolConfig& config,
                 double& offTime, double& onTime, double& sendTime,
                 double& dataSent, double& dataRecv,
                 double& offSent, double& offRecv);

void runSender(IOService& ios, const ProtocolConfig& config);

class Sender {
public:

    explicit Sender(const ProtocolConfig& config);

    ProtocolConfig config;
    EncryptionParameters parms;
    PublicKey public_key;

    random_device rd;
    mt19937_64 gen{rd()};
    uniform_int_distribution<uint64_t> dist;
    vector<size_t> perIndex;
    vector<size_t> active_indices;

    vector<oc::block> keyss;
    CuckooIndex<oc::ThreadSafe> cuckoo;
    vector<oc::block> after_cuckoo_set;
    vector<pair<Ciphertext, Ciphertext>> he_pair;
    vector<pair<Plaintext, Plaintext>> share_pair;
    vector<pair<Plaintext, Plaintext>> random_pair;

    vector<pair<Ciphertext, Ciphertext>> recv_hePair;
    unique_ptr<SEALContext> context_ptr;
    unique_ptr<Evaluator> evaluator_ptr;

    void init(Channel& chls, vector<oc::block>& sendK);
    void output(Channel& chls);

};

class Receiver {
public:

    explicit Receiver(const ProtocolConfig& config);

    ProtocolConfig config;
    EncryptionParameters parms;
    SecretKey secret_key;
    PublicKey public_key;
    string hePair1_str, hePair2_str;

    vector<oc::block> keys;
    vector<vector<oc::block>> after_simple_set;
    vector<pair<vector<uint64_t>, vector<uint64_t>>> hash_pair;

    vector<pair<uint64_t, uint64_t>> resultIndex;
    vector<vector<size_t>> save_index;
    map<size_t, oc::block> receiver_sender_psi;
    unique_ptr<SEALContext> context_ptr;
    unique_ptr<Decryptor> decryptor_ptr;
    unique_ptr<BatchEncoder> batch_encoder_ptr;
    vector<uint64_t> decode_buffer1;
    vector<uint64_t> decode_buffer2;
    vector<uint64_t> decode_buffer3;
    vector<uint64_t> decode_buffer4;

    void init(Channel& chls, vector<oc::block>& recvK, double& offTime);
    void output(Channel& chls, double& onTime, double& sendTime);

};

#endif //PSI_PSI_H
