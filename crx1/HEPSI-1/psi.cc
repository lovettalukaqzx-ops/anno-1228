#include "psi.h"
#include <random>
#include <cstring>
#include <cstddef>
#include <vector>
#include <unordered_map>
#include <string>
#include <map>
#include <utility>
#include <stdexcept>
#include <cstdint>
#include <sstream>
#include "seal/seal.h"
#include "CuckooIndex.h"
#include "SimpleIndex.h"
#include <algorithm>

using namespace std;
using namespace osuCrypto;
using namespace seal;

namespace {

size_t hash_len_for_paxos(size_t sender_size, size_t receiver_size) {
    switch (receiver_size) {
        case (size_t{1} << 20):
            switch (sender_size) {
                case 1: return 24;
                case 64: return 26;
                case 256: return 26;
                case 1024: return 27;
            }
            break;
        case (size_t{1} << 22):
            switch (sender_size) {
                case 1: return 25;
                case 64: return 26;
                case 256: return 27;
                case 1024: return 28;
            }
            break;
        case (size_t{1} << 24):
            switch (sender_size) {
                case 1: return 25;
                case 64: return 27;
                case 256: return 28;
                case 1024: return 28;
            }
            break;
    }

    throw invalid_argument("Unsupported sender/receiver size combination for HEPSI-1. Supported sender sizes are 1, 64, 256, 1024 and receiver sizes are 2^20, 2^22, 2^24.");
}

size_t parm_len_for_receiver(size_t receiver_size) {
    switch (receiver_size) {
        case (size_t{1} << 20): return 10;
        case (size_t{1} << 22): return 12;
        case (size_t{1} << 24): return 14;
        default:
            throw invalid_argument("Unsupported receiver size for HEPSI-1. Only 2^20, 2^22, and 2^24 are supported.");
    }
}

size_t intersection_size_for_sender(size_t sender_size) {
    switch (sender_size) {
        case 1: return 1;
        case 64: return 10;
        case 256: return 10;
        case 1024: return 100;
        default:
            throw invalid_argument("Unsupported sender size for HEPSI-1. Supported sender sizes are 1, 64, 256, 1024.");
    }
}

} // namespace

inline string uint64_to_hex_string(uint64_t value) {
    return util::uint_to_hex_string(&value, size_t(1));
}

inline uint64_t truncate_hash(const oc::block& hashed_block, size_t len) {
    uint64_t value = *reinterpret_cast<const uint64_t*>(&hashed_block);
    if (len >= 64) {
        return value;
    }
    return value & ((uint64_t{1} << len) - 1);
}

inline uint64_t encode_index(uint64_t i, uint64_t j, size_t slot_bits) {
    return (i << slot_bits) | j;
}

inline void decode_index(uint64_t index, size_t slot_bits, uint64_t& i, uint64_t& j) {
    i = index >> slot_bits;
    j = index & ((uint64_t{1} << slot_bits) - 1);
}

ProtocolConfig make_protocol_config(size_t sender_size, size_t receiver_size) {
    return ProtocolConfig{
        sender_size,
        receiver_size,
        hash_len_for_paxos(sender_size, receiver_size),
        parm_len_for_receiver(receiver_size),
        intersection_size_for_sender(sender_size),
        12,
        4096
    };
}

void key_init(vector<oc::block>& key, bool choose, size_t intersection_size) {

    oc::PRNG prng(toBlock(123));
    oc::PRNG prng0(toBlock(456));
    oc::PRNG prng1(toBlock(789));
    size_t common_count = min(intersection_size, key.size());

    if (choose) {
        for (size_t i = 0; i < common_count; i++) {
            oc::block same_value = prng.get<oc::block>();
            key[i] = same_value;
        }
        for (size_t i = common_count; i < key.size(); i++) {
            key[i] = prng0.get<oc::block>();
        }
    }
    else {
        for (size_t i = 0; i < common_count; i++) {
            oc::block same_value = prng.get<oc::block>();
            key[i] = same_value;
        }
        for (size_t i = common_count; i < key.size(); i++) {
            key[i] = prng1.get<oc::block>();
        }
    }
}

void runReceiver(IOService& ios, const ProtocolConfig& config,
                 double& offTime, double& onTime, double& sendTime,
                 double& dataSent, double& dataRecv,
                 double& offSent, double& offRecv) {

    Session receiverSession(ios, "127.0.0.1", 12345, EpMode::Client);
    Channel receiverCh = receiverSession.addChannel();

    Receiver receiver(config);
    vector<oc::block> recvK(config.receiver_size);
    key_init(recvK, true, config.intersection_size);

    receiver.init(receiverCh, recvK, offTime);

    offSent = receiverCh.getTotalDataSent();
    offRecv = receiverCh.getTotalDataRecv();

    receiver.output(receiverCh, onTime, sendTime);

    dataSent = receiverCh.getTotalDataSent();
    dataRecv = receiverCh.getTotalDataRecv();

    receiverCh.close();
}

void runSender(IOService& ios, const ProtocolConfig& config) {

    Session senderSession(ios, "127.0.0.1", 12345, EpMode::Server);
    Channel senderCh = senderSession.addChannel();

    Sender sender(config);
    vector<oc::block> sendK(config.sender_size);
    key_init(sendK, false, config.intersection_size);

    sender.init(senderCh, sendK);
    sender.output(senderCh);

    senderCh.close();
}

Sender::Sender(const ProtocolConfig& config)
    : config(config),
      dist(0, (uint64_t{1} << config.hash_len) - 1) {}

void Sender::init(Channel& chls, vector<oc::block>& sendK) {

    keyss = sendK;

    string received_parms_str, received_pkey_str;
    chls.recv(received_parms_str);
    chls.recv(received_pkey_str);
    istringstream received_parms_stream(received_parms_str);
    parms.load(received_parms_stream);

    context_ptr = make_unique<SEALContext>(parms);
    istringstream received_pkey_stream(received_pkey_str);
    public_key.load(*context_ptr, received_pkey_stream);
    evaluator_ptr = make_unique<Evaluator>(*context_ptr);

    CuckooParam param = {1, 1.09, 4, static_cast<u64>(config.p_b())};
    cuckoo.init(param);
    vector<size_t> indexes(config.sender_size);
    for (size_t i = 0; i < config.sender_size; i++) {
        indexes[i] = i;
    }
    cuckoo.insert(indexes, keyss);

    size_t cuckoo_bin_num = cuckoo.mBins.size();
    after_cuckoo_set.resize(cuckoo_bin_num);
    he_pair.resize(cuckoo_bin_num);
    share_pair.resize(cuckoo_bin_num);
    random_pair.resize(cuckoo_bin_num);
    recv_hePair.resize(cuckoo_bin_num);
    AES aes1(ZeroBlock);
    AES aes2(AllOneBlock);
    BatchEncoder batch_encoder(*context_ptr);
    Encryptor encryptor(*context_ptr, public_key);
    size_t slot_count = batch_encoder.slot_count();
    active_indices.clear();
    active_indices.reserve(cuckoo_bin_num);
    for (uint64_t i = 0; i < cuckoo.mBins.size(); i++) {
        auto& bin = cuckoo.mBins[i];
        if (bin.isEmpty()) {
            after_cuckoo_set[i] = AllOneBlock;
        }
        else {
            active_indices.push_back(i);
            oc::block target = keyss[bin.idx()] ^ toBlock(bin.hashIdx());
            after_cuckoo_set[i] = target;
            uint64_t h1 = truncate_hash(aes1.hashBlock(target), config.hash_len);
            uint64_t h2 = truncate_hash(aes2.hashBlock(target), config.hash_len);
            vector<uint64_t> temp1(slot_count, h1);
            vector<uint64_t> temp2(slot_count, h2);
            Plaintext plain1, plain2;
            batch_encoder.encode(temp1, plain1);
            batch_encoder.encode(temp2, plain2);
            encryptor.encrypt(plain1, he_pair[i].first);
            encryptor.encrypt(plain2, he_pair[i].second);
            vector<uint64_t> share1, share2, random1, random2;
            share1.reserve(slot_count);
            share2.reserve(slot_count);
            random1.reserve(slot_count);
            random2.reserve(slot_count);
            for (uint64_t j = 0; j < slot_count; j++) {
                uint64_t target_index = encode_index(i, j, config.slot_bits);
                uint64_t a = dist(gen);
                share1.emplace_back(a | target_index);
                uint64_t r = dist(gen);
                share2.emplace_back(target_index | (r & (~a)));
                random1.emplace_back(a);
                random2.emplace_back(r);
            }
            Plaintext p1_share, p2_share, p1_random, p2_random;
            batch_encoder.encode(share1, p1_share);
            batch_encoder.encode(share2, p2_share);
            batch_encoder.encode(random1, p1_random);
            batch_encoder.encode(random2, p2_random);
            share_pair[i].first = p1_share;
            share_pair[i].second = p2_share;
            random_pair[i].first = p1_random;
            random_pair[i].second = p2_random;
        }
    }

    perIndex = active_indices;
    shuffle(perIndex.begin(), perIndex.end(), gen);
}

void Sender::output(Channel& chls) {

    string recv1_str, recv2_str;
    chls.recv(recv1_str);
    chls.recv(recv2_str);

    istringstream recv1_stream(recv1_str), recv2_stream(recv2_str);
    for (size_t idx = 0; idx < recv_hePair.size(); idx++) {
        recv_hePair[idx].first.load(*context_ptr, recv1_stream);
        recv_hePair[idx].second.load(*context_ptr, recv2_stream);
    }

    ostringstream stream1, stream2, stream3, stream4;
    for (size_t ck : perIndex) {
        Ciphertext c1, c2, c3, c4;
        evaluator_ptr->sub(he_pair[ck].first, recv_hePair[ck].first, c1);
        evaluator_ptr->sub(he_pair[ck].second, recv_hePair[ck].second, c2);
        evaluator_ptr->multiply_plain(c1, random_pair[ck].first, c3);
        evaluator_ptr->multiply_plain(c2, random_pair[ck].second, c4);
        evaluator_ptr->add_plain_inplace(c3, share_pair[ck].first);
        evaluator_ptr->add_plain_inplace(c4, share_pair[ck].second);
        c1.save(stream1);
        c2.save(stream2);
        c3.save(stream3);
        c4.save(stream4);
    }
    string str1 = stream1.str();
    string str2 = stream2.str();
    string str3 = stream3.str();
    string str4 = stream4.str();

    chls.send(str1);
    chls.send(str2);
    chls.send(str3);
    chls.send(str4);
}

Receiver::Receiver(const ProtocolConfig& config)
    : config(config) {}

void Receiver::init(Channel& chls, vector<oc::block>& recvK, double& offTime) {

    struct timeval start, end;
    gettimeofday(&start, NULL);

    keys = recvK;

    parms = EncryptionParameters(scheme_type::bfv);
    parms.set_poly_modulus_degree(config.poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(config.poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(config.poly_modulus_degree, config.hash_len + 1));
    context_ptr = make_unique<SEALContext>(parms);
    KeyGenerator keygen(*context_ptr);
    secret_key = keygen.secret_key();
    keygen.create_public_key(public_key);
    decryptor_ptr = make_unique<Decryptor>(*context_ptr, secret_key);
    batch_encoder_ptr = make_unique<BatchEncoder>(*context_ptr);

    ostringstream parms_stream;
    parms.save(parms_stream);
    string parms_str = parms_stream.str();
    ostringstream public_stream;
    public_key.save(public_stream);
    string public_str = public_stream.str();
    chls.send(parms_str);
    chls.send(public_str);

    size_t cuckoo_bin_num = ceil(1.09 * config.p_b());
    after_simple_set.resize(cuckoo_bin_num);
    hash_pair.resize(cuckoo_bin_num);
    AES aes1(ZeroBlock);
    AES aes2(AllOneBlock);
    for (auto& blk : keys) {
        for (size_t i = 0; i < 4; i++) {
            size_t idx = CuckooIndex<ThreadSafe>::getHash(blk, i, cuckoo_bin_num);
            auto temp = blk ^ toBlock(i);
            hash_pair[idx].first.emplace_back(truncate_hash(aes1.hashBlock(temp), config.hash_len));
            hash_pair[idx].second.emplace_back(truncate_hash(aes2.hashBlock(temp), config.hash_len));
        }
    }
    Encryptor encryptor(*context_ptr, public_key);
    size_t slot_count = batch_encoder_ptr->slot_count();
    decode_buffer1.reserve(slot_count);
    decode_buffer2.reserve(slot_count);
    decode_buffer3.reserve(slot_count);
    decode_buffer4.reserve(slot_count);
    ostringstream hePair1_stream, hePair2_stream;
    for (size_t i = 0; i < cuckoo_bin_num; i++) {
        vector<uint64_t> temp1 = hash_pair[i].first;
        vector<uint64_t> temp2 = hash_pair[i].second;
        temp1.resize(slot_count, 0);
        temp2.resize(slot_count, 0);
        Plaintext plain1, plain2;
        batch_encoder_ptr->encode(temp1, plain1);
        batch_encoder_ptr->encode(temp2, plain2);
        Ciphertext cipher1, cipher2;
        encryptor.encrypt(plain1, cipher1);
        encryptor.encrypt(plain2, cipher2);
        cipher1.save(hePair1_stream);
        cipher2.save(hePair2_stream);
    }
    hePair1_str = hePair1_stream.str();
    hePair2_str = hePair2_stream.str();

    gettimeofday(&end, NULL);
    offTime = (end.tv_sec - start.tv_sec) + ((end.tv_usec - start.tv_usec) / 1000000.0);
}

void Receiver::output(Channel& chls, double& onTime, double& sendTime) {

    struct timeval start0, end0;
    gettimeofday(&start0, NULL);

    chls.send(hePair1_str);
    chls.send(hePair2_str);

    gettimeofday(&end0, NULL);
    sendTime = (end0.tv_sec - start0.tv_sec) + ((end0.tv_usec - start0.tv_usec) / 1000000.0);

    struct timeval start, end;
    gettimeofday(&start, NULL);

    string send_str1, send_str2, send_str3, send_str4;
    chls.recv(send_str1);
    chls.recv(send_str2);
    chls.recv(send_str3);
    chls.recv(send_str4);

    istringstream send_stream1(send_str1), send_stream2(send_str2),
                  send_stream3(send_str3), send_stream4(send_str4);
    while (send_stream1.peek() != EOF) {
        Ciphertext cipher1, cipher2, cipher3, cipher4;
        cipher1.load(*context_ptr, send_stream1);
        cipher2.load(*context_ptr, send_stream2);
        cipher3.load(*context_ptr, send_stream3);
        cipher4.load(*context_ptr, send_stream4);
        Plaintext plain1, plain2;
        decryptor_ptr->decrypt(cipher1, plain1);
        decryptor_ptr->decrypt(cipher2, plain2);
        decode_buffer1.clear();
        decode_buffer2.clear();
        batch_encoder_ptr->decode(plain1, decode_buffer1);
        batch_encoder_ptr->decode(plain2, decode_buffer2);
        for (size_t i = 0; i < decode_buffer1.size(); i++) {
            if (decode_buffer1[i] == 0 && decode_buffer2[i] == 0) {
                Plaintext plain3, plain4;
                decryptor_ptr->decrypt(cipher3, plain3);
                decryptor_ptr->decrypt(cipher4, plain4);
                decode_buffer3.clear();
                decode_buffer4.clear();
                batch_encoder_ptr->decode(plain3, decode_buffer3);
                batch_encoder_ptr->decode(plain4, decode_buffer4);
                uint64_t index = decode_buffer3[i] & decode_buffer4[i];
                uint64_t a, b;
                decode_index(index, config.slot_bits, a, b);
                resultIndex.emplace_back(a, b);
            }
        }
    }

    gettimeofday(&end, NULL);
    onTime = (end.tv_sec - start.tv_sec) + ((end.tv_usec - start.tv_usec) / 1000000.0);

    save_index.resize(after_simple_set.size());
    for (size_t index = 0; index < keys.size(); index++) {
        for (size_t i = 0; i < 4; i++) {
            size_t idx = CuckooIndex<ThreadSafe>::getHash(keys[index], i, after_simple_set.size());
            save_index[idx].emplace_back(index);
        }
    }

    if (resultIndex.empty()) {
        cout << "PSI Empty!" << endl;
    }
    else if (resultIndex.size() == keys.size()) {
        cout << "PSI Full!" << endl;
        for (const auto& idx : resultIndex) {
            receiver_sender_psi[save_index[idx.first][idx.second]] = keys[save_index[idx.first][idx.second]];
        }
    }
    else {
        for (const auto& idx : resultIndex) {
            receiver_sender_psi[save_index[idx.first][idx.second]] = keys[save_index[idx.first][idx.second]];
        }
        for (const auto& [idx, blk] : receiver_sender_psi) {
            cout << "PSI Index: " << idx << "  Element: " << blk << endl;
        }
        cout << "PSI Partial: " << receiver_sender_psi.size() << endl;
    }
}
