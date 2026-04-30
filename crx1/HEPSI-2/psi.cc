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

size_t parm_len_for_receiver(size_t receiver_size) {
    switch (receiver_size) {
        case (size_t{1} << 20): return 10;
        case (size_t{1} << 22): return 12;
        case (size_t{1} << 24): return 14;
        default:
            throw invalid_argument("Unsupported receiver size for HEPSI-2. Only 2^20, 2^22, and 2^24 are supported.");
    }
}

size_t hash_len_for_rb_okvs(size_t receiver_size) {
    switch (receiver_size) {
        case (size_t{1} << 20): return 44;
        case (size_t{1} << 22): return 45;
        case (size_t{1} << 24): return 44;
        default:
            throw invalid_argument("Unsupported receiver size for HEPSI-2. Only 2^20, 2^22, and 2^24 are supported.");
    }
}

size_t intersection_size_for_sender(size_t sender_size) {
    switch (sender_size) {
        case 1: return 1;
        case 64: return 10;
        case 256: return 10;
        case 1024: return 100;
        default:
            throw invalid_argument("Unsupported sender size for HEPSI-2. Supported sender sizes are 1, 64, 256, 1024.");
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
    if (sender_size != 1 && sender_size != 64 && sender_size != 256 && sender_size != 1024) {
        throw invalid_argument("Unsupported sender size for HEPSI-2. Supported sender sizes are 1, 64, 256, 1024.");
    }

    return ProtocolConfig{
        sender_size,
        receiver_size,
        hash_len_for_rb_okvs(receiver_size),
        parm_len_for_receiver(receiver_size),
        intersection_size_for_sender(sender_size),
        13,
        8192
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
    after_cuckoo_set.resize(cuckoo_bin_num + 1);
    size_t half_bin_num = after_cuckoo_set.size() / 2;
    judge_set.resize(half_bin_num, true);
    he_vector.resize(half_bin_num);
    index_vector.resize(half_bin_num);
    random_vector.resize(half_bin_num);
    recv_heVector.resize(half_bin_num);
    AES aes1(ZeroBlock);
    BatchEncoder batch_encoder(*context_ptr);
    Encryptor encryptor(*context_ptr, public_key);
    size_t slot_count = batch_encoder.slot_count();
    for (uint64_t i = 0; i < cuckoo_bin_num; i++) {
        auto& bin = cuckoo.mBins[i];
        if (bin.isEmpty()) {
            after_cuckoo_set[i] = AllOneBlock;
        }
        else {
            oc::block target = keyss[bin.idx()] ^ toBlock(bin.hashIdx());
            after_cuckoo_set[i] = target;
        }
    }
    after_cuckoo_set[cuckoo_bin_num] = AllOneBlock;

    active_indices.clear();
    active_indices.reserve(half_bin_num);
    for (uint64_t i = 0, j = 0; i < half_bin_num; i++, j += 2) {
        oc::block first_block = after_cuckoo_set[j];
        oc::block second_block = after_cuckoo_set[j + 1];
        if (first_block != AllOneBlock || second_block != AllOneBlock) {
            active_indices.push_back(i);
        }
        if (first_block != AllOneBlock) {
            uint64_t h1 = truncate_hash(aes1.hashBlock(first_block), config.hash_len);
            uint64_t h2 = second_block != AllOneBlock ? truncate_hash(aes1.hashBlock(second_block), config.hash_len) : dist(gen);
            vector<uint64_t> temp(slot_count / 2, h1);
            temp.insert(temp.end(), slot_count / 2, h2);
            Plaintext plain;
            batch_encoder.encode(temp, plain);
            encryptor.encrypt(plain, he_vector[i]);
            vector<uint64_t> index, random;
            index.reserve(slot_count);
            random.reserve(slot_count);
            for (uint64_t k = 0; k < slot_count; k++) {
                uint64_t target_index = encode_index(i, k, config.slot_bits);
                index.emplace_back(target_index);
                uint64_t a = dist(gen);
                random.emplace_back(a);
            }
            Plaintext p_index, p_random;
            batch_encoder.encode(index, p_index);
            batch_encoder.encode(random, p_random);
            index_vector[i] = p_index;
            random_vector[i] = p_random;
        } else if (second_block != AllOneBlock) {
            uint64_t h1 = dist(gen);
            uint64_t h2 = truncate_hash(aes1.hashBlock(second_block), config.hash_len);
            vector<uint64_t> temp(slot_count / 2, h1);
            temp.insert(temp.end(), slot_count / 2, h2);
            Plaintext plain;
            batch_encoder.encode(temp, plain);
            encryptor.encrypt(plain, he_vector[i]);
            vector<uint64_t> index, random;
            index.reserve(slot_count);
            random.reserve(slot_count);
            for (uint64_t k = 0; k < slot_count; k++) {
                uint64_t target_index = encode_index(i, k, config.slot_bits);
                index.emplace_back(target_index);
                uint64_t a = dist(gen);
                random.emplace_back(a);
            }
            Plaintext p_index, p_random;
            batch_encoder.encode(index, p_index);
            batch_encoder.encode(random, p_random);
            index_vector[i] = p_index;
            random_vector[i] = p_random;
        } else {
            judge_set[i] = false;
        }
    }

    perIndex = active_indices;
    shuffle(perIndex.begin(), perIndex.end(), gen);
}

void Sender::output(Channel& chls) {

    string recv1_str;
    chls.recv(recv1_str);

    istringstream recv1_stream(recv1_str);
    for (size_t idx = 0; idx < recv_heVector.size(); idx++) {
        recv_heVector[idx].load(*context_ptr, recv1_stream);
    }

    ostringstream stream1, stream3;
    for (size_t ck : perIndex) {
        Ciphertext c1, c3;
        evaluator_ptr->sub(he_vector[ck], recv_heVector[ck], c1);
        evaluator_ptr->multiply_plain(c1, random_vector[ck], c3);
        evaluator_ptr->add_plain_inplace(c3, index_vector[ck]);
        c1.save(stream1);
        c3.save(stream3);
    }
    string str1 = stream1.str();
    string str3 = stream3.str();

    chls.send(str1);
    chls.send(str3);
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
    size_t half_bin_num = (cuckoo_bin_num + 1) / 2;
    hash_vector.resize(cuckoo_bin_num + 1);
    AES aes1(ZeroBlock);
    for (auto& blk : keys) {
        for (size_t i = 0; i < 4; i++) {
            size_t idx = CuckooIndex<ThreadSafe>::getHash(blk, i, cuckoo_bin_num);
            auto temp = blk ^ toBlock(i);
            hash_vector[idx].emplace_back(truncate_hash(aes1.hashBlock(temp), config.hash_len));
        }
    }

    Encryptor encryptor(*context_ptr, public_key);
    size_t slot_count = batch_encoder_ptr->slot_count();
    decode_buffer1.reserve(slot_count);
    decode_buffer3.reserve(slot_count);
    ostringstream he_stream;
    for (size_t i = 0, j = 0; i < half_bin_num; i++, j += 2) {
        vector<uint64_t> temp1 = hash_vector[j];
        vector<uint64_t> temp2 = hash_vector[j + 1];
        temp1.resize(slot_count / 2, 0);
        temp2.resize(slot_count / 2, 0);
        temp1.insert(temp1.end(), temp2.begin(), temp2.end());
        Plaintext plain1;
        batch_encoder_ptr->encode(temp1, plain1);
        Ciphertext cipher1;
        encryptor.encrypt(plain1, cipher1);
        cipher1.save(he_stream);
    }
    he_str = he_stream.str();

    gettimeofday(&end, NULL);
    offTime = (end.tv_sec - start.tv_sec) + ((end.tv_usec - start.tv_usec) / 1000000.0);
}

void Receiver::output(Channel& chls, double& onTime, double& sendTime) {

    struct timeval start0, end0;
    gettimeofday(&start0, NULL);

    chls.send(he_str);

    gettimeofday(&end0, NULL);
    sendTime = (end0.tv_sec - start0.tv_sec) + ((end0.tv_usec - start0.tv_usec) / 1000000.0);

    struct timeval start, end;
    gettimeofday(&start, NULL);

    string send_str1, send_str3;
    chls.recv(send_str1);
    chls.recv(send_str3);

    istringstream send_stream1(send_str1), send_stream3(send_str3);
    while (send_stream1.peek() != EOF) {
        Ciphertext cipher1, cipher3;
        cipher1.load(*context_ptr, send_stream1);
        cipher3.load(*context_ptr, send_stream3);
        Plaintext plain1;
        decryptor_ptr->decrypt(cipher1, plain1);
        decode_buffer1.clear();
        batch_encoder_ptr->decode(plain1, decode_buffer1);
        for (size_t i = 0; i < decode_buffer1.size(); i++) {
            if (decode_buffer1[i] == 0) {
                Plaintext plain3;
                decryptor_ptr->decrypt(cipher3, plain3);
                decode_buffer3.clear();
                batch_encoder_ptr->decode(plain3, decode_buffer3);
                uint64_t index = decode_buffer3[i];
                uint64_t a, b;
                decode_index(index, config.slot_bits, a, b);
                resultIndex_long.emplace_back(a, b);
            }
        }
    }

    gettimeofday(&end, NULL);
    onTime = (end.tv_sec - start.tv_sec) + ((end.tv_usec - start.tv_usec) / 1000000.0);

    size_t half_slot_count = batch_encoder_ptr->slot_count() / 2;
    for (const auto& temp : resultIndex_long) {
        uint64_t a = temp.first;
        uint64_t b = temp.second;
        if (b < half_slot_count) {
            resultIndex.emplace_back(2 * a, b);
        } else {
            resultIndex.emplace_back(2 * a + 1, b - half_slot_count);
        }
    }

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
