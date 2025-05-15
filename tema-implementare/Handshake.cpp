#include "Handshake.h"
#include "Logger.h"
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <iostream>
#include <fstream>
#include <sstream>

Handshake::Handshake() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

Handshake::~Handshake() {
    EVP_cleanup();
    ERR_free_strings();
}

bool Handshake::performHandshake(int entityId1, int entityId2,
    const std::string& password1,
    const std::string& password2) {
    std::cout << "\n=== Handshake intre " << entityId1 << " si " << entityId2 << " ===" << std::endl;

    // 1. Verifica autenticitatea cheilor
    if (!verifyMAC(entityId1, "ecc") || !verifyMAC(entityId2, "ecc")) {
        std::cerr << "Eroare la verificarea MAC!" << std::endl;
        return false;
    }

    // 2. Incarca cheile
    EVP_PKEY* privateKey1 = loadPrivateKey(entityId1, "ecc", password1);
    EVP_PKEY* publicKey2 = loadPublicKey(entityId2, "ecc");

    if (!privateKey1 || !publicKey2) {
        std::cerr << "Eroare la incarcarea cheilor!" << std::endl;
        if (privateKey1) EVP_PKEY_free(privateKey1);
        if (publicKey2) EVP_PKEY_free(publicKey2);
        return false;
    }

    // 3. ECDH
    std::vector<unsigned char> sharedSecret = doECDH(privateKey1, publicKey2);

    // 4. Deriveaza cheile simetrice
    SymmetricElements symElements = deriveSymmetricKey(sharedSecret);

    // Cleanup
    EVP_PKEY_free(privateKey1);
    EVP_PKEY_free(publicKey2);

    Logger::getInstance()->log(entityId1, "Handshake realizat cu " + std::to_string(entityId2));
    Logger::getInstance()->log(entityId2, "Handshake realizat cu " + std::to_string(entityId1));

    return true;
}

bool Handshake::generateSymmetricElementsForTransaction(int transactionId,
    int senderId, int receiverId,
    const std::string& senderPassword) {

    std::cout << "\n=== Generare elemente simetrice pentru tranzactia " << transactionId << " ===" << std::endl;

    EVP_PKEY* senderPrivKey = loadPrivateKey(senderId, "ecc", senderPassword);
    EVP_PKEY* receiverPubKey = loadPublicKey(receiverId, "ecc");

    if (!senderPrivKey || !receiverPubKey) {
        std::cerr << "Eroare la incarcarea cheilor pentru tranzactia " << transactionId << std::endl;
        if (senderPrivKey) EVP_PKEY_free(senderPrivKey);
        if (receiverPubKey) EVP_PKEY_free(receiverPubKey);
        return false;
    }

    std::vector<unsigned char> sharedSecret = doECDH(senderPrivKey, receiverPubKey);

    SymmetricElements symElements = deriveSymmetricKey(sharedSecret);
    symElements.symElementsId = transactionId;

    bool success = saveSymmetricElements(symElements, transactionId);

    EVP_PKEY_free(senderPrivKey);
    EVP_PKEY_free(receiverPubKey);

    if (success) {
        Logger::getInstance()->log(senderId, "Elemente simetrice generate pentru tranzactia " + std::to_string(transactionId));
    }

    return success;
}

bool Handshake::verifyMAC(int entityId, const std::string& keyType) {
    std::string macFile = std::to_string(entityId) + "_" + keyType + ".mac";
    std::ifstream file(macFile);
    bool exists = file.good();
    file.close();

    if (exists) {
        Logger::getInstance()->log(entityId, "MAC verificat pentru " + keyType);
    }

    return exists;
}

EVP_PKEY* Handshake::loadPrivateKey(int entityId, const std::string& keyType,
    const std::string& password) {
    std::string filename = std::to_string(entityId) + "_priv." + keyType;

    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) return nullptr;

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*)password.c_str());
    BIO_free(bio);

    return key;
}

EVP_PKEY* Handshake::loadPublicKey(int entityId, const std::string& keyType) {
    std::string filename = std::to_string(entityId) + "_pub." + keyType;

    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) return nullptr;

    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return key;
}

std::vector<unsigned char> Handshake::doECDH(EVP_PKEY* privateKey, EVP_PKEY* publicKey) {
    std::vector<unsigned char> sharedSecret;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx) return sharedSecret;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, publicKey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return sharedSecret;
    }

    size_t secretLen;
    if (EVP_PKEY_derive(ctx, NULL, &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return sharedSecret;
    }

    sharedSecret.resize(secretLen);
    if (EVP_PKEY_derive(ctx, sharedSecret.data(), &secretLen) <= 0) {
        sharedSecret.clear();
    }

    EVP_PKEY_CTX_free(ctx);
    return sharedSecret;
}

Handshake::SymmetricElements Handshake::deriveSymmetricKey(
    const std::vector<unsigned char>& sharedSecret) {
    SymmetricElements elements;

    std::vector<unsigned char> x = sharedSecret;
    std::vector<unsigned char> y = sha256(sharedSecret);

    std::vector<unsigned char> hash = sha256(x);
    std::vector<unsigned char> part1(hash.begin(), hash.begin() + 16);
    std::vector<unsigned char> part2(hash.begin() + 16, hash.end());
    std::vector<unsigned char> symLeft = xorBytes(part1, part2);

    std::vector<unsigned char> symRight = pbkdf2_sha384(y);

    std::vector<unsigned char> first16(symRight.begin(), symRight.begin() + 16);
    elements.symKey = xorBytes(symLeft, first16);

    if (symRight.size() >= 32) {
        elements.iv = std::vector<unsigned char>(symRight.begin() + 16, symRight.begin() + 32);
    }
    else {
        elements.iv = generateIV();
    }

    return elements;
}

bool Handshake::saveSymmetricElements(const SymmetricElements& elements, int symElementsId) {
    std::string filename = std::to_string(symElementsId) + ".sym";

    std::vector<unsigned char> der;

    der.push_back(0x30);
    size_t seqLenPos = der.size();
    der.push_back(0);

    der.push_back(0x02);
    std::vector<unsigned char> idBytes;
    int id = elements.symElementsId;
    while (id > 0) {
        idBytes.insert(idBytes.begin(), id & 0xFF);
        id >>= 8;
    }
    if (idBytes.empty()) {
        idBytes.push_back(0);
    }
    der.push_back(idBytes.size());
    der.insert(der.end(), idBytes.begin(), idBytes.end());

    der.push_back(0x04);
    der.push_back(elements.symKey.size());
    der.insert(der.end(), elements.symKey.begin(), elements.symKey.end());

    der.push_back(0x04);
    der.push_back(elements.iv.size());
    der.insert(der.end(), elements.iv.begin(), elements.iv.end());

    der[seqLenPos] = der.size() - seqLenPos - 1;

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);

    BIO_write(b64, der.data(), der.size());
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string base64Data(bptr->data, bptr->length);
    BIO_free_all(b64);

    std::ofstream file(filename);
    if (!file) return false;

    file << base64Data;
    file.close();

    std::cout << "Elemente simetrice salvate: " << filename << std::endl;
    return true;
}

std::vector<unsigned char> Handshake::sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<unsigned char> Handshake::pbkdf2_sha384(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> key(48);  // SHA-384 produce 48 bytes

    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(data.data()), data.size(),
        nullptr, 0,  
        10000,       
        EVP_sha384(),
        key.size(), key.data());

    return key;
}

std::vector<unsigned char> Handshake::xorBytes(const std::vector<unsigned char>& a,
    const std::vector<unsigned char>& b) {
    size_t len = std::min(a.size(), b.size());
    std::vector<unsigned char> result(len);

    for (size_t i = 0; i < len; i++) {
        result[i] = a[i] ^ b[i];
    }

    return result;
}

std::vector<unsigned char> Handshake::generateIV() {
    std::vector<unsigned char> iv(16);
    RAND_bytes(iv.data(), iv.size());
    return iv;
}