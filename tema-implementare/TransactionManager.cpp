#include "TransactionManager.h"
#include "Logger.h"
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <sstream>

TransactionManager::TransactionManager() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

TransactionManager::~TransactionManager() {
    EVP_cleanup();
    ERR_free_strings();
}

bool TransactionManager::processTransaction(int transactionId, int senderId, int receiverId,
    const std::string& subject, const std::string& message,
    const std::string& senderPassword) {
    std::cout << "\n=== Procesare tranzactie " << transactionId << " ===" << std::endl;

    Logger::getInstance()->log(senderId, "Initiere tranzactie " + std::to_string(transactionId));

    // 1. Incarca elementele simetrice
    SymmetricElements symElements = loadSymmetricElements(senderId);
    if (symElements.symKey.empty() || symElements.iv.empty()) {
        std::cerr << "Eroare la incarcarea elementelor simetrice!" << std::endl;
        return false;
    }

    // 2. Cripteaza mesajul
    std::vector<unsigned char> encryptedData = encryptFancyOFB(message,
        symElements.symKey,
        symElements.iv);

    // 3. Creeaza datele pentru semnare
    std::stringstream dataToSign;
    dataToSign << transactionId << subject << senderId << receiverId << symElements.symElementsId;
    dataToSign.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());

    // 4. Semneaza
    std::vector<unsigned char> signature = signWithRSA(dataToSign.str(), senderId, senderPassword);
    if (signature.empty()) {
        std::cerr << "Eroare la semnare!" << std::endl;
        return false;
    }

    // 5. Creeaza structura tranzactiei
    TransactionData transaction;
    transaction.transactionId = transactionId;
    transaction.subject = subject;
    transaction.senderId = senderId;
    transaction.receiverId = receiverId;
    transaction.symElementsId = symElements.symElementsId;
    transaction.encryptedData = encryptedData;
    transaction.signature = signature;

    // 6. Salveaza tranzactia
    if (!saveTransaction(transaction)) {
        std::cerr << "Eroare la salvarea tranzactiei!" << std::endl;
        return false;
    }

    std::cout << "Tranzactie procesata cu succes!" << std::endl;
    Logger::getInstance()->log(senderId, "Tranzactie " + std::to_string(transactionId) + " procesata");
    Logger::getInstance()->log(receiverId, "Primita tranzactie " + std::to_string(transactionId));

    return true;
}

std::vector<unsigned char> TransactionManager::encryptFancyOFB(const std::string& plaintext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> data(plaintext.begin(), plaintext.end());

    // Inverseaza IV-ul
    std::vector<unsigned char> invIV = invertIV(iv);

    // Ajusteaza cheia la 16 bytes
    std::vector<unsigned char> aesKey(16);
    if (key.size() >= 16) {
        std::copy(key.begin(), key.begin() + 16, aesKey.begin());
    }
    else {
        std::copy(key.begin(), key.end(), aesKey.begin());
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ciphertext;

    // Folosim AES-128-ECB pentru a cripta blocuri individuale
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aesKey.data(), NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    std::vector<unsigned char> state(16);
    std::vector<unsigned char> keystream(16);
    std::copy(iv.begin(), iv.end(), state.begin());

    // Proceseaza pe blocuri
    for (size_t i = 0; i < data.size(); i += 16) {
        // Cripteaza state-ul
        int len;
        std::vector<unsigned char> aesOutput(16);
        EVP_EncryptUpdate(ctx, aesOutput.data(), &len, state.data(), 16);

        // XOR cu invIV pentru keystream
        for (int j = 0; j < 16; j++) {
            keystream[j] = aesOutput[j] ^ invIV[j];
        }

        // XOR cu datele
        size_t blockSize = std::min(size_t(16), data.size() - i);
        for (size_t j = 0; j < blockSize; j++) {
            ciphertext.push_back(data[i + j] ^ keystream[j]);
        }

        // Updateaza state
        std::copy(aesOutput.begin(), aesOutput.end(), state.begin());
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<unsigned char> TransactionManager::signWithRSA(const std::string& data,
    int entityId,
    const std::string& password) {
    std::vector<unsigned char> signature;

    EVP_PKEY* rsaKey = loadRSAPrivateKey(entityId, password);
    if (!rsaKey) return signature;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(rsaKey);
        return signature;
    }

    // Semneaza cu SHA256
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, rsaKey) != 1 ||
        EVP_DigestSignUpdate(mdctx, data.c_str(), data.length()) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsaKey);
        return signature;
    }

    size_t sigLen;
    if (EVP_DigestSignFinal(mdctx, NULL, &sigLen) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsaKey);
        return signature;
    }

    signature.resize(sigLen);
    if (EVP_DigestSignFinal(mdctx, signature.data(), &sigLen) != 1) {
        signature.clear();
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(rsaKey);

    return signature;
}

TransactionManager::SymmetricElements TransactionManager::loadSymmetricElements(int entityId) {
    SymmetricElements elements;
    elements.symElementsId = 0;

    std::string filename = std::to_string(entityId) + ".sym";
    std::ifstream file(filename);
    if (!file) return elements;

    // Citeste base64
    std::string base64Content((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
    file.close();

    // Decodifica
    std::vector<unsigned char> der = base64Decode(base64Content);

    // Parse DER simplu
    size_t pos = 0;

    // SEQUENCE
    if (der[pos++] != 0x30) return elements;
    size_t seqLen = der[pos++];

    // SymElementsID - INTEGER
    if (der[pos++] != 0x02) return elements;
    size_t idLen = der[pos++];

    elements.symElementsId = 0;
    for (size_t i = 0; i < idLen; i++) {
        elements.symElementsId = (elements.symElementsId << 8) | der[pos++];
    }

    // SymKey - OCTET STRING
    if (der[pos++] != 0x04) return elements;
    size_t keyLen = der[pos++];
    elements.symKey.assign(der.begin() + pos, der.begin() + pos + keyLen);
    pos += keyLen;

    // IV - OCTET STRING
    if (der[pos++] != 0x04) return elements;
    size_t ivLen = der[pos++];
    elements.iv.assign(der.begin() + pos, der.begin() + pos + ivLen);

    return elements;
}

bool TransactionManager::saveTransaction(const TransactionData& transaction) {
    std::string filename = std::to_string(transaction.senderId) +
        "_" + std::to_string(transaction.receiverId) +
        "_" + std::to_string(transaction.transactionId) + ".trx";

    std::ofstream file(filename, std::ios::binary);
    if (!file) return false;

    // Construieste DER
    std::vector<unsigned char> der;

    // SEQUENCE
    der.push_back(0x30);
    size_t seqLenPos = der.size();
    der.push_back(0);

    // TransactionID - INTEGER
    der.push_back(0x02);
    std::vector<unsigned char> idBytes;
    int id = transaction.transactionId;
    while (id > 0) {
        idBytes.insert(idBytes.begin(), id & 0xFF);
        id >>= 8;
    }
    der.push_back(idBytes.size());
    der.insert(der.end(), idBytes.begin(), idBytes.end());

    // Subject - PrintableString
    der.push_back(0x13);
    der.push_back(transaction.subject.length());
    der.insert(der.end(), transaction.subject.begin(), transaction.subject.end());

    // SenderID - INTEGER
    der.push_back(0x02);
    idBytes.clear();
    id = transaction.senderId;
    while (id > 0) {
        idBytes.insert(idBytes.begin(), id & 0xFF);
        id >>= 8;
    }
    der.push_back(idBytes.size());
    der.insert(der.end(), idBytes.begin(), idBytes.end());

    // ReceiverID - INTEGER
    der.push_back(0x02);
    idBytes.clear();
    id = transaction.receiverId;
    while (id > 0) {
        idBytes.insert(idBytes.begin(), id & 0xFF);
        id >>= 8;
    }
    der.push_back(idBytes.size());
    der.insert(der.end(), idBytes.begin(), idBytes.end());

    // SymElementsID - INTEGER
    der.push_back(0x02);
    idBytes.clear();
    id = transaction.symElementsId;
    while (id > 0) {
        idBytes.insert(idBytes.begin(), id & 0xFF);
        id >>= 8;
    }
    der.push_back(idBytes.size());
    der.insert(der.end(), idBytes.begin(), idBytes.end());

    // EncryptedData - OCTET STRING
    der.push_back(0x04);
    if (transaction.encryptedData.size() < 128) {
        der.push_back(transaction.encryptedData.size());
    }
    else {
        der.push_back(0x81);
        der.push_back(transaction.encryptedData.size());
    }
    der.insert(der.end(), transaction.encryptedData.begin(), transaction.encryptedData.end());

    // Signature - OCTET STRING
    der.push_back(0x04);
    if (transaction.signature.size() < 128) {
        der.push_back(transaction.signature.size());
    }
    else if (transaction.signature.size() < 256) {
        der.push_back(0x81);
        der.push_back(transaction.signature.size());
    }
    else {
        der.push_back(0x82);
        der.push_back((transaction.signature.size() >> 8) & 0xFF);
        der.push_back(transaction.signature.size() & 0xFF);
    }
    der.insert(der.end(), transaction.signature.begin(), transaction.signature.end());

    // Actualizeaza lungimea
    size_t totalLen = der.size() - seqLenPos - 1;
    if (totalLen < 128) {
        der[seqLenPos] = totalLen;
    }
    else {
        der[seqLenPos] = 0x81;
        der.insert(der.begin() + seqLenPos + 1, totalLen);
    }

    file.write(reinterpret_cast<const char*>(der.data()), der.size());
    file.close();

    std::cout << "Tranzactie salvata: " << filename << std::endl;
    return true;
}

std::vector<unsigned char> TransactionManager::invertIV(const std::vector<unsigned char>& iv) {
    return std::vector<unsigned char>(iv.rbegin(), iv.rend());
}

EVP_PKEY* TransactionManager::loadRSAPrivateKey(int entityId, const std::string& password) {
    std::string filename = std::to_string(entityId) + "_priv.rsa";

    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) return nullptr;

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*)password.c_str());
    BIO_free(bio);

    return key;
}

std::vector<unsigned char> TransactionManager::base64Decode(const std::string& encoded) {
    std::vector<unsigned char> decoded;

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(encoded.c_str(), encoded.length());
    BIO_push(b64, mem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    decoded.resize(encoded.length());
    int decodedLen = BIO_read(b64, decoded.data(), encoded.length());

    if (decodedLen > 0) {
        decoded.resize(decodedLen);
    }
    else {
        decoded.clear();
    }

    BIO_free_all(b64);
    return decoded;
}