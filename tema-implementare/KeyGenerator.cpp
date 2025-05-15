#include "KeyGenerator.h"
#include "Logger.h"
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cmath>

KeyGenerator::KeyGenerator() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

KeyGenerator::~KeyGenerator() {
    EVP_cleanup();
    ERR_free_strings();
}

bool KeyGenerator::generateAllKeys(int entityId, const std::string& password) {
    std::cout << "\nGenerare chei pentru entitatea " << entityId << std::endl;

    if (!generateECKeys(entityId, password)) {
        std::cerr << "Eroare la generarea cheilor EC!" << std::endl;
        return false;
    }

    if (!generateMAC(entityId, "ecc")) {
        std::cerr << "Eroare la generarea MAC pentru EC!" << std::endl;
        return false;
    }

    if (!generateRSAKeys(entityId, password)) {
        std::cerr << "Eroare la generarea cheilor RSA!" << std::endl;
        return false;
    }

    if (!generateMAC(entityId, "rsa")) {
        std::cerr << "Eroare la generarea MAC pentru RSA!" << std::endl;
        return false;
    }

    Logger::getInstance()->log(entityId, "Toate cheile generate cu succes");
    return true;
}

bool KeyGenerator::generateECKeys(int entityId, const std::string& password) {
    EVP_PKEY* ecKey = createECKey();
    if (!ecKey) {
        return false;
    }

    std::string privateFile = getPrivateKeyFile(entityId, "ecc");
    std::string publicFile = getPublicKeyFile(entityId, "ecc");

    bool success = savePrivateKey(ecKey, privateFile, password) &&
        savePublicKey(ecKey, publicFile);

    EVP_PKEY_free(ecKey);

    if (success) {
        Logger::getInstance()->log(entityId, "Chei EC generate");
    }

    return success;
}

bool KeyGenerator::generateRSAKeys(int entityId, const std::string& password) {
    EVP_PKEY* rsaKey = createRSAKey();
    if (!rsaKey) {
        return false;
    }

    std::string privateFile = getPrivateKeyFile(entityId, "rsa");
    std::string publicFile = getPublicKeyFile(entityId, "rsa");

    bool success = savePrivateKey(rsaKey, privateFile, password) &&
        savePublicKey(rsaKey, publicFile);

    EVP_PKEY_free(rsaKey);

    if (success) {
        Logger::getInstance()->log(entityId, "Chei RSA generate");
    }

    return success;
}

EVP_PKEY* KeyGenerator::createECKey() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return nullptr;

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

EVP_PKEY* KeyGenerator::createRSAKey() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return nullptr;

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

bool KeyGenerator::savePrivateKey(EVP_PKEY* key, const std::string& filename,
    const std::string& password) {
    BIO* bio = BIO_new_file(filename.c_str(), "w");
    if (!bio) return false;

    int result = PEM_write_bio_PKCS8PrivateKey(bio, key, EVP_aes_256_cbc(),
        password.c_str(), password.length(),
        nullptr, nullptr);
    BIO_free(bio);

    if (result == 1) {
        std::cout << "Cheie privata salvata: " << filename << std::endl;
    }

    return result == 1;
}

bool KeyGenerator::savePublicKey(EVP_PKEY* key, const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "w");
    if (!bio) return false;

    int result = PEM_write_bio_PUBKEY(bio, key);
    BIO_free(bio);

    if (result == 1) {
        std::cout << "Cheie publica salvata: " << filename << std::endl;
    }

    return result == 1;
}

bool KeyGenerator::generateMAC(int entityId, const std::string& keyType) {
    std::cout << "Generare MAC pentru " << keyType << std::endl;

    std::string publicKeyFile = getPublicKeyFile(entityId, keyType);
    std::ifstream keyFile(publicKeyFile, std::ios::binary);
    if (!keyFile) {
        return false;
    }

    std::string keyContent((std::istreambuf_iterator<char>(keyFile)),
        std::istreambuf_iterator<char>());
    keyFile.close();

    std::vector<unsigned char> macKey = generateMACKey();

    std::vector<unsigned char> macValue = calculateMAC(keyContent, macKey);

    bool success = saveMACToFile(entityId, keyType, macValue);

    if (success) {
        Logger::getInstance()->log(entityId, "MAC generat pentru " + keyType);
    }

    return success;
}

std::vector<unsigned char> KeyGenerator::generateMACKey() {
    std::string timeDiff = getTimeDifference();
    std::vector<unsigned char> key(32);

    // PBKDF2 cu SHA256 (pentru simplitate)
    PKCS5_PBKDF2_HMAC(timeDiff.c_str(), timeDiff.length(),
        nullptr, 0,  // fara salt
        10000,       // iteratii
        EVP_sha256(),
        key.size(), key.data());

    return key;
}

std::vector<unsigned char> KeyGenerator::calculateMAC(const std::string& data,
    const std::vector<unsigned char>& key) {
    std::vector<unsigned char> mac(16);  // GMAC are 16 bytes

    std::vector<unsigned char> aesKey(16);
    if (key.size() >= 16) {
        std::copy(key.begin(), key.begin() + 16, aesKey.begin());
    }
    else {
        std::copy(key.begin(), key.end(), aesKey.begin());
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return mac;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, aesKey.data(), NULL);

    unsigned char iv[12] = { 0 };
    EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);

    int len;
    EVP_EncryptUpdate(ctx, NULL, &len,
        reinterpret_cast<const unsigned char*>(data.c_str()),
        data.length());

    unsigned char dummy[1];
    EVP_EncryptFinal_ex(ctx, dummy, &len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, mac.data());

    EVP_CIPHER_CTX_free(ctx);
    return mac;
}

bool KeyGenerator::saveMACToFile(int entityId, const std::string& keyType,
    const std::vector<unsigned char>& macValue) {
    std::string filename = getMACFile(entityId, keyType);
    std::string pubKeyName = getPublicKeyFile(entityId, keyType);
    std::vector<unsigned char> macKey = generateMACKey();

    std::ofstream file(filename, std::ios::binary);
    if (!file) return false;

    std::vector<unsigned char> der;

    der.push_back(0x30);
    size_t seqLenPos = der.size();
    der.push_back(0);  // placeholder pentru lungime

    der.push_back(0x13);
    der.push_back(pubKeyName.length());
    der.insert(der.end(), pubKeyName.begin(), pubKeyName.end());

    der.push_back(0x04);
    der.push_back(macKey.size());
    der.insert(der.end(), macKey.begin(), macKey.end());

    der.push_back(0x04);
    der.push_back(macValue.size());
    der.insert(der.end(), macValue.begin(), macValue.end());

    der[seqLenPos] = der.size() - seqLenPos - 1;

    file.write(reinterpret_cast<const char*>(der.data()), der.size());
    file.close();

    std::cout << "MAC salvat: " << filename << std::endl;
    return true;
}

std::string KeyGenerator::getTimeDifference() {
    struct tm target_tm = { 0 };
    target_tm.tm_year = 105;  // 2005 - 1900
    target_tm.tm_mon = 4;     // Mai
    target_tm.tm_mday = 5;
    target_tm.tm_hour = 5;
    target_tm.tm_min = 5;
    target_tm.tm_sec = 5;

    time_t target_time = mktime(&target_tm);
    time_t current_time = time(nullptr);

    long long diff_seconds = static_cast<long long>(difftime(target_time, current_time));

    std::stringstream ss;
    ss << abs(diff_seconds);

    return ss.str();
}

std::string KeyGenerator::getPrivateKeyFile(int entityId, const std::string& keyType) {
    return std::to_string(entityId) + "_priv." + keyType;
}

std::string KeyGenerator::getPublicKeyFile(int entityId, const std::string& keyType) {
    return std::to_string(entityId) + "_pub." + keyType;
}

std::string KeyGenerator::getMACFile(int entityId, const std::string& keyType) {
    return std::to_string(entityId) + "_" + keyType + ".mac";
}