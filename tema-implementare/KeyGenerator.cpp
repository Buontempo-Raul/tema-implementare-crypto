#include "KeyGenerator.h"
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <cmath>
#include "Logger.h"

// Pentru compatibilitate cu OpenSSL 3.0+
#ifdef OPENSSL_VERSION_MAJOR
#if OPENSSL_VERSION_MAJOR >= 3
#define OPENSSL_SUPPRESS_DEPRECATED
#pragma warning(disable : 4996)
#endif
#endif

// Constructor
KeyGenerator::KeyGenerator() {
    // Initializeaza biblioteca OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// Destructor
KeyGenerator::~KeyGenerator() {
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
}

// Functie auxiliara pentru afisarea erorilor OpenSSL
void printOpenSSLError() {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    std::cerr << "OpenSSL Error: " << err_buf << std::endl;
}

// Genereaza o pereche de chei EC
bool KeyGenerator::generateECKeyPair(int entityId, const std::string& password) {
    std::cout << "Generare chei EC pentru entitatea " << entityId << "..." << std::endl;

    EVP_PKEY* ecKey = generateECKey();
    if (!ecKey) {
        std::cerr << "Eroare la generarea cheii EC!" << std::endl;
        Logger::getInstance()->logAction(entityId, Logger::ERROR, "Eroare generare cheie EC");
        return false;
    }

    // Salveaza cheile
    std::string privateFile = getPrivateKeyFilename(entityId, "ecc");
    std::string publicFile = getPublicKeyFilename(entityId, "ecc");

    bool success = savePrivateKey(ecKey, privateFile, password) &&
        savePublicKey(ecKey, publicFile);

    if (success) {
        Logger::getInstance()->logAction(entityId, Logger::KEY_GENERATION, "Chei EC generate");
    }

    EVP_PKEY_free(ecKey);
    return success;
}

// Genereaza o pereche de chei RSA
bool KeyGenerator::generateRSAKeyPair(int entityId, const std::string& password) {
    std::cout << "Generare chei RSA pentru entitatea " << entityId << "..." << std::endl;

    EVP_PKEY* rsaKey = generateRSAKey();
    if (!rsaKey) {
        std::cerr << "Eroare la generarea cheii RSA!" << std::endl;
        Logger::getInstance()->logAction(entityId, Logger::ERROR, "Eroare generare cheie RSA");
        return false;
    }

    // Salveaza cheile
    std::string privateFile = getPrivateKeyFilename(entityId, "rsa");
    std::string publicFile = getPublicKeyFilename(entityId, "rsa");

    bool success = savePrivateKey(rsaKey, privateFile, password) &&
        savePublicKey(rsaKey, publicFile);

    if (success) {
        Logger::getInstance()->logAction(entityId, Logger::KEY_GENERATION, "Chei RSA generate");
    }

    EVP_PKEY_free(rsaKey);
    return success;
}

// Genereaza cheie EC
EVP_PKEY* KeyGenerator::generateECKey() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return nullptr;

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    // Folosim curba P-256 (secp256r1)
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Genereaza cheie RSA
EVP_PKEY* KeyGenerator::generateRSAKey() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return nullptr;

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Salveaza cheia privata criptata
bool KeyGenerator::savePrivateKey(EVP_PKEY* key, const std::string& filename,
    const std::string& password) {
    BIO* bio = BIO_new_file(filename.c_str(), "w");
    if (!bio) {
        std::cerr << "Nu s-a putut crea fisierul " << filename << std::endl;
        return false;
    }

    int result = 0;

    // Verifica tipul cheii pentru a folosi formatul corect
    int keyType = EVP_PKEY_id(key);

    if (keyType == EVP_PKEY_RSA) {
        // Pentru chei RSA, folosim format PKCS1 conform cerintelor
        RSA* rsa = EVP_PKEY_get1_RSA(key);
        if (rsa) {
            result = PEM_write_bio_RSAPrivateKey(bio, rsa, EVP_aes_256_cbc(),
                (unsigned char*)password.c_str(), password.length(),
                nullptr, nullptr);
            RSA_free(rsa);
        }
    }
    else if (keyType == EVP_PKEY_EC) {
        // Pentru chei EC, folosim format PKCS8 conform cerintelor
        result = PEM_write_bio_PKCS8PrivateKey(bio, key, EVP_aes_256_cbc(),
            password.c_str(), password.length(),
            nullptr, nullptr);
    }
    else {
        // Pentru alte tipuri de chei, folosim PKCS8 ca default
        result = PEM_write_bio_PKCS8PrivateKey(bio, key, EVP_aes_256_cbc(),
            password.c_str(), password.length(),
            nullptr, nullptr);
    }

    BIO_free(bio);

    if (result == 1) {
        std::cout << "Cheie privata salvata: " << filename << std::endl;
        return true;
    }
    return false;
}

// Salveaza cheia publica
bool KeyGenerator::savePublicKey(EVP_PKEY* key, const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "w");
    if (!bio) {
        std::cerr << "Nu s-a putut crea fisierul " << filename << std::endl;
        return false;
    }

    // Pentru OpenSSL 3.0+, folosim aceeasi functie pentru ambele tipuri
    int result = PEM_write_bio_PUBKEY(bio, key);

    BIO_free(bio);

    if (result == 1) {
        std::cout << "Cheie publica salvata: " << filename << std::endl;
        return true;
    }
    return false;
}

// Calculeaza diferenta de timp pana la 050505050505Z
std::string KeyGenerator::getTimeDifference() {
    // Data target: 5 Mai 2005, 05:05:05 UTC
    // Conform cerintelor: 050505050505Z
    struct tm target_tm = { 0 };
    target_tm.tm_year = 105;  // 2005 - 1900
    target_tm.tm_mon = 4;     // Mai (0-indexed, deci 4 pentru mai)
    target_tm.tm_mday = 5;
    target_tm.tm_hour = 5;
    target_tm.tm_min = 5;
    target_tm.tm_sec = 5;

    // Converteste la UTC time_t
    time_t target_time = mktime(&target_tm);
    time_t current_time = time(nullptr);

    // Calculeaza diferenta in secunde
    long long diff_seconds = static_cast<long long>(difftime(target_time, current_time));

    // Converteste la string
    std::stringstream ss;
    ss << abs(diff_seconds);  // Folosim valoarea absoluta

    return ss.str();
}

// Genereaza cheia MAC folosind PBKDF2 cu SHA3-256
std::vector<unsigned char> KeyGenerator::generateMACKey() {
    std::string timeDiff = getTimeDifference();
    return pbkdf2_sha3_256(timeDiff, PBKDF2_ITERATIONS);
}

// Implementare PBKDF2 cu SHA3-256
std::vector<unsigned char> KeyGenerator::pbkdf2_sha3_256(const std::string& input, int iterations) {
    std::vector<unsigned char> key(32); // SHA3-256 produce 32 bytes

    // Incercam mai intai SHA3-256
    const EVP_MD* sha3_256 = EVP_sha3_256();
    if (sha3_256 != nullptr) {
        int result = PKCS5_PBKDF2_HMAC(input.c_str(), input.length(),
            nullptr, 0,  // fara salt
            iterations,
            sha3_256,
            key.size(), key.data());

        if (result == 1) {
            std::cout << "Folosesc SHA3-256 pentru PBKDF2" << std::endl;
            return key;
        }
    }

    // Fallback la SHA256 daca SHA3 nu e disponibil
    std::cerr << "SHA3-256 nu este disponibil, folosesc SHA256" << std::endl;
    int result = PKCS5_PBKDF2_HMAC(input.c_str(), input.length(),
        nullptr, 0,
        iterations,
        EVP_sha256(),
        key.size(), key.data());

    if (result != 1) {
        std::cerr << "Eroare la derivarea cheii PBKDF2" << std::endl;
    }

    return key;
}

// Genereaza toate cheile pentru o entitate
bool KeyGenerator::generateAllKeysForEntity(int entityId, const std::string& password) {
    std::cout << "\n=== Generare chei pentru entitatea " << entityId << " ===" << std::endl;

    // Genereaza chei EC
    if (!generateECKeyPair(entityId, password)) {
        return false;
    }

    // Genereaza MAC pentru cheia EC
    if (!generateMAC(entityId, "ecc")) {
        return false;
    }

    // Genereaza chei RSA
    if (!generateRSAKeyPair(entityId, password)) {
        return false;
    }

    // Genereaza MAC pentru cheia RSA
    if (!generateMAC(entityId, "rsa")) {
        return false;
    }

    std::cout << "Toate cheile au fost generate cu succes pentru entitatea " << entityId << std::endl;
    return true;
}

// Functii pentru nume de fisiere
std::string KeyGenerator::getPrivateKeyFilename(int entityId, const std::string& keyType) {
    return "id" + std::to_string(entityId) + "_priv." + keyType;
}

std::string KeyGenerator::getPublicKeyFilename(int entityId, const std::string& keyType) {
    return "id" + std::to_string(entityId) + "_pub." + keyType;
}

std::string KeyGenerator::getMACFilename(int entityId, const std::string& keyType) {
    return "id" + std::to_string(entityId) + "_" + keyType + ".mac";
}

// Genereaza si salveaza MAC-ul pentru o cheie publica
bool KeyGenerator::generateMAC(int entityId, const std::string& keyType) {
    std::cout << "Generare MAC pentru cheia " << keyType << " a entitatii " << entityId << std::endl;

    // 1. Citeste cheia publica
    std::string publicKeyFile = getPublicKeyFilename(entityId, keyType);

    // Citeste continutul cheii publice
    std::ifstream keyFile(publicKeyFile, std::ios::binary);
    if (!keyFile) {
        std::cerr << "Nu s-a putut deschide fisierul " << publicKeyFile << std::endl;
        Logger::getInstance()->logAction(entityId, Logger::ERROR,
            "Eroare la deschiderea fisierului " + publicKeyFile);
        return false;
    }

    std::string keyContent((std::istreambuf_iterator<char>(keyFile)),
        std::istreambuf_iterator<char>());
    keyFile.close();

    // 2. Genereaza cheia MAC
    std::vector<unsigned char> macKey = generateMACKey();

    // 3. Calculeaza GMAC
    std::vector<unsigned char> macValue = calculateMAC(keyContent, macKey);

    // 4. Salveaza in format DER
    bool success = saveMACToFile(entityId, keyType, macValue);

    if (success) {
        Logger::getInstance()->logAction(entityId, Logger::MAC_GENERATION,
            "MAC generat pentru cheia " + keyType);
    }

    return success;
}

// Calculeaza MAC folosind GMAC (AES-GCM authentication tag)
std::vector<unsigned char> KeyGenerator::calculateMAC(const std::string& data,
    const std::vector<unsigned char>& key) {
    std::vector<unsigned char> mac(16); // GMAC produce 16 bytes

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Eroare la crearea contextului cipher" << std::endl;
        return mac;
    }

    // Ajustam cheia la 16 bytes pentru AES-128-GCM (conform cerintei de AES-128)
    std::vector<unsigned char> aesKey(16);
    if (key.size() >= 16) {
        std::copy(key.begin(), key.begin() + 16, aesKey.begin());
    }
    else {
        std::copy(key.begin(), key.end(), aesKey.begin());
        // Padding cu 0
        std::fill(aesKey.begin() + key.size(), aesKey.end(), 0);
    }

    // Initializam cu AES-128-GCM pentru GMAC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return mac;
    }

    // Setam cheia
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, aesKey.data(), NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return mac;
    }

    // Pentru GMAC, folosim un IV de 12 bytes cu valoare zero
    unsigned char iv[12] = { 0 };
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return mac;
    }

    // Adaugam datele ca AAD (Additional Authenticated Data)
    int len;
    if (EVP_EncryptUpdate(ctx, NULL, &len,
        reinterpret_cast<const unsigned char*>(data.c_str()),
        data.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return mac;
    }

    // Finalizam fara a cripta nimic (doar calculam MAC-ul) 
    unsigned char dummy[1];
    if (EVP_EncryptFinal_ex(ctx, dummy, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return mac;
    }

    // Obtinem tag-ul (MAC-ul)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, mac.data()) != 1) {
        std::cerr << "Eroare la obtinerea tag-ului GMAC" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return mac;
    }

    EVP_CIPHER_CTX_free(ctx);
    return mac;
}

// Salveaza MAC-ul in format DER
bool KeyGenerator::saveMACToFile(int entityId, const std::string& keyType,
    const std::vector<unsigned char>& macValue) {
    std::string filename = getMACFilename(entityId, keyType);
    std::string pubKeyName = getPublicKeyFilename(entityId, keyType);

    // Obtine cheia MAC actuala pentru salvare
    std::vector<unsigned char> macKey = generateMACKey();

    // Creeaza structura ASN.1 pentru MAC
    // PubKeyMAC := Sequence {
    //   PubKeyName: PrintableString
    //   MACKey: OCTET STRING
    //   MACValue: OCTET STRING
    // }

    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Nu s-a putut crea fisierul " << filename << std::endl;
        return false;
    }

    // Scriem manual DER pentru simplitate
    std::vector<unsigned char> der;

    // SEQUENCE tag
    der.push_back(0x30); // SEQUENCE

    // Calculam lungimea totala (o vom completa mai tarziu)
    size_t seqLenPos = der.size();
    der.push_back(0); // placeholder pentru lungime

    // PubKeyName - PrintableString
    der.push_back(0x13); // PrintableString tag
    der.push_back(pubKeyName.length());
    der.insert(der.end(), pubKeyName.begin(), pubKeyName.end());

    // MACKey - OCTET STRING
    der.push_back(0x04); // OCTET STRING tag
    if (macKey.size() < 128) {
        der.push_back(macKey.size());
    }
    else {
        der.push_back(0x81); // long form
        der.push_back(macKey.size());
    }
    der.insert(der.end(), macKey.begin(), macKey.end());

    // MACValue - OCTET STRING
    der.push_back(0x04); // OCTET STRING tag
    der.push_back(macValue.size());
    der.insert(der.end(), macValue.begin(), macValue.end());

    // Actualizam lungimea secventei
    size_t totalLen = der.size() - seqLenPos - 1;
    if (totalLen < 128) {
        der[seqLenPos] = totalLen;
    }
    else {
        // Pentru lungimi mari, folosim forma lunga
        der[seqLenPos] = 0x81;
        der.insert(der.begin() + seqLenPos + 1, totalLen);
    }

    // Scriem in fisier
    file.write(reinterpret_cast<const char*>(der.data()), der.size());
    file.close();

    std::cout << "MAC salvat: " << filename << std::endl;
    return true;
}