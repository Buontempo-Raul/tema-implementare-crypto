#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

class KeyGenerator {
private:
    // Constante pentru criptare
    static const int EC_KEY_SIZE = 256;        // biti pentru curba eliptica
    static const int RSA_KEY_SIZE = 3072;      // biti pentru RSA
    static const int PBKDF2_ITERATIONS = 10000; // iteratii pentru PBKDF2

    // Structura pentru a pastra o pereche de chei
    struct KeyPair {
        EVP_PKEY* privateKey;
        EVP_PKEY* publicKey;

        KeyPair() : privateKey(nullptr), publicKey(nullptr) {}
        ~KeyPair() {
            if (privateKey) EVP_PKEY_free(privateKey);
            if (publicKey) EVP_PKEY_free(publicKey);
        }
    };

public:
    // Constructor si destructor
    KeyGenerator();
    ~KeyGenerator();

    // Metode publice pentru generarea cheilor
    bool generateECKeyPair(int entityId, const std::string& password);
    bool generateRSAKeyPair(int entityId, const std::string& password);

    // Metode pentru generarea MAC-urilor
    bool generateMAC(int entityId, const std::string& keyType); // keyType = "ecc" sau "rsa"

    // Metoda principala care genereaza toate cheile pentru o entitate
    bool generateAllKeysForEntity(int entityId, const std::string& password);

private:
    // Metode auxiliare pentru generarea cheilor
    EVP_PKEY* generateECKey();
    EVP_PKEY* generateRSAKey();

    // Metode pentru salvarea cheilor
    bool savePrivateKey(EVP_PKEY* key, const std::string& filename, const std::string& password);
    bool savePublicKey(EVP_PKEY* key, const std::string& filename);

    // Metode pentru calculul si salvarea MAC-urilor
    std::vector<unsigned char> calculateMAC(const std::string& data, const std::vector<unsigned char>& key);
    std::vector<unsigned char> generateMACKey();
    bool saveMACToFile(int entityId, const std::string& keyType, const std::vector<unsigned char>& macValue);

    // Metode auxiliare
    std::string getTimeDifference();  // Pentru calculul diferentei de timp pana la 050505050505Z
    std::vector<unsigned char> pbkdf2_sha3_256(const std::string& input, int iterations);

    // Utilitare pentru nume de fisiere
    std::string getPrivateKeyFilename(int entityId, const std::string& keyType);
    std::string getPublicKeyFilename(int entityId, const std::string& keyType);
    std::string getMACFilename(int entityId, const std::string& keyType);
};

#endif // KEY_GENERATOR_H