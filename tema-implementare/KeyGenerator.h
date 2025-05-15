#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include <string>
#include <vector>
#include <openssl/evp.h>

class KeyGenerator {
public:
    KeyGenerator();
    ~KeyGenerator();

    // Metode principale
    bool generateAllKeys(int entityId, const std::string& password);

private:
    // Generare chei
    bool generateECKeys(int entityId, const std::string& password);
    bool generateRSAKeys(int entityId, const std::string& password);

    // Generare MAC
    bool generateMAC(int entityId, const std::string& keyType);

    // Metode ajutatoare
    EVP_PKEY* createECKey();
    EVP_PKEY* createRSAKey();

    bool savePrivateKey(EVP_PKEY* key, const std::string& filename, const std::string& password);
    bool savePublicKey(EVP_PKEY* key, const std::string& filename);

    std::vector<unsigned char> calculateMAC(const std::string& data, const std::vector<unsigned char>& key);
    std::vector<unsigned char> generateMACKey();
    bool saveMACToFile(int entityId, const std::string& keyType, const std::vector<unsigned char>& macValue);

    // Utilitare
    std::string getPrivateKeyFile(int entityId, const std::string& keyType);
    std::string getPublicKeyFile(int entityId, const std::string& keyType);
    std::string getMACFile(int entityId, const std::string& keyType);
    std::string getTimeDifference();
};

#endif // KEY_GENERATOR_H