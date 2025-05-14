#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>

class Handshake {
private:
    // Structura pentru elementele simetrice derivate
    struct SymmetricElements {
        std::vector<unsigned char> symKey;    // 16 bytes
        std::vector<unsigned char> iv;        // IV pentru AES
        int symElementsId;
    };

    // Structura pentru stocarea unui handshake
    struct HandshakeData {
        int entityId1;
        int entityId2;
        std::vector<unsigned char> sharedSecret;
        SymmetricElements symElements;
    };

public:
    // Constructor si destructor
    Handshake();
    ~Handshake();

    // Metoda principala pentru realizarea handshake-ului
    bool performHandshake(int entityId1, int entityId2,
        const std::string& password1,
        const std::string& password2);

    // Metode pentru verificarea si incarcarea cheilor
    bool verifyKeyAuthenticity(int entityId, const std::string& keyType);

private:
    // Metode pentru ECDH
    EVP_PKEY* loadPrivateKey(int entityId, const std::string& keyType,
        const std::string& password);
    EVP_PKEY* loadPublicKey(int entityId, const std::string& keyType);

    // Realizarea efectiva a schimbului de chei ECDH
    std::vector<unsigned char> performECDH(EVP_PKEY* privateKey,
        EVP_PKEY* publicKey);

    // Derivarea cheii simetrice conform cerintelor
    SymmetricElements deriveSymmetricKey(const std::vector<unsigned char>& sharedSecret);

    // Metode auxiliare pentru derivare
    std::vector<unsigned char> deriveSymLeft(const std::vector<unsigned char>& x);
    std::vector<unsigned char> deriveSymRight(const std::vector<unsigned char>& y);

    // Salvarea elementelor simetrice
    bool saveSymmetricElements(const SymmetricElements& elements,
        int entityId1, int entityId2);

    // Salvarea elementelor simetrice pentru o entitate
    bool saveSymmetricElementsForEntity(const SymmetricElements& elements,
        int entityId);

    // Verificare MAC
    bool verifyMAC(int entityId, const std::string& keyType);

    // Calculeaza MAC-ul pentru verificare
    std::vector<unsigned char> calculateMAC(const std::string& data,
        const std::vector<unsigned char>& key);

    // Utilitare
    std::string getSymmetricElementsFilename(int entityId);
    std::vector<unsigned char> xorVectors(const std::vector<unsigned char>& a,
        const std::vector<unsigned char>& b);

    // Pentru extragerea componentelor x si y din punctul EC
    bool extractECPointComponents(EVP_PKEY* key,
        std::vector<unsigned char>& x,
        std::vector<unsigned char>& y);

    // Pentru extragerea componentelor x si y din secretul partajat ECDH
    bool extractECDHSharedSecretComponents(const std::vector<unsigned char>& sharedSecret,
        std::vector<unsigned char>& x,
        std::vector<unsigned char>& y);

    // Metoda pentru calculul timpului pana la 050505050505Z
    std::string getTimeDifference();

    // PBKDF2 cu SHA3-256 pentru generarea cheii MAC
    std::vector<unsigned char> pbkdf2_sha3_256(const std::string& input, int iterations);

    // Generare IV pentru AES
    std::vector<unsigned char> generateIV();
};

#endif // HANDSHAKE_H