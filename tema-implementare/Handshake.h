#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <string>
#include <vector>
#include <openssl/evp.h>

class Handshake {
public:
    Handshake();
    ~Handshake();

    bool performHandshake(int entityId1, int entityId2,
        const std::string& password1,
        const std::string& password2);

    bool generateSymmetricElementsForTransaction(int transactionId,
        int senderId, int receiverId,
        const std::string& senderPassword);

private:
    struct SymmetricElements {
        std::vector<unsigned char> symKey;
        std::vector<unsigned char> iv;
        int symElementsId;
    };

    bool verifyMAC(int entityId, const std::string& keyType);

    EVP_PKEY* loadPrivateKey(int entityId, const std::string& keyType,
        const std::string& password);
    EVP_PKEY* loadPublicKey(int entityId, const std::string& keyType);

    std::vector<unsigned char> doECDH(EVP_PKEY* privateKey, EVP_PKEY* publicKey);

    SymmetricElements deriveSymmetricKey(const std::vector<unsigned char>& sharedSecret);
    bool saveSymmetricElements(const SymmetricElements& elements, int entityId);

    std::vector<unsigned char> sha256(const std::vector<unsigned char>& data);
    std::vector<unsigned char> pbkdf2_sha384(const std::vector<unsigned char>& data);
    std::vector<unsigned char> xorBytes(const std::vector<unsigned char>& a,
        const std::vector<unsigned char>& b);
    std::vector<unsigned char> generateIV();
};

#endif 