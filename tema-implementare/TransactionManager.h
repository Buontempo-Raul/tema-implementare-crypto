#ifndef TRANSACTION_MANAGER_H
#define TRANSACTION_MANAGER_H

#include <string>
#include <vector>
#include <openssl/evp.h>

class TransactionManager {
public:
    TransactionManager();
    ~TransactionManager();

    bool processTransaction(int transactionId, int senderId, int receiverId,
        const std::string& subject, const std::string& message,
        const std::string& senderPassword);

private:
    struct SymmetricElements {
        int symElementsId;
        std::vector<unsigned char> symKey;
        std::vector<unsigned char> iv;
    };

    struct TransactionData {
        int transactionId;
        std::string subject;
        int senderId;
        int receiverId;
        int symElementsId;
        std::vector<unsigned char> encryptedData;
        std::vector<unsigned char> signature;
    };

    std::vector<unsigned char> encryptFancyOFB(const std::string& plaintext,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv);

    std::vector<unsigned char> signWithRSA(const std::vector<unsigned char>& data,
        int entityId,
        const std::string& password);

    SymmetricElements loadSymmetricElements(int entityId);
    bool saveTransaction(const TransactionData& transaction);

    std::vector<unsigned char> createTransactionToSignDER(
        int transactionId, const std::string& subject, int senderId, int receiverId,
        int symElementsId, const std::vector<unsigned char>& encryptedData);

    std::vector<unsigned char> encodeInteger(int value);
    void encodeLengthAndData(std::vector<unsigned char>& der,
        unsigned char tag, const std::vector<unsigned char>& data);
    void updateSequenceLength(std::vector<unsigned char>& der, size_t lenPos);

    std::vector<unsigned char> invertIV(const std::vector<unsigned char>& iv);
    EVP_PKEY* loadRSAPrivateKey(int entityId, const std::string& password);
    std::vector<unsigned char> base64Decode(const std::string& encoded);
};

#endif // TRANSACTION_MANAGER_H