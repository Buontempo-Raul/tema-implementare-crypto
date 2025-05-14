#ifndef TRANSACTION_MANAGER_H
#define TRANSACTION_MANAGER_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <memory>

class TransactionManager {
private:
    // Structura pentru o tranzactie
    struct TransactionData {
        int transactionId;
        std::string subject;
        int senderId;
        int receiverId;
        int symElementsId;
        std::vector<unsigned char> encryptedData;
        std::vector<unsigned char> signature;
    };

    // Structura pentru elemente simetrice
    struct SymmetricElements {
        int symElementsId;
        std::vector<unsigned char> symKey;
        std::vector<unsigned char> iv;
    };

public:
    // Constructor si destructor
    TransactionManager();
    ~TransactionManager();

    // Metoda principala pentru procesarea unei tranzactii
    bool processTransaction(int transactionId, int senderId, int receiverId,
        const std::string& subject, const std::string& message,
        const std::string& senderPassword);

private:
    // Criptare AES-128-FancyOFB
    std::vector<unsigned char> encryptAESFancyOFB(const std::string& plaintext,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv);

    // Decriptare AES-128-FancyOFB
    std::string decryptAESFancyOFB(const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv);

    // Implementare FancyOFB cu xor inv_IV
    std::vector<unsigned char> fancyOFBEncrypt(const std::vector<unsigned char>& data,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv);

    // Implementare decriptare FancyOFB
    std::vector<unsigned char> fancyOFBDecrypt(const std::vector<unsigned char>& data,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv);

    // Semnare cu RSA
    std::vector<unsigned char> signWithRSA(const std::string& data,
        int entityId,
        const std::string& password);

    // Verificare semnatura RSA
    bool verifyRSASignature(const std::string& data,
        const std::vector<unsigned char>& signature,
        int entityId);

    // Incarcare elemente simetrice
    SymmetricElements loadSymmetricElements(int entityId);

    // Salvare tranzactie in format DER
    bool saveTransaction(const TransactionData& transaction);

    // Functii auxiliare
    std::string getTransactionFilename(int senderId, int receiverId, int transactionId);
    std::vector<unsigned char> invertIV(const std::vector<unsigned char>& iv);
    EVP_PKEY* loadRSAPrivateKey(int entityId, const std::string& password);
    EVP_PKEY* loadRSAPublicKey(int entityId);

    // Parsare DER pentru elemente simetrice
    bool parseSymmetricElementsDER(const std::vector<unsigned char>& der,
        SymmetricElements& elements);

    // Base64 encoding/decoding pentru fisiere .sym
    std::vector<unsigned char> base64Decode(const std::string& encoded);
};

#endif // TRANSACTION_MANAGER_H