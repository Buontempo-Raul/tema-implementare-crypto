#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include "Logger.h"
#include "TransactionManager.h"

// Constructor
TransactionManager::TransactionManager() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// Destructor
TransactionManager::~TransactionManager() {
    EVP_cleanup();
    ERR_free_strings();
}

// Procesare tranzactie principala
bool TransactionManager::processTransaction(int transactionId, int senderId, int receiverId,
    const std::string& subject, const std::string& message,
    const std::string& senderPassword) {
    std::cout << "\n=== Procesare tranzactie " << transactionId
        << " de la " << senderId << " catre " << receiverId << " ===" << std::endl;

    Logger::getInstance()->logAction(senderId, Logger::TRANSACTION,
        "Initiere tranzactie " + std::to_string(transactionId) +
        " catre " + std::to_string(receiverId));

    try {
        // 1. Incarca elementele simetrice pentru sender
        SymmetricElements symElements = loadSymmetricElements(senderId);
        if (symElements.symKey.empty() || symElements.iv.empty()) {
            std::cerr << "Nu s-au putut incarca elementele simetrice!" << std::endl;
            Logger::getInstance()->logAction(senderId, Logger::ERROR,
                "Eroare incarcare elemente simetrice pentru tranzactia " +
                std::to_string(transactionId));
            return false;
        }

        // 2. Cripteaza mesajul cu AES-128-FancyOFB
        std::vector<unsigned char> encryptedData = encryptAESFancyOFB(message,
            symElements.symKey,
            symElements.iv);

        // 3. Construieste datele pentru semnare (tot ce nu e semnatura)
        std::stringstream dataToSign;
        dataToSign << transactionId << subject << senderId << receiverId
            << symElements.symElementsId;
        dataToSign.write(reinterpret_cast<const char*>(encryptedData.data()),
            encryptedData.size());

        // 4. Semneaza cu cheia RSA
        std::vector<unsigned char> signature = signWithRSA(dataToSign.str(),
            senderId,
            senderPassword);
        if (signature.empty()) {
            std::cerr << "Eroare la semnarea tranzactiei!" << std::endl;
            Logger::getInstance()->logAction(senderId, Logger::ERROR,
                "Eroare semnare tranzactie " + std::to_string(transactionId));
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
            Logger::getInstance()->logAction(senderId, Logger::ERROR,
                "Eroare salvare tranzactie " + std::to_string(transactionId));
            return false;
        }

        std::cout << "Tranzactie procesata cu succes!" << std::endl;
        std::cout << "  Dimensiune mesaj original: " << message.size() << " bytes" << std::endl;
        std::cout << "  Dimensiune mesaj criptat: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "  Dimensiune semnatura: " << signature.size() << " bytes" << std::endl;

        Logger::getInstance()->logAction(senderId, Logger::TRANSACTION,
            "Tranzactie " + std::to_string(transactionId) + " procesata cu succes");
        Logger::getInstance()->logAction(receiverId, Logger::TRANSACTION,
            "Primita tranzactie " + std::to_string(transactionId) +
            " de la " + std::to_string(senderId));

        return true;

    }
    catch (const std::exception& e) {
        std::cerr << "Exceptie la procesarea tranzactiei: " << e.what() << std::endl;
        Logger::getInstance()->logAction(senderId, Logger::ERROR,
            "Exceptie tranzactie " + std::to_string(transactionId) + ": " + e.what());
        return false;
    }
}

// Criptare AES-128-FancyOFB
std::vector<unsigned char> TransactionManager::encryptAESFancyOFB(const std::string& plaintext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {
    // FancyOFB cu xor inv_IV in loc de +5
    std::vector<unsigned char> invIV = invertIV(iv);

    // Converteste plaintext la bytes
    std::vector<unsigned char> data(plaintext.begin(), plaintext.end());

    // Cripteaza cu FancyOFB
    return fancyOFBEncrypt(data, key, iv);
}

// Decriptare AES-128-FancyOFB
std::string TransactionManager::decryptAESFancyOFB(const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {
    // Decripteaza cu FancyOFB
    std::vector<unsigned char> decrypted = fancyOFBDecrypt(ciphertext, key, iv);

    // Converteste la string
    return std::string(decrypted.begin(), decrypted.end());
}

// Implementare FancyOFB modificat
std::vector<unsigned char> TransactionManager::fancyOFBEncrypt(const std::vector<unsigned char>& data,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> state(16);  // AES block size
    std::vector<unsigned char> keystream(16);
    std::vector<unsigned char> aes_output(16); // Output-ul AES inainte de XOR

    // Inverseaza IV-ul
    std::vector<unsigned char> invIV = invertIV(iv);

    // Initializeaza state cu IV
    std::copy(iv.begin(), iv.end(), state.begin());

    // Asigura ca avem o cheie de 16 bytes pentru AES-128
    std::vector<unsigned char> aesKey(16);
    if (key.size() >= 16) {
        std::copy(key.begin(), key.begin() + 16, aesKey.begin());
    }
    else {
        std::copy(key.begin(), key.end(), aesKey.begin());
        std::fill(aesKey.begin() + key.size(), aesKey.end(), 0);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Eroare la crearea contextului AES" << std::endl;
        return ciphertext;
    }

    // Configureaza AES-128 in mod ECB (pentru a cripta individual blocurile)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aesKey.data(), NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }

    // Dezactiveaza padding-ul
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Proceseaza datele pe blocuri
    for (size_t i = 0; i < data.size(); i += 16) {
        // Cripteaza state pentru a obtine output-ul AES
        int len;
        if (EVP_EncryptUpdate(ctx, aes_output.data(), &len, state.data(), 16) != 1) {
            break;
        }

        // Aplica operatia XOR inv_IV pentru a obtine keystream
        for (int j = 0; j < 16; j++) {
            keystream[j] = aes_output[j] ^ invIV[j];
        }

        // XOR cu datele pentru criptare
        size_t blockSize = std::min(size_t(16), data.size() - i);
        for (size_t j = 0; j < blockSize; j++) {
            ciphertext.push_back(data[i + j] ^ keystream[j]);
        }

        // Actualizeaza state pentru urmatorul bloc
        // State devine output-ul AES_encrypt (inainte de XOR cu inv_IV)
        std::copy(aes_output.begin(), aes_output.end(), state.begin());
    }

    // Handle ultimul bloc daca nu e multiplu de 16
    if (data.size() % 16 != 0) {
        // Cripta un ultim bloc pentru padding
        int len;
        if (EVP_EncryptUpdate(ctx, aes_output.data(), &len, state.data(), 16) == 1) {
            // Aplica operatia XOR inv_IV
            for (int j = 0; j < 16; j++) {
                keystream[j] = aes_output[j] ^ invIV[j];
            }

            // XOR cu restul datelor
            size_t remainingBytes = data.size() % 16;
            size_t offset = data.size() - remainingBytes;
            for (size_t j = 0; j < remainingBytes; j++) {
                ciphertext.push_back(data[offset + j] ^ keystream[j]);
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// Implementare decriptare FancyOFB
std::vector<unsigned char> TransactionManager::fancyOFBDecrypt(const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {
    // Pentru OFB, decriptarea este identica cu criptarea
    // Doar aplicam XOR intre ciphertext si keystream
    return fancyOFBEncrypt(ciphertext, key, iv);
}

// Semneaza datele cu cheia RSA privata
std::vector<unsigned char> TransactionManager::signWithRSA(const std::string& data,
    int entityId,
    const std::string& password) {
    std::vector<unsigned char> signature;

    // Incarca cheia privata RSA
    EVP_PKEY* rsaKey = loadRSAPrivateKey(entityId, password);
    if (!rsaKey) {
        std::cerr << "Nu s-a putut incarca cheia RSA privata!" << std::endl;
        return signature;
    }

    // Creeaza context pentru semnare
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(rsaKey);
        return signature;
    }

    // Initializeaza semnarea cu SHA256
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, rsaKey) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsaKey);
        return signature;
    }

    // Adauga datele
    if (EVP_DigestSignUpdate(mdctx, data.c_str(), data.length()) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsaKey);
        return signature;
    }

    // Determina lungimea semnaturii
    size_t sigLen;
    if (EVP_DigestSignFinal(mdctx, NULL, &sigLen) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsaKey);
        return signature;
    }

    signature.resize(sigLen);

    // Genereaza semnatura
    if (EVP_DigestSignFinal(mdctx, signature.data(), &sigLen) != 1) {
        signature.clear();
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(rsaKey);

    return signature;
}

// Incarca elementele simetrice din fisier
TransactionManager::SymmetricElements TransactionManager::loadSymmetricElements(int entityId) {
    SymmetricElements elements;
    elements.symElementsId = 0;

    std::string filename = "id" + std::to_string(entityId) + ".sym";
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Nu s-a putut deschide fisierul " << filename << std::endl;
        return elements;
    }

    // Citeste continutul base64
    std::string base64Content((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
    file.close();

    // Decodifica din base64
    std::vector<unsigned char> derContent = base64Decode(base64Content);

    // Parseaza DER
    if (!parseSymmetricElementsDER(derContent, elements)) {
        std::cerr << "Eroare la parsarea elementelor simetrice!" << std::endl;
    }

    return elements;
}

// Parseaza DER pentru elemente simetrice
bool TransactionManager::parseSymmetricElementsDER(const std::vector<unsigned char>& der,
    SymmetricElements& elements) {
    if (der.size() < 10) return false;

    size_t pos = 0;

    // SEQUENCE tag
    if (der[pos++] != 0x30) return false;
    size_t seqLen = der[pos++];

    // SymElementsID - INTEGER
    if (der[pos++] != 0x02) return false;
    size_t idLen = der[pos++];

    elements.symElementsId = 0;
    for (size_t i = 0; i < idLen; i++) {
        elements.symElementsId = (elements.symElementsId << 8) | der[pos++];
    }

    // SymKey - OCTET STRING
    if (der[pos++] != 0x04) return false;
    size_t keyLen = der[pos++];
    elements.symKey.assign(der.begin() + pos, der.begin() + pos + keyLen);
    pos += keyLen;

    // IV - OCTET STRING
    if (der[pos++] != 0x04) return false;
    size_t ivLen = der[pos++];
    elements.iv.assign(der.begin() + pos, der.begin() + pos + ivLen);

    return true;
}

// Salveaza tranzactia in format DER
bool TransactionManager::saveTransaction(const TransactionData& transaction) {
    std::string filename = getTransactionFilename(transaction.senderId,
        transaction.receiverId,
        transaction.transactionId);

    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Nu s-a putut crea fisierul " << filename << std::endl;
        return false;
    }

    // Construieste DER manual
    std::vector<unsigned char> der;

    // SEQUENCE tag
    der.push_back(0x30);
    size_t seqLenPos = der.size();
    der.push_back(0); // placeholder - vom actualiza mai tarziu

    // TransactionID - INTEGER
    der.push_back(0x02);
    std::vector<unsigned char> idBytes;
    int id = transaction.transactionId;
    while (id > 0) {
        idBytes.insert(idBytes.begin(), id & 0xFF);
        id >>= 8;
    }
    if (idBytes.empty()) idBytes.push_back(0);
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
    if (idBytes.empty()) idBytes.push_back(0);
    der.push_back(idBytes.size());
    der.insert(der.end(), idBytes.begin(), idBytes.end());

    // EncryptedData - OCTET STRING
    der.push_back(0x04);
    // Tratare lung form pentru lungimi mari
    if (transaction.encryptedData.size() < 128) {
        der.push_back(transaction.encryptedData.size());
    }
    else if (transaction.encryptedData.size() < 256) {
        der.push_back(0x81); // long form cu 1 byte
        der.push_back(transaction.encryptedData.size());
    }
    else {
        der.push_back(0x82); // long form cu 2 bytes
        der.push_back((transaction.encryptedData.size() >> 8) & 0xFF);
        der.push_back(transaction.encryptedData.size() & 0xFF);
    }
    der.insert(der.end(), transaction.encryptedData.begin(), transaction.encryptedData.end());

    // TransactionSign - OCTET STRING
    der.push_back(0x04);
    // Tratare lung form pentru lungimi mari (semnatura RSA 3072-bit = 384 bytes)
    if (transaction.signature.size() < 128) {
        der.push_back(transaction.signature.size());
    }
    else if (transaction.signature.size() < 256) {
        der.push_back(0x81); // long form cu 1 byte
        der.push_back(transaction.signature.size());
    }
    else {
        der.push_back(0x82); // long form cu 2 bytes
        der.push_back((transaction.signature.size() >> 8) & 0xFF);
        der.push_back(transaction.signature.size() & 0xFF);
    }
    der.insert(der.end(), transaction.signature.begin(), transaction.signature.end());

    // Actualizeaza lungimea totala a secventei
    size_t totalLen = der.size() - seqLenPos - 1;
    if (totalLen < 128) {
        der[seqLenPos] = totalLen;
    }
    else if (totalLen < 256) {
        // Long form cu 1 byte
        der[seqLenPos] = 0x81;
        der.insert(der.begin() + seqLenPos + 1, totalLen);
    }
    else {
        // Long form cu 2 bytes  
        der[seqLenPos] = 0x82;
        der.insert(der.begin() + seqLenPos + 1, (totalLen >> 8) & 0xFF);
        der.insert(der.begin() + seqLenPos + 2, totalLen & 0xFF);
    }

    // Scrie in fisier
    file.write(reinterpret_cast<const char*>(der.data()), der.size());
    file.close();

    std::cout << "Tranzactie salvata: " << filename << std::endl;
    return true;
}

// Nume fisier pentru tranzactie
std::string TransactionManager::getTransactionFilename(int senderId, int receiverId, int transactionId) {
    return "id" + std::to_string(senderId) + "_id" + std::to_string(receiverId) +
        "_tr" + std::to_string(transactionId) + ".trx";
}

// Inverseaza un IV
std::vector<unsigned char> TransactionManager::invertIV(const std::vector<unsigned char>& iv) {
    std::vector<unsigned char> inverted(iv.rbegin(), iv.rend());
    return inverted;
}

// Incarca cheia privata RSA
EVP_PKEY* TransactionManager::loadRSAPrivateKey(int entityId, const std::string& password) {
    std::string filename = "id" + std::to_string(entityId) + "_priv.rsa";

    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) {
        std::cerr << "Nu s-a putut deschide fisierul " << filename << std::endl;
        return nullptr;
    }

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*)password.c_str());
    BIO_free(bio);

    if (!key) {
        std::cerr << "Eroare la citirea cheii private RSA din " << filename << std::endl;
    }

    return key;
}

// Decodare Base64
std::vector<unsigned char> TransactionManager::base64Decode(const std::string& encoded) {
    std::vector<unsigned char> decoded;

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(encoded.c_str(), encoded.length());
    BIO_push(b64, mem);

    // Pentru fisiere cu newlines
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