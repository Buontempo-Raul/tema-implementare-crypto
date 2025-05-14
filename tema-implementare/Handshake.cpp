#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <iomanip>
#include "Logger.h"
#include "Handshake.h"


#ifdef OPENSSL_VERSION_MAJOR
#if OPENSSL_VERSION_MAJOR >= 3
#define OPENSSL_SUPPRESS_DEPRECATED
#pragma warning(disable : 4996)
#endif
#endif

// Constructor
Handshake::Handshake() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// Destructor
Handshake::~Handshake() {
    EVP_cleanup();
    ERR_free_strings();
}

// Metoda principala pentru realizarea handshake-ului
bool Handshake::performHandshake(int entityId1, int entityId2,
    const std::string& password1,
    const std::string& password2) {
    std::cout << "\n=== Realizare handshake intre entitatea " << entityId1
        << " si entitatea " << entityId2 << " ===" << std::endl;

    // 1. Verifica autenticitatea cheilor
    std::cout << "Verificare autenticitate chei..." << std::endl;
    if (!verifyKeyAuthenticity(entityId1, "ecc") ||
        !verifyKeyAuthenticity(entityId2, "ecc")) {
        std::cerr << "Autenticitatea cheilor nu a putut fi verificata!" << std::endl;
        Logger::getInstance()->logAction(entityId1, Logger::ERROR,
            "Eroare verificare autenticitate chei pentru handshake cu " + std::to_string(entityId2));
        return false;
    }

    // 2. Incarca cheile pentru ambele entitati
    std::cout << "Incarcare chei..." << std::endl;
    EVP_PKEY* privateKey1 = loadPrivateKey(entityId1, "ecc", password1);
    EVP_PKEY* publicKey1 = loadPublicKey(entityId1, "ecc");
    EVP_PKEY* privateKey2 = loadPrivateKey(entityId2, "ecc", password2);
    EVP_PKEY* publicKey2 = loadPublicKey(entityId2, "ecc");

    if (!privateKey1 || !publicKey1 || !privateKey2 || !publicKey2) {
        std::cerr << "Eroare la incarcarea cheilor!" << std::endl;
        if (privateKey1) EVP_PKEY_free(privateKey1);
        if (publicKey1) EVP_PKEY_free(publicKey1);
        if (privateKey2) EVP_PKEY_free(privateKey2);
        if (publicKey2) EVP_PKEY_free(publicKey2);
        return false;
    }

    // 3. Realizeaza ECDH in ambele directii
    std::cout << "Realizare schimb de chei ECDH..." << std::endl;

    // ECDH pentru entitatea 1 (foloseste cheia sa privata + cheia publica a entitatii 2)
    std::vector<unsigned char> sharedSecret1 = performECDH(privateKey1, publicKey2);

    // ECDH pentru entitatea 2 (foloseste cheia sa privata + cheia publica a entitatii 1)
    std::vector<unsigned char> sharedSecret2 = performECDH(privateKey2, publicKey1);

    if (sharedSecret1.empty() || sharedSecret2.empty()) {
        std::cerr << "Eroare la realizarea ECDH!" << std::endl;
        EVP_PKEY_free(privateKey1);
        EVP_PKEY_free(publicKey1);
        EVP_PKEY_free(privateKey2);
        EVP_PKEY_free(publicKey2);
        return false;
    }

    // Verifica ca ambele secrete partajate sunt identice (proprietatea ECDH)
    if (sharedSecret1.size() != sharedSecret2.size() ||
        memcmp(sharedSecret1.data(), sharedSecret2.data(), sharedSecret1.size()) != 0) {
        std::cerr << "Eroare: Secretele partajate ECDH nu sunt identice!" << std::endl;
        EVP_PKEY_free(privateKey1);
        EVP_PKEY_free(publicKey1);
        EVP_PKEY_free(privateKey2);
        EVP_PKEY_free(publicKey2);
        return false;
    }

    // 4. Deriveaza elementele simetrice pentru fiecare entitate
    std::cout << "Derivare cheie simetrica..." << std::endl;

    // Pentru entitatea 1
    SymmetricElements symElements1 = deriveSymmetricKey(sharedSecret1);
    symElements1.symElementsId = entityId1 * 10000 + entityId2;

    // Pentru entitatea 2  
    SymmetricElements symElements2 = deriveSymmetricKey(sharedSecret2);
    symElements2.symElementsId = entityId2 * 10000 + entityId1;

    // 5. Salveaza elementele simetrice separate pentru fiecare entitate
    std::cout << "Salvare elemente simetrice..." << std::endl;
    bool success = saveSymmetricElementsForEntity(symElements1, entityId1) &&
        saveSymmetricElementsForEntity(symElements2, entityId2);

    // Cleanup
    EVP_PKEY_free(privateKey1);
    EVP_PKEY_free(publicKey1);
    EVP_PKEY_free(privateKey2);
    EVP_PKEY_free(publicKey2);

    if (success) {
        std::cout << "Handshake realizat cu succes!" << std::endl;
        Logger::getInstance()->logAction(entityId1, Logger::HANDSHAKE,
            "Handshake realizat cu entitatea " + std::to_string(entityId2));
        Logger::getInstance()->logAction(entityId2, Logger::HANDSHAKE,
            "Handshake realizat cu entitatea " + std::to_string(entityId1));
    }

    return success;
}

// Verifica autenticitatea unei chei folosind MAC-ul salvat
bool Handshake::verifyKeyAuthenticity(int entityId, const std::string& keyType) {
    bool result = verifyMAC(entityId, keyType);

    if (result) {
        Logger::getInstance()->logAction(entityId, Logger::MAC_VERIFICATION,
            "MAC verificat pentru cheia " + keyType);
    }
    else {
        Logger::getInstance()->logAction(entityId, Logger::ERROR,
            "Eroare verificare MAC pentru cheia " + keyType);
    }

    return result;
}

// Incarca o cheie privata criptata
EVP_PKEY* Handshake::loadPrivateKey(int entityId, const std::string& keyType,
    const std::string& password) {
    std::string filename = "id" + std::to_string(entityId) + "_priv." + keyType;

    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) {
        std::cerr << "Nu s-a putut deschide fisierul " << filename << std::endl;
        return nullptr;
    }

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*)password.c_str());
    BIO_free(bio);

    if (!key) {
        std::cerr << "Eroare la citirea cheii private din " << filename << std::endl;
    }

    return key;
}

// Incarca o cheie publica
EVP_PKEY* Handshake::loadPublicKey(int entityId, const std::string& keyType) {
    std::string filename = "id" + std::to_string(entityId) + "_pub." + keyType;

    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (!bio) {
        std::cerr << "Nu s-a putut deschide fisierul " << filename << std::endl;
        return nullptr;
    }

    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!key) {
        std::cerr << "Eroare la citirea cheii publice din " << filename << std::endl;
    }

    return key;
}

// Realizeaza schimbul de chei ECDH
std::vector<unsigned char> Handshake::performECDH(EVP_PKEY* privateKey,
    EVP_PKEY* publicKey) {
    std::vector<unsigned char> sharedSecret;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx) {
        std::cerr << "Eroare la crearea contextului ECDH" << std::endl;
        return sharedSecret;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        std::cerr << "Eroare la initializarea ECDH" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return sharedSecret;
    }

    if (EVP_PKEY_derive_set_peer(ctx, publicKey) <= 0) {
        std::cerr << "Eroare la setarea peer-ului ECDH" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return sharedSecret;
    }

    // Determina lungimea secretului partajat
    size_t secretLen;
    if (EVP_PKEY_derive(ctx, NULL, &secretLen) <= 0) {
        std::cerr << "Eroare la determinarea lungimii secretului" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return sharedSecret;
    }

    sharedSecret.resize(secretLen);

    // Deriva secretul partajat
    if (EVP_PKEY_derive(ctx, sharedSecret.data(), &secretLen) <= 0) {
        std::cerr << "Eroare la derivarea secretului partajat" << std::endl;
        sharedSecret.clear();
    }

    EVP_PKEY_CTX_free(ctx);
    return sharedSecret;
}

// Extrage componentele x si y dintr-un punct EC
bool Handshake::extractECPointComponents(EVP_PKEY* key,
    std::vector<unsigned char>& x,
    std::vector<unsigned char>& y) {
    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(key);
    if (!ecKey) {
        std::cerr << "Nu s-a putut obtine cheia EC" << std::endl;
        return false;
    }

    const EC_POINT* publicPoint = EC_KEY_get0_public_key(ecKey);
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);

    if (!publicPoint || !group) {
        EC_KEY_free(ecKey);
        return false;
    }

    BIGNUM* xBN = BN_new();
    BIGNUM* yBN = BN_new();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (!EC_POINT_get_affine_coordinates_GFp(group, publicPoint, xBN, yBN, NULL)) {
#else
    if (!EC_POINT_get_affine_coordinates(group, publicPoint, xBN, yBN, NULL)) {
#endif
        BN_free(xBN);
        BN_free(yBN);
        EC_KEY_free(ecKey);
        return false;
    }

    // Converteste BIGNUM la vector de bytes
    int xLen = BN_num_bytes(xBN);
    int yLen = BN_num_bytes(yBN);

    x.resize(xLen);
    y.resize(yLen);

    BN_bn2bin(xBN, x.data());
    BN_bn2bin(yBN, y.data());

    BN_free(xBN);
    BN_free(yBN);
    EC_KEY_free(ecKey);

    return true;
    }

// Extrage componentele x si y din secretul partajat ECDH
bool Handshake::extractECDHSharedSecretComponents(const std::vector<unsigned char>&sharedSecret,
    std::vector<unsigned char>&x,
    std::vector<unsigned char>&y) {
    // Pentru P-256, secretul partajat este coordonata x a punctului rezultat
    // Are 32 bytes pentru P-256

    if (sharedSecret.size() != 32) {
        std::cerr << "Dimensiune invalida pentru secretul partajat: " << sharedSecret.size() << std::endl;
        // Pentru compatibilitate, impartim secretul in doua jumatati
        size_t halfLen = sharedSecret.size() / 2;
        x.assign(sharedSecret.begin(), sharedSecret.begin() + halfLen);
        y.assign(sharedSecret.begin() + halfLen, sharedSecret.end());
        return true;
    }

    // Pentru ECDH standard, secretul partajat este doar coordonata x
    x = sharedSecret;

    // Pentru y, vom folosi un hash al lui x
    y.resize(32);
    SHA256(x.data(), x.size(), y.data());

    return true;
}

// Deriveaza cheia simetrica conform cerintelor
Handshake::SymmetricElements Handshake::deriveSymmetricKey(
    const std::vector<unsigned char>&sharedSecret) {
    SymmetricElements elements;

    // Extrage componentele x si y din secretul partajat
    std::vector<unsigned char> x, y;
    extractECDHSharedSecretComponents(sharedSecret, x, y);

    // Deriva SymLeft si SymRight
    std::vector<unsigned char> symLeft = deriveSymLeft(x);
    std::vector<unsigned char> symRight = deriveSymRight(y);

    // SymKey = SymLeft XOR First_16_bytes(SymRight)
    std::vector<unsigned char> first16(symRight.begin(), symRight.begin() + 16);
    elements.symKey = xorVectors(symLeft, first16);

    // Restul octetilor din SymRight sunt folositi pentru IV si alte elemente
    if (symRight.size() > 16) {
        elements.iv = std::vector<unsigned char>(symRight.begin() + 16,
            symRight.begin() + 32);
    }
    else {
        // Genereaza IV daca nu sunt suficienti octeti
        elements.iv = generateIV();
    }

    // Asiguram ca cheia are exact 16 bytes pentru AES-128
    if (elements.symKey.size() > 16) {
        elements.symKey.resize(16);
    }

    return elements;
}

// Deriveaza SymLeft aplicand SHA-256 si XOR
std::vector<unsigned char> Handshake::deriveSymLeft(const std::vector<unsigned char>&x) {
    // Aplica SHA-256 peste x
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(x.data(), x.size(), hash.data());

    // Imparte in 2 elemente de 16 octeti si face XOR
    std::vector<unsigned char> part1(hash.begin(), hash.begin() + 16);
    std::vector<unsigned char> part2(hash.begin() + 16, hash.end());

    return xorVectors(part1, part2);
}

// Deriveaza SymRight folosind PBKDF2 cu SHA-384
std::vector<unsigned char> Handshake::deriveSymRight(const std::vector<unsigned char>&y) {
    std::vector<unsigned char> key(48); // SHA-384 produce 48 bytes

    // PBKDF2 cu SHA-384, fara salt
    int result = PKCS5_PBKDF2_HMAC(
        reinterpret_cast<const char*>(y.data()), y.size(),
        nullptr, 0,  // fara salt
        10000,       // iteratii
        EVP_sha384(),
        key.size(), key.data()
    );

    if (result != 1) {
        std::cerr << "Eroare la derivarea SymRight" << std::endl;
    }

    return key;
}

// Salveaza elementele simetrice in format DER codat Base64
bool Handshake::saveSymmetricElements(const SymmetricElements & elements,
    int entityId1, int entityId2) {
    // DEPRECATED - Aceasta metoda nu mai trebuie folosita
    // Folositi saveSymmetricElementsForEntity() in schimb
    return saveSymmetricElementsForEntity(elements, entityId1) &&
        saveSymmetricElementsForEntity(elements, entityId2);
}

// Salveaza elementele simetrice pentru o singura entitate
bool Handshake::saveSymmetricElementsForEntity(const SymmetricElements & elements,
    int entityId) {
    std::string filename = getSymmetricElementsFilename(entityId);

    // Creeaza structura DER
    // SymElements := Sequence {
    //   SymElementsID: Integer
    //   SymKey: OCTET STRING
    //   IV: OCTET STRING
    // }

    std::vector<unsigned char> der;

    // SEQUENCE tag
    der.push_back(0x30);
    size_t seqLenPos = der.size();
    der.push_back(0); // placeholder pentru lungime

    // SymElementsID - INTEGER
    der.push_back(0x02); // INTEGER tag

    // Encode integer value
    std::vector<unsigned char> idBytes;
    int id = elements.symElementsId;
    while (id > 0) {
        idBytes.insert(idBytes.begin(), id & 0xFF);
        id >>= 8;
    }
    if (idBytes.empty()) idBytes.push_back(0);

    der.push_back(idBytes.size());
    der.insert(der.end(), idBytes.begin(), idBytes.end());

    // SymKey - OCTET STRING
    der.push_back(0x04);
    der.push_back(elements.symKey.size());
    der.insert(der.end(), elements.symKey.begin(), elements.symKey.end());

    // IV - OCTET STRING
    der.push_back(0x04);
    der.push_back(elements.iv.size());
    der.insert(der.end(), elements.iv.begin(), elements.iv.end());

    // Actualizeaza lungimea
    size_t totalLen = der.size() - seqLenPos - 1;
    der[seqLenPos] = totalLen;

    // Codeaza in Base64
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);

    BIO_write(b64, der.data(), der.size());
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string base64Data(bptr->data, bptr->length);

    BIO_free_all(b64);

    // Salveaza in fisier
    std::ofstream file(filename);
    if (!file) {
        std::cerr << "Eroare la crearea fisierului " << filename << std::endl;
        return false;
    }

    file << base64Data;
    file.close();

    std::cout << "Elemente simetrice salvate: " << filename << std::endl;
    return true;
}

// Verifica MAC-ul unei chei
bool Handshake::verifyMAC(int entityId, const std::string & keyType) {
    std::cout << "Verificare MAC pentru cheia " << keyType << " a entitatii " << entityId << std::endl;

    // 1. Citeste cheia publica
    std::string publicKeyFile = "id" + std::to_string(entityId) + "_pub." + keyType;
    std::ifstream keyFile(publicKeyFile, std::ios::binary);
    if (!keyFile) {
        std::cerr << "Nu s-a putut deschide fisierul " << publicKeyFile << std::endl;
        return false;
    }

    std::string keyContent((std::istreambuf_iterator<char>(keyFile)),
        std::istreambuf_iterator<char>());
    keyFile.close();

    // 2. Citeste MAC-ul salvat
    std::string macFile = "id" + std::to_string(entityId) + "_" + keyType + ".mac";
    std::ifstream macFileIn(macFile, std::ios::binary);
    if (!macFileIn) {
        std::cerr << "Nu s-a putut deschide fisierul " << macFile << std::endl;
        return false;
    }

    // Citeste tot continutul DER
    std::vector<unsigned char> derContent((std::istreambuf_iterator<char>(macFileIn)),
        std::istreambuf_iterator<char>());
    macFileIn.close();

    // 3. Parseaza DER pentru a extrage MAC-ul salvat si cheia MAC
    std::vector<unsigned char> storedMacValue;
    std::vector<unsigned char> storedMacKey;

    // Parsare simplificata DER
    size_t pos = 0;

    if (pos >= derContent.size() || derContent[pos] != 0x30) {
        std::cerr << "Format DER invalid - nu incepe cu SEQUENCE" << std::endl;
        return false;
    }
    pos++; // Tag SEQUENCE

    // Lungimea secventei
    size_t seqLen = derContent[pos++];
    if (seqLen > 127) {
        // Long form
        seqLen = derContent[pos++];
    }

    // PubKeyName - PrintableString
    if (pos >= derContent.size() || derContent[pos] != 0x13) {
        std::cerr << "Format DER invalid - nu gasesc PrintableString" << std::endl;
        return false;
    }
    pos++; // Tag PrintableString
    size_t nameLen = derContent[pos++];
    pos += nameLen; // Sari peste nume

    // MACKey - OCTET STRING
    if (pos >= derContent.size() || derContent[pos] != 0x04) {
        std::cerr << "Format DER invalid - nu gasesc MACKey" << std::endl;
        return false;
    }
    pos++; // tag OCTET STRING
    size_t keyLen = derContent[pos++];
    if (keyLen > 127) {
        // Long form
        keyLen = derContent[pos++];
    }

    if (pos + keyLen > derContent.size()) {
        std::cerr << "Format DER invalid - MACKey depaseste limitele" << std::endl;
        return false;
    }

    storedMacKey.assign(derContent.begin() + pos, derContent.begin() + pos + keyLen);
    pos += keyLen;

    // MACValue - OCTET STRING  
    if (pos >= derContent.size() || derContent[pos] != 0x04) {
        std::cerr << "Format DER invalid - nu gasesc MACValue" << std::endl;
        return false;
    }
    pos++; // tag OCTET STRING
    size_t valueLen = derContent[pos++];

    if (pos + valueLen > derContent.size()) {
        std::cerr << "Format DER invalid - MACValue depaseste limitele" << std::endl;
        return false;
    }

    storedMacValue.assign(derContent.begin() + pos, derContent.begin() + pos + valueLen);

    // 4. Recalculeaza MAC-ul folosind cheia MAC din DER
    std::vector<unsigned char> calculatedMac = calculateMAC(keyContent, storedMacKey);

    // 5. Debug - afiseaza valorile
    std::cout << "Lungime cheie MAC stocata: " << storedMacKey.size() << std::endl;
    std::cout << "Lungime MAC stocat: " << storedMacValue.size() << std::endl;
    std::cout << "Lungime MAC calculat: " << calculatedMac.size() << std::endl;

    // 6. Compara valorile
    if (calculatedMac.size() != storedMacValue.size()) {
        std::cerr << "Dimensiuni diferite de MAC!" << std::endl;
        return false;
    }

    bool valid = true;
    for (size_t i = 0; i < calculatedMac.size(); i++) {
        if (calculatedMac[i] != storedMacValue[i]) {
            valid = false;
            break;
        }
    }

    if (valid) {
        std::cout << "MAC valid pentru cheia " << keyType << " a entitatii " << entityId << std::endl;
    }
    else {
        std::cerr << "MAC invalid pentru cheia " << keyType << " a entitatii " << entityId << std::endl;

        // Debug - afiseaza primii 8 bytes
        std::cout << "MAC stocat (primii 8 bytes): ";
        for (size_t i = 0; i < 8 && i < storedMacValue.size(); i++) {
            std::cout << std::hex << (int)storedMacValue[i] << " ";
        }
        std::cout << std::dec << std::endl;

        std::cout << "MAC calculat (primii 8 bytes): ";
        for (size_t i = 0; i < 8 && i < calculatedMac.size(); i++) {
            std::cout << std::hex << (int)calculatedMac[i] << " ";
        }
        std::cout << std::dec << std::endl;
    }

    return valid;
}

// Calculeaza MAC folosind GMAC (AES-GCM authentication tag)
std::vector<unsigned char> Handshake::calculateMAC(const std::string & data,
    const std::vector<unsigned char>&key) {
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

// Calculeaza diferenta de timp pana la 050505050505Z
std::string Handshake::getTimeDifference() {
    // Data target: 5 Mai 2005, 05:05:05 UTC  
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

// Implementare PBKDF2 cu SHA3-256
std::vector<unsigned char> Handshake::pbkdf2_sha3_256(const std::string & input, int iterations) {
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

// Nume fisier pentru elemente simetrice
std::string Handshake::getSymmetricElementsFilename(int entityId) {
    return "id" + std::to_string(entityId) + ".sym";
}

// XOR intre doi vectori
std::vector<unsigned char> Handshake::xorVectors(const std::vector<unsigned char>&a,
    const std::vector<unsigned char>&b) {
    size_t len = std::min(a.size(), b.size());
    std::vector<unsigned char> result(len);

    for (size_t i = 0; i < len; i++) {
        result[i] = a[i] ^ b[i];
    }

    return result;
}

// Genereaza un IV random pentru AES
std::vector<unsigned char> Handshake::generateIV() {
    std::vector<unsigned char> iv(16); // AES block size
    RAND_bytes(iv.data(), iv.size());
    return iv;
}