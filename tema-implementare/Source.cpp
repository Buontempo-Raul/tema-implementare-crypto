#include <iostream>
#include "FileParser.h"
#include "KeyGenerator.h"
#include "Handshake.h"
#include "TransactionManager.h"

int main(int argc, char* argv[]) {
    std::string testFile = "test.txt";

    // Verifica daca s-a dat un argument pentru fisier
    if (argc > 1) {
        testFile = argv[1];
    }

    std::cout << "=== Aplicatie Criptografie - Management Tranzactii ===" << std::endl;
    std::cout << "Fisier de intrare: " << testFile << std::endl << std::endl;

    // Parseaza fisierul de intrare
    FileParser parser(testFile);
    if (!parser.parseFile()) {
        std::cerr << "Eroare la parsarea fisierului!" << std::endl;
        return 1;
    }

    std::cout << "Parsare reusita!" << std::endl;
    parser.printParsedData();

    std::cout << "\n=== Generare chei pentru entitati ===" << std::endl;

    // Creaza generator de chei
    KeyGenerator keyGen;

    // Genereaza chei pentru fiecare entitate
    const auto& entities = parser.getEntities();
    for (const auto& entity : entities) {
        if (!keyGen.generateAllKeysForEntity(entity.id, entity.password)) {
            std::cerr << "Eroare la generarea cheilor pentru entitatea "
                << entity.id << std::endl;
            return 1;
        }
    }

    std::cout << "\n=== Toate cheile au fost generate cu succes! ===" << std::endl;
    std::cout << "\nFisiere generate:" << std::endl;

    // Afiseaza lista de fisiere generate
    for (const auto& entity : entities) {
        std::cout << "\nEntitatea " << entity.id << ":" << std::endl;
        std::cout << "  - id" << entity.id << "_priv.ecc (cheie privata EC criptata)" << std::endl;
        std::cout << "  - id" << entity.id << "_pub.ecc (cheie publica EC)" << std::endl;
        std::cout << "  - id" << entity.id << "_priv.rsa (cheie privata RSA criptata)" << std::endl;
        std::cout << "  - id" << entity.id << "_pub.rsa (cheie publica RSA)" << std::endl;
        std::cout << "  - id" << entity.id << "_ecc.mac (MAC pentru cheie EC)" << std::endl;
        std::cout << "  - id" << entity.id << "_rsa.mac (MAC pentru cheie RSA)" << std::endl;
    }

    std::cout << "\n=== Realizare handshake intre entitati ===" << std::endl;

    // Creaza obiect pentru handshake
    Handshake handshake;

    // Pentru fiecare pereche unica de entitati, realizeaza handshake
    for (size_t i = 0; i < entities.size(); i++) {
        for (size_t j = i + 1; j < entities.size(); j++) {
            if (!handshake.performHandshake(entities[i].id, entities[j].id,
                entities[i].password, entities[j].password)) {
                std::cerr << "Eroare la handshake intre entitatea " << entities[i].id
                    << " si entitatea " << entities[j].id << std::endl;
                return 1;
            }
        }
    }

    std::cout << "\n=== Handshake-uri realizate cu succes! ===" << std::endl;
    std::cout << "\nFisiere suplimentare generate:" << std::endl;

    // Afiseaza fisierele de elemente simetrice
    for (const auto& entity : entities) {
        std::cout << "  - id" << entity.id << ".sym (elemente simetrice)" << std::endl;
    }

    std::cout << "\n=== Procesare tranzactii ===" << std::endl;

    // Creaza manager pentru tranzactii
    TransactionManager transactionManager;

    // Proceseaza tranzactiile din fisier
    const auto& transactions = parser.getTransactions();
    for (const auto& transaction : transactions) {
        // Gaseste parola expeditorului
        std::string senderPassword;
        for (const auto& entity : entities) {
            if (entity.id == transaction.senderId) {
                senderPassword = entity.password;
                break;
            }
        }

        if (!transactionManager.processTransaction(transaction.transactionId,
            transaction.senderId,
            transaction.receiverId,
            transaction.subject,
            transaction.message,
            senderPassword)) {
            std::cerr << "Eroare la procesarea tranzactiei " << transaction.transactionId << std::endl;
            return 1;
        }
    }

    std::cout << "\n=== Toate tranzactiile au fost procesate cu succes! ===" << std::endl;
    std::cout << "\nFisiere de tranzactii generate:" << std::endl;

    // Afiseaza fisierele de tranzactii
    for (const auto& transaction : transactions) {
        std::cout << "  - id" << transaction.senderId << "_id" << transaction.receiverId
            << "_tr" << transaction.transactionId << ".trx" << std::endl;
    }

    std::cout << "\n=== Aplicatie finalizata cu succes! ===" << std::endl;

    return 0;
}