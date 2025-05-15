#include <iostream>
#include <string>
#include <vector>
#include "FileParser.h"
#include "KeyGenerator.h"
#include "Handshake.h"
#include "TransactionManager.h"

int main(int argc, char* argv[]) {
    std::string inputFile = "test.txt";

    if (argc > 1) {
        inputFile = argv[1];
    }

    std::cout << "=== Aplicatie Criptografie ===" << std::endl;
    std::cout << "Fisier intrare: " << inputFile << std::endl << std::endl;

    // 1. Parseaza fisierul
    FileParser parser(inputFile);
    if (!parser.parse()) {
        std::cerr << "Eroare la parsare!" << std::endl;
        return 1;
    }

    parser.printData();

    // 2. Genereaza cheile
    std::cout << "\n=== Generare chei ===" << std::endl;

    KeyGenerator keyGen;
    std::vector<Entity> entities = parser.getEntities();

    for (const auto& entity : entities) {
        if (!keyGen.generateAllKeys(entity.id, entity.password)) {
            std::cerr << "Eroare la generarea cheilor pentru " << entity.id << std::endl;
            return 1;
        }
    }

    // 3. Realizeaza handshake
    std::cout << "\n=== Handshake ===" << std::endl;

    Handshake handshake;

    // Pentru fiecare pereche de entitati
    for (size_t i = 0; i < entities.size(); i++) {
        for (size_t j = i + 1; j < entities.size(); j++) {
            if (!handshake.performHandshake(entities[i].id, entities[j].id,
                entities[i].password, entities[j].password)) {
                std::cerr << "Eroare handshake intre " << entities[i].id
                    << " si " << entities[j].id << std::endl;
                return 1;
            }
        }
    }

    // 4. Proceseaza tranzactiile
    std::cout << "\n=== Procesare tranzactii ===" << std::endl;

    TransactionManager transMgr;
    std::vector<Transaction> transactions = parser.getTransactions();

    for (const auto& trans : transactions) {
        // Gaseste parola expeditorului
        std::string senderPassword;
        for (const auto& entity : entities) {
            if (entity.id == trans.senderId) {
                senderPassword = entity.password;
                break;
            }
        }

        if (!transMgr.processTransaction(trans.transactionId, trans.senderId, trans.receiverId,
            trans.subject, trans.message, senderPassword)) {
            std::cerr << "Eroare la procesarea tranzactiei " << trans.transactionId << std::endl;
            return 1;
        }
    }

    std::cout << "\n=== Aplicatie finalizata cu succes! ===" << std::endl;

    return 0;
}