#include <iostream>
#include "FileParser.h"
#include "KeyGenerator.h"

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

    return 0;
}