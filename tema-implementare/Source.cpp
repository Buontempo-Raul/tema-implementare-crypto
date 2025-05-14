#include <iostream>
#include "FileParser.h"

int main(int argc, char* argv[]) {
    std::string testFile = "test.txt";

    // Verifica daca s-a dat un argument pentru fisier
    if (argc > 1) {
        testFile = argv[1];
    }

    std::cout << "=== Testare FileParser ===" << std::endl;
    std::cout << "Fisier de intrare: " << testFile << std::endl << std::endl;

    // Creaza parser-ul
    FileParser parser(testFile);

    // Parseaza fisierul
    if (parser.parseFile()) {
        std::cout << "Parsare reusita!" << std::endl << std::endl;

        // Afiseaza datele parsate
        parser.printParsedData();

        // Acum putem folosi datele parsate pentru generarea cheilor
        std::cout << "\n=== Urmatorul pas: Generare chei ===" << std::endl;

        const auto& entities = parser.getEntities();
        for (const auto& entity : entities) {
            std::cout << "\nPentru entitatea ID=" << entity.id
                << " (parola: " << entity.password << ") vom genera:" << std::endl;
            std::cout << "  - Cheie privata ECC: id" << entity.id << "_priv.ecc" << std::endl;
            std::cout << "  - Cheie publica ECC: id" << entity.id << "_pub.ecc" << std::endl;
            std::cout << "  - Cheie privata RSA: id" << entity.id << "_priv.rsa" << std::endl;
            std::cout << "  - Cheie publica RSA: id" << entity.id << "_pub.rsa" << std::endl;
            std::cout << "  - MAC pentru cheie publica ECC: id" << entity.id << "_ecc.mac" << std::endl;
            std::cout << "  - MAC pentru cheie publica RSA: id" << entity.id << "_rsa.mac" << std::endl;
        }

        // Aici vom apela functiile de generare a cheilor
        // pentru fiecare entitate din parser.getEntities()

    }
    else {
        std::cerr << "Eroare la parsarea fisierului!" << std::endl;
        return 1;
    }

    return 0;
}