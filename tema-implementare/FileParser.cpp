#include "FileParser.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>

// Constructor
FileParser::FileParser(const std::string& path)
    : filePath(path), entityCount(0), transactionCount(0) {
}

// Destructor
FileParser::~FileParser() {
    // Nu e nevoie de cleanup explicit pentru containerele STL
}

// Metoda principala de parsare
bool FileParser::parseFile() {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Eroare: Nu s-a putut deschide fisierul " << filePath << std::endl;
        return false;
    }

    try {
        // Citeste numarul de entitati
        file >> entityCount;
        file.ignore(); // Ignora newline

        // Parseaza entitatile
        parseEntities(file);

        // Citeste numarul de tranzactii
        file >> transactionCount;
        file.ignore(); // Ignora newline

        // Parseaza tranzactiile
        parseTransactions(file);

        file.close();
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Eroare la parsare: " << e.what() << std::endl;
        file.close();
        return false;
    }
}

// Parseaza entitatile din fisier
void FileParser::parseEntities(std::ifstream& file) {
    entities.clear();
    std::string line;

    for (int i = 0; i < entityCount; i++) {
        if (!std::getline(file, line)) {
            throw std::runtime_error("Eroare la citirea entitatii");
        }

        std::istringstream iss(line);
        Entity entity;

        // Format: id password
        if (!(iss >> entity.id >> entity.password)) {
            throw std::runtime_error("Format invalid pentru entitate");
        }

        entities.push_back(entity);
    }
}

// Parseaza tranzactiile din fisier
void FileParser::parseTransactions(std::ifstream& file) {
    transactions.clear();
    std::string line;

    for (int i = 0; i < transactionCount; i++) {
        if (!std::getline(file, line)) {
            throw std::runtime_error("Eroare la citirea tranzactiei");
        }

        // Format: id_tranzactie/id_sursa/id_destinatie/subiect/mesaj
        std::vector<std::string> parts = splitString(line, '/');

        if (parts.size() < 5) {
            throw std::runtime_error("Format invalid pentru tranzactie");
        }

        Transaction transaction;

        // Prima parte este direct ID-ul tranzactiei
        transaction.transactionId = std::stoi(parts[0]);

        // A doua si a treia parte sunt ID-urile entitatilor
        transaction.senderId = std::stoi(parts[1]);
        transaction.receiverId = std::stoi(parts[2]);

        // A patra parte este subiectul
        transaction.subject = trim(parts[3]);

        // A cincea parte si restul (daca exista) formeaza mesajul
        transaction.message = "";
        for (size_t j = 4; j < parts.size(); j++) {
            if (j > 4) transaction.message += "/";
            transaction.message += parts[j];
        }
        transaction.message = trim(transaction.message);

        transactions.push_back(transaction);
    }
}

// Functie auxiliara pentru split string
std::vector<std::string> FileParser::splitString(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;

    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

// Functie auxiliara pentru eliminarea spatiilor de la inceput si sfarsit
std::string FileParser::trim(const std::string& str) {
    const auto strBegin = str.find_first_not_of(" \t\n\r");
    if (strBegin == std::string::npos)
        return "";

    const auto strEnd = str.find_last_not_of(" \t\n\r");
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

// Afisare pentru debug
void FileParser::printParsedData() const {
    std::cout << "Numar entitati: " << entityCount << std::endl;
    std::cout << "Entitati:" << std::endl;
    for (const auto& entity : entities) {
        std::cout << "  ID: " << entity.id << ", Password: " << entity.password << std::endl;
    }

    std::cout << "\nNumar tranzactii: " << transactionCount << std::endl;
    std::cout << "Tranzactii:" << std::endl;
    for (const auto& transaction : transactions) {
        std::cout << "  ID: " << transaction.transactionId
            << ", Sender: " << transaction.senderId
            << ", Receiver: " << transaction.receiverId
            << ", Subject: " << transaction.subject
            << ", Message: " << transaction.message << std::endl;
    }
}