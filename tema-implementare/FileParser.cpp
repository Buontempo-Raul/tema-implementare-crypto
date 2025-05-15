#include "FileParser.h"
#include <fstream>
#include <iostream>
#include <sstream>

FileParser::FileParser(const std::string& path) : filepath(path) {
}

bool FileParser::parse() {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Nu s-a putut deschide fisierul: " << filepath << std::endl;
        return false;
    }

    int entityCount, transactionCount;

    file >> entityCount;
    file.ignore();

    for (int i = 0; i < entityCount; i++) {
        Entity entity;
        file >> entity.id >> entity.password;
        entities.push_back(entity);
    }

    file >> transactionCount;
    file.ignore();

    std::string line;
    for (int i = 0; i < transactionCount; i++) {
        std::getline(file, line);
        std::vector<std::string> parts = split(line, '/');

        Transaction transaction;
        transaction.transactionId = std::stoi(parts[0]);
        transaction.senderId = std::stoi(parts[1]);
        transaction.receiverId = std::stoi(parts[2]);
        transaction.subject = parts[3];

        transaction.message = "";
        for (size_t j = 4; j < parts.size(); j++) {
            if (j > 4) transaction.message += "/";
            transaction.message += parts[j];
        }

        transactions.push_back(transaction);
    }

    file.close();
    return true;
}

void FileParser::printData() const {
    std::cout << "Entitati (" << entities.size() << "):" << std::endl;
    for (const auto& entity : entities) {
        std::cout << "  ID: " << entity.id << ", Password: " << entity.password << std::endl;
    }

    std::cout << "\nTranzactii (" << transactions.size() << "):" << std::endl;
    for (const auto& transaction : transactions) {
        std::cout << "  ID: " << transaction.transactionId
            << ", De la: " << transaction.senderId
            << ", Catre: " << transaction.receiverId
            << ", Subiect: " << transaction.subject
            << ", Mesaj: " << transaction.message << std::endl;
    }
}

std::vector<std::string> FileParser::split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;

    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

std::string FileParser::trim(const std::string& str) {
    const auto begin = str.find_first_not_of(" \t");
    if (begin == std::string::npos) return "";

    const auto end = str.find_last_not_of(" \t");
    return str.substr(begin, end - begin + 1);
}