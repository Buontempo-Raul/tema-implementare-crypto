#ifndef FILE_PARSER_H
#define FILE_PARSER_H

#include <string>
#include <vector>
#include <utility>

// Structura pentru o entitate
struct Entity {
    int id;
    std::string password;
};

// Structura pentru o tranzactie
struct Transaction {
    int transactionId;
    int senderId;
    int receiverId;
    std::string subject;
    std::string message;
};

// Clasa pentru parsarea fisierului de intrare
class FileParser {
private:
    std::string filePath;
    int entityCount;
    int transactionCount;
    std::vector<Entity> entities;
    std::vector<Transaction> transactions;

public:
    // Constructor
    FileParser(const std::string& path);

    // Destructor
    ~FileParser();

    // Metoda principala de parsare
    bool parseFile();

    // Getters
    int getEntityCount() const { return entityCount; }
    int getTransactionCount() const { return transactionCount; }
    const std::vector<Entity>& getEntities() const { return entities; }
    const std::vector<Transaction>& getTransactions() const { return transactions; }

    // Afisare pentru debug
    void printParsedData() const;

private:
    // Metode auxiliare
    void parseEntities(std::ifstream& file);
    void parseTransactions(std::ifstream& file);
    std::vector<std::string> splitString(const std::string& str, char delimiter);
    std::string trim(const std::string& str);
};

#endif // FILE_PARSER_H