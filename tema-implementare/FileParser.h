#ifndef FILE_PARSER_H
#define FILE_PARSER_H

#include <string>
#include <vector>

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

// Clasa simplificata pentru parsarea fisierului
class FileParser {
public:
    FileParser(const std::string& filepath);

    bool parse();  // Metoda principala simplificata
    void printData() const;  // Pentru debugging

    // Getters simplificati
    int getEntityCount() const { return entities.size(); }
    int getTransactionCount() const { return transactions.size(); }
    std::vector<Entity> getEntities() const { return entities; }
    std::vector<Transaction> getTransactions() const { return transactions; }

private:
    std::string filepath;
    std::vector<Entity> entities;
    std::vector<Transaction> transactions;

    // Metode ajutatoare simple
    std::vector<std::string> split(const std::string& str, char delimiter);
    std::string trim(const std::string& str);
};

#endif // FILE_PARSER_H