#ifndef FILE_PARSER_H
#define FILE_PARSER_H

#include <string>
#include <vector>

struct Entity {
    int id;
    std::string password;
};

struct Transaction {
    int transactionId;
    int senderId;
    int receiverId;
    std::string subject;
    std::string message;
};

class FileParser {
public:
    FileParser(const std::string& filepath);

    bool parse();  
    void printData() const;  

    int getEntityCount() const { return entities.size(); }
    int getTransactionCount() const { return transactions.size(); }
    std::vector<Entity> getEntities() const { return entities; }
    std::vector<Transaction> getTransactions() const { return transactions; }

private:
    std::string filepath;
    std::vector<Entity> entities;
    std::vector<Transaction> transactions;

    std::vector<std::string> split(const std::string& str, char delimiter);
    std::string trim(const std::string& str);
};

#endif