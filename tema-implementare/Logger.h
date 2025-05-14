#pragma once
#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <ctime>
#include <sstream>
#include <iomanip>

class Logger {
private:
    static Logger* instance;
    std::ofstream logFile;
    std::string logFilename;

    // Constructor privat pentru Singleton
    Logger();

public:
    // Destructor
    ~Logger();

    // Obtine instanta Singleton
    static Logger* getInstance();

    // Tipuri de actiuni
    enum ActionType {
        KEY_GENERATION,
        HANDSHAKE,
        TRANSACTION,
        MAC_GENERATION,
        MAC_VERIFICATION,
        ERROR
    };

    // Logheaza o actiune
    void logAction(int entityId, ActionType action, const std::string& details);

    // Converteste tipul de actiune la string
    std::string actionTypeToString(ActionType action);

private:
    // Format: <data><timp><entitate><actiune>
    void writeLogEntry(const std::string& date, const std::string& time,
        int entityId, const std::string& action);

    // Obtine data si ora curenta
    std::string getCurrentDate();
    std::string getCurrentTime();

    // Deschide fisierul de log
    bool openLogFile();
};

#endif // LOGGER_H