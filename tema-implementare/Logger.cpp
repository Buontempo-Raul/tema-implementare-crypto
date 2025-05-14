#include "Logger.h"
#include <iostream>

// Initializare pointer static
Logger* Logger::instance = nullptr;

// Constructor
Logger::Logger() : logFilename("info.log") {
    openLogFile();
}

// Destructor
Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}

// Obtine instanta Singleton
Logger* Logger::getInstance() {
    if (instance == nullptr) {
        instance = new Logger();
    }
    return instance;
}

// Deschide fisierul de log
bool Logger::openLogFile() {
    // Deschide fisierul in mod text pentru o afisare mai clara
    logFile.open(logFilename, std::ios::out | std::ios::trunc);

    if (!logFile.is_open()) {
        std::cerr << "Nu s-a putut deschide fisierul de log: " << logFilename << std::endl;
        return false;
    }

    return true;
}

// Logheaza o actiune
void Logger::logAction(int entityId, ActionType action, const std::string& details) {
    std::string date = getCurrentDate();
    std::string time = getCurrentTime();
    std::string actionStr = actionTypeToString(action);

    if (!details.empty()) {
        actionStr += " - " + details;
    }

    writeLogEntry(date, time, entityId, actionStr);
}

// Scrie o intrare in log
void Logger::writeLogEntry(const std::string& date, const std::string& time,
    int entityId, const std::string& action) {
    if (!logFile.is_open()) {
        return;
    }

    // Format: <data><timp><entitate><actiune>
    logFile << "<" << date << ">"
        << "<" << time << ">"
        << "<" << entityId << ">"
        << "<" << action << ">" << std::endl;

    logFile.flush();
}

// Obtine data curenta in format an-luna-zi
std::string Logger::getCurrentDate() {
    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);

    std::stringstream ss;
    ss << (timeinfo.tm_year + 1900) << "-"
        << std::setfill('0') << std::setw(2) << (timeinfo.tm_mon + 1) << "-"
        << std::setfill('0') << std::setw(2) << timeinfo.tm_mday;

    return ss.str();
}

// Obtine ora curenta in format HH:MM:SS
std::string Logger::getCurrentTime() {
    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);

    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << timeinfo.tm_hour << ":"
        << std::setfill('0') << std::setw(2) << timeinfo.tm_min << ":"
        << std::setfill('0') << std::setw(2) << timeinfo.tm_sec;

    return ss.str();
}

// Converteste tipul de actiune la string
std::string Logger::actionTypeToString(ActionType action) {
    switch (action) {
    case KEY_GENERATION:
        return "Generare chei";
    case HANDSHAKE:
        return "Handshake";
    case TRANSACTION:
        return "Tranzactie";
    case MAC_GENERATION:
        return "Generare MAC";
    case MAC_VERIFICATION:
        return "Verificare MAC";
    case ERROR:
        return "Eroare";
    default:
        return "Actiune necunoscuta";
    }
}