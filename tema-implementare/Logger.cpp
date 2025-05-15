#include "Logger.h"
#include <iostream>
#include <ctime>
#include <sstream>
#include <iomanip>

Logger* Logger::instance = nullptr;

Logger::Logger() {
    logFile.open("info.log", std::ios::out | std::ios::trunc);
    if (!logFile.is_open()) {
        std::cerr << "Nu s-a putut deschide fisierul de log!" << std::endl;
    }
}

Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}

Logger* Logger::getInstance() {
    if (instance == nullptr) {
        instance = new Logger();
    }
    return instance;
}

void Logger::log(int entityId, const std::string& action) {
    if (!logFile.is_open()) {
        return;
    }

    std::string date = getCurrentDate();
    std::string time = getCurrentTime();

    // Format: <data><timp><entitate><actiune>
    logFile << "<" << date << ">"
        << "<" << time << ">"
        << "<" << entityId << ">"
        << "<" << action << ">"
        << std::endl;
    logFile.flush();
}

std::string Logger::getCurrentDate() {
    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);

    std::stringstream ss;
    ss << std::setfill('0') << std::setw(4) << (timeinfo.tm_year + 1900)
        << std::setfill('0') << std::setw(2) << (timeinfo.tm_mon + 1)
        << std::setfill('0') << std::setw(2) << timeinfo.tm_mday;

    return ss.str();
}

std::string Logger::getCurrentTime() {
    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);

    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << timeinfo.tm_hour
        << std::setfill('0') << std::setw(2) << timeinfo.tm_min
        << std::setfill('0') << std::setw(2) << timeinfo.tm_sec;

    return ss.str();
}