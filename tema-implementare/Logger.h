#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>

class Logger {
public:
    static Logger* getInstance();

    void log(int entityId, const std::string& action);

private:
    Logger();  // Constructor privat pentru Singleton
    ~Logger();

    static Logger* instance;
    std::ofstream logFile;

    std::string getCurrentDate();
    std::string getCurrentTime();
};

#endif // LOGGER_H