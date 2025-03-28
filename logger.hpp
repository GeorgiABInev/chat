#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <mutex>
#include <cstdio>
#include <ctime>

class Logger {
public:
    // Get singleton instance
    static Logger& getInstance();
    
    // Delete copy/move constructors and assignment operators
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;
    
    bool open_file(const std::string& log_dir = "logs");

    void close_file();
    
    // Check if we need to rotate to a new file
    void check_rotate();

    void write(const std::string& username, const std::string& message);

private:
    Logger();
    ~Logger();
    
    std::string log_dir_;
    FILE* log_file_;
    std::time_t current_hour_;
    std::mutex mutex_;
    bool initialized_;
};

#endif // LOGGER_HPP