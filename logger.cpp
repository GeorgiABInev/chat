#include "logger.hpp"
#include <sys/stat.h>
#include <iostream>
#include <cstring>

// Utility function to create directory if it doesn't exist
bool createDirectory(const std::string& path) {
    int result = mkdir(path.c_str(), 0755);
    return result == 0 || errno == EEXIST;
}

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger() 
    : log_file_(nullptr), 
      current_hour_(0), 
      initialized_(false) {
}

Logger::~Logger() {
    close_file();
}

bool Logger::open_file(const std::string& log_dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    log_dir_ = log_dir;
    
    // Create log directory if it doesn't exist
    if (!createDirectory(log_dir_)) {
        std::cerr << "Failed to create log directory: " << log_dir_ << std::endl;
        return false;
    }
    
    // Get current time
    std::time_t now = std::time(nullptr);
    
    // Store current hour for rotation check
    current_hour_ = now - (now % 3600);
    
    // Standard log file name
    std::string path = log_dir_ + "/chat.log";
    
    // Close existing file if open
    if (log_file_) {
        fclose(log_file_);
    }
    
    // Open file
    log_file_ = fopen(path.c_str(), "a");
    if (!log_file_) {
        std::cerr << "Failed to open log file: " << path << std::endl;
        return false;
    }
    
    initialized_ = true;
    return true;
}

void Logger::check_rotate() {
    std::time_t now = std::time(nullptr);
    std::time_t current_hour = now - (now % 3600);
    
    // Check if hour has changed
    if (current_hour > current_hour_) {
        // Format the archived filename with the previous hour's timestamp
        std::tm* tm_info = std::localtime(&current_hour_);
        
        char filename[100];
        std::strftime(filename, sizeof(filename), "chat_%Y-%m-%d_%H-00-00.log", tm_info);
        
        // Full paths
        std::string current_path = log_dir_ + "/chat.log";
        std::string archive_path = log_dir_ + "/" + filename;
        
        // Close the current file
        if (log_file_) {
            fclose(log_file_);
            log_file_ = nullptr;
        }
        
        // Rename the file
        if (rename(current_path.c_str(), archive_path.c_str()) != 0) {
            std::cerr << "Failed to rename log file from " << current_path << " to " << archive_path << std::endl;
        }
        
        // Open a new file with the standard name
        log_file_ = fopen(current_path.c_str(), "a");
        if (!log_file_) {
            std::cerr << "Failed to open new log file: " << current_path << std::endl;
            initialized_ = false;
            return;
        }
        
        // Update the current hour
        current_hour_ = current_hour;
    }
}

void Logger::close_file() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (log_file_) {
        fclose(log_file_);
        log_file_ = nullptr;
    }
    initialized_ = false;
}

void Logger::write(const std::string& username, const std::string& message) {
    
    if (!initialized_ || !log_file_) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    check_rotate();
    
    // Get current time
    std::time_t now = std::time(nullptr);
    std::tm* tm_info = std::localtime(&now);
    
    // Format timestamp
    char timestamp[30];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Write log entry
    fprintf(log_file_, "[%s] %s: %s\n", timestamp, username.c_str(), message.c_str());
    
    // Flush to ensure it's written
    fflush(log_file_);
}