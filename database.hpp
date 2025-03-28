#ifndef DATABASE_HPP
#define DATABASE_HPP

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <sqlite3.h>
#include <ctime>
#include <optional>

// User information structure
struct UserInfo {
    int user_id;
    std::string username;
    std::string ip_address;
    std::time_t last_seen;
    std::time_t created_at;
};

// Message information structure
struct MessageInfo {
    int message_id;
    int user_id;
    std::string username;
    std::string content;
    std::time_t timestamp;
};

// User statistics structure
struct UserStats {
    int user_id;
    std::string username;
    int message_count;
    std::time_t first_message;
    std::time_t last_message;
    double average_message_length;
};

class Database {
public:
    Database(const std::string& db_path);

    ~Database();

    bool initialize();

    // User operations
    int get_or_create_user(const std::string& username, const std::string& ip_address);
    bool update_user_last_seen(int user_id, const std::string& ip_address, std::time_t timestamp) ;
    
    // Message operations
    bool save_message(int user_id, const std::string& content, std::time_t timestamp);
    std::vector<MessageInfo> get_recent_messages(int limit = 100);

private:
    sqlite3* db_;
    std::mutex mutex_;
    
    bool execute_query(const std::string& query);
};

#endif // DATABASE_HPP