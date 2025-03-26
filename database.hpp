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
    std::time_t last_seen;
    std::time_t created_at;
};

// Message information structure
struct MessageInfo {
    int message_id;
    int user_id;
    std::string username;  // For convenience
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
    // Constructor with database path
    Database(const std::string& db_path);
    
    // Destructor
    ~Database();

    // Database initialization
    bool initialize();

    // User operations
    int get_or_create_user(const std::string& username);
    bool update_user_last_seen(int user_id, std::time_t timestamp);
    std::vector<UserInfo> get_active_users(int limit = 100);
    std::optional<UserInfo> get_user_by_id(int user_id);
    std::optional<UserInfo> get_user_by_username(const std::string& username);
    UserStats get_user_stats(int user_id);
    
    // Message operations
    bool save_message(int user_id, const std::string& content, std::time_t timestamp);
    std::vector<MessageInfo> get_recent_messages(int limit = 100);
    std::vector<MessageInfo> get_messages_by_user(int user_id, int limit = 100);
    std::vector<MessageInfo> search_messages(const std::string& keyword, int limit = 100);
    
    // Chat room operations
    std::vector<std::string> get_most_active_users(int limit = 10);
    int get_total_message_count();
    double get_messages_per_day(int days = 7);
    
    // Database maintenance
    bool backup_database(const std::string& backup_path);
    bool vacuum();
    bool is_connected() const { return db_ != nullptr; }

private:
    sqlite3* db_;
    std::mutex mutex_;
    
    // Helper methods
    bool execute_query(const std::string& query);
    std::string escape_string(const std::string& str);
};

#endif // DATABASE_HPP