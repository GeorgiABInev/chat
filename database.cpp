#include "database.h"
#include <iostream>

Database::Database(const std::string& db_path) : db_(nullptr) 
{
    int result = sqlite3_open(db_path.c_str(), &db_);
    if (result != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db_) << std::endl;
        db_ = nullptr;
    }
}

Database::~Database() 
{
    if (db_) {
        sqlite3_close(db_);
    }
}

bool Database::initialize() 
{
    if (!db_) return false;

    const char* create_users_table =
        "CREATE TABLE IF NOT EXISTS users ("
        "user_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "ip_address TEXT NOT NULL, "
        "last_seen TIMESTAMP NOT NULL, "
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");";

    const char* create_messages_table =
        "CREATE TABLE IF NOT EXISTS messages ("
        "message_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_id INTEGER NOT NULL, "
        "content TEXT NOT NULL, "
        "timestamp TIMESTAMP NOT NULL, "
        "FOREIGN KEY (user_id) REFERENCES users(user_id)"
        ");";

    return execute_query(create_users_table) && execute_query(create_messages_table);
}

bool Database::execute_query(const std::string& query) 
{
    char* error_msg = nullptr;
    int result = sqlite3_exec(db_, query.c_str(), nullptr, nullptr, &error_msg);

    if (result != SQLITE_OK) {
        std::cerr << "SQL error: " << error_msg << std::endl;
        sqlite3_free(error_msg);
        return false;
    }

    return true;
}

int Database::get_or_create_user(const std::string& username, const std::string& ip_address) 
{
    if (!db_) return -1;

    // First try to get existing user
    sqlite3_stmt* stmt;
    std::string query = "SELECT user_id FROM users WHERE username = ?;";

    if (sqlite3_prepare_v2(db_, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    int user_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (user_id != -1) {
        // User exists, update last_seen
        std::time_t now = std::time(nullptr);
        update_user_last_seen(user_id, ip_address, now);
        return user_id;
    }

    // Create new user
    query = "INSERT INTO users (username, ip_address, last_seen) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db_, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }

    std::time_t now = std::time(nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ip_address.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, now);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return sqlite3_last_insert_rowid(db_);
}

bool Database::update_user_last_seen(int user_id, const std::string& ip_address, std::time_t timestamp) 
{
    if (!db_) return false;

    sqlite3_stmt* stmt;
    std::string query = "UPDATE users SET last_seen = ?, ip_address = ? WHERE user_id = ?;";

    if (sqlite3_prepare_v2(db_, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_text(stmt, 2, ip_address.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, user_id);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    return success;
}

bool Database::save_message(int user_id, const std::string& content, std::time_t timestamp) 
{
    if (!db_) return false;

    sqlite3_stmt* stmt;
    std::string query = "INSERT INTO messages (user_id, content, timestamp) VALUES (?, ?, ?);";

    if (sqlite3_prepare_v2(db_, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, content.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, timestamp);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    return success;
}

std::vector<MessageInfo> Database::get_recent_messages(int limit) 
{
    std::vector<MessageInfo> messages;
    if (!db_) return messages;

    sqlite3_stmt* stmt;
    std::string query =
        "SELECT m.message_id, m.user_id, u.username, m.content, m.timestamp "
        "FROM messages m JOIN users u ON m.user_id = u.user_id "
        "ORDER BY m.timestamp DESC LIMIT ?;";

    if (sqlite3_prepare_v2(db_, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return messages;
    }

    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        MessageInfo msg;
        msg.message_id = sqlite3_column_int(stmt, 0);
        msg.user_id = sqlite3_column_int(stmt, 1);
        msg.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        msg.content = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        msg.timestamp = sqlite3_column_int64(stmt, 4);
        messages.push_back(msg);
    }

    sqlite3_finalize(stmt);
    return messages;
}
