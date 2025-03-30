#ifndef CHATROOM_H
#define CHATROOM_H

#include <deque>

#include "database.h"
#include "chat_participant.h"
#include "chat_message.hpp"

typedef std::deque<chat_message> chat_message_queue;
typedef std::shared_ptr<chat_participant> chat_participant_ptr;

class chat_room
{
public:
    chat_room(std::shared_ptr<Database> db);

    void join(chat_participant_ptr participant, const std::string& ip_address);
    void leave(chat_participant_ptr participant);
    void deliver(const chat_message& msg);
    bool kick_user(const std::string& username, const std::string& reason);
    std::vector<std::tuple<std::string, std::string, std::time_t>> get_connected_clients() const;

private:
    std::set<chat_participant_ptr> participants_;
    enum { max_recent_msgs = 100 };
    chat_message_queue recent_msgs_;
    std::shared_ptr<Database> db_;
};

#endif // CHATROOM_H