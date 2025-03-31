#include "chat_room.h"
#include "database.h"
#include "chat_message.hpp"
#include "logger.h"

chat_room::chat_room(std::shared_ptr<Database> db)
        : db_(db)
{
    // Load recent messages from database
    auto recent_db_msgs = db_->get_recent_messages(max_recent_msgs);

    // Convert database messages to chat_messages
    for (const auto& db_msg : recent_db_msgs) {
        chat::ChatPacket packet;
        auto* msg = packet.mutable_message();
        msg->set_username(db_msg.username);
        msg->set_content(db_msg.content);
        msg->set_timestamp(db_msg.timestamp);

        chat_message chat_msg;
        chat_msg.set_protobuf_message(packet);
        recent_msgs_.push_front(chat_msg); // Reverse order to maintain chronology
    }
}

void chat_room::join(chat_participant_ptr participant, const std::string& ip_address)
{   
    int user_id = db_->get_or_create_user(participant->username(), ip_address);

    participants_.insert(participant);
    for (auto msg: recent_msgs_)
        participant->deliver(msg);

    // Announce user joined
    chat::ChatPacket packet;
    auto* system_msg = packet.mutable_message();
    system_msg->set_username("System");
    system_msg->set_content("User " + participant->username() + " has joined the chat.");
    system_msg->set_timestamp(std::time(nullptr));

    chat_message msg;
    msg.set_protobuf_message(packet);
    deliver(msg);
}

void chat_room::leave(chat_participant_ptr participant)
{
    participants_.erase(participant);

    // Announce user left
    chat::ChatPacket packet;
    auto* system_msg = packet.mutable_message();
    system_msg->set_username("System");
    system_msg->set_content("User " + participant->username() + " has left the chat.");
    system_msg->set_timestamp(std::time(nullptr));

    chat_message msg;
    msg.set_protobuf_message(packet);
    deliver(msg);
}

void chat_room::deliver(const chat_message& msg)
{
    // Extract info from the message to store in database
    chat::ChatPacket packet;
    if (msg.get_protobuf_message(packet) && packet.has_message()) {
        const auto& chat_msg = packet.message();
        std::string username = chat_msg.username();

        // Don't store system messages in the database
        if (username != "System") {
            auto it = std::find_if(participants_.begin(), participants_.end(),
                                [&username](const chat_participant_ptr& p) {
                                    return p->username() == username;
                                });
            
            std::string ip_address = "unknown";
            if (it != participants_.end()) {
                ip_address = (*it)->get_ip_address();
            }
            
            int user_id = db_->get_or_create_user(username, ip_address);
            db_->save_message(user_id, chat_msg.content(), chat_msg.timestamp());
        }
    }

    recent_msgs_.push_back(msg);
    while (recent_msgs_.size() > max_recent_msgs)
        recent_msgs_.pop_front();

    for (auto participant: participants_)
        participant->deliver(msg);
}

bool chat_room::kick_user(const std::string& username, const std::string& reason) 
{
    for (auto it = participants_.begin(); it != participants_.end(); ++it) {
        if ((*it)->username() == username) {
            auto participant = *it;
            
            // Send kick message to the user being kicked
            chat::ChatPacket kick_packet;
            auto* system_msg = kick_packet.mutable_message();
            system_msg->set_username("System");
            system_msg->set_content("You have been kicked from the server: " + reason);
            system_msg->set_timestamp(std::time(nullptr));
            
            chat_message kick_msg;
            kick_msg.set_protobuf_message(kick_packet);
            participant->deliver(kick_msg);
            
            // Send announcement to all users
            chat::ChatPacket announce_packet;
            auto* announce_msg = announce_packet.mutable_message();
            announce_msg->set_username("System");
            announce_msg->set_content("User " + username + " has been kicked from the server");
            announce_msg->set_timestamp(std::time(nullptr));
            
            chat_message announce_message;
            announce_message.set_protobuf_message(announce_packet);
            deliver(announce_message);
            
            Logger::getInstance().write("System", "User " + username + " has been kicked: " + reason);

            participants_.erase(it);
            participant->disconnect();
            
            return true;
        }
    }
    
    return false;
}

std::vector<std::tuple<std::string, std::string, std::time_t>> chat_room::get_connected_clients() const 
{
    std::vector<std::tuple<std::string, std::string, std::time_t>> clients;
    for (const auto& participant : participants_) {
        clients.emplace_back(
            participant->username(),
            participant->get_ip_address(),
            participant->get_connection_time()
        );
    }
    return clients;
}

bool chat_room::check_user_exist(const std::string& username) const
{
    for (const auto& participant: participants_) {
        if (participant->username() == username) {
            return true;
        }
    }

    return false;
}