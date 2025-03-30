#ifndef CHATSESSION_H
#define CHATSESSION_H

#include <cstdlib>
#include <boost/asio.hpp>

#include "chat_participant.h"
#include "chat_message.hpp"
#include "chat_room.h"

using boost::asio::ip::tcp;

class chat_session
  : public chat_participant,
    public std::enable_shared_from_this<chat_session>
{
public:
  chat_session(tcp::socket socket, chat_room& room);

  void start();
  void deliver(const chat_message& msg) override;
  void disconnect() override;

  const std::string& username() const override;
  const std::string& get_ip_address() const override;
  std::time_t get_connection_time() const override;

private:
  void reset_idle_timer();
  void start_idle_timer();
  void do_read_header();
  void do_read_body();
  void handle_registration(const chat::ClientRegistration& reg);
  void handle_chat_message(const chat::ChatMessage& chat_msg);
  void do_write();

  tcp::socket socket_;
  chat_room& room_;
  chat_message read_msg_;
  chat_message_queue write_msgs_;
  std::string username_;
  std::string ip_address_;
  bool joined_ = false;

  // Idle timeout members
  boost::asio::steady_timer timer_;
  std::chrono::steady_clock::duration idle_timeout_;
  std::time_t connection_time_;
};

#endif // CHATSESSION_H