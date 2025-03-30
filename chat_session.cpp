#include "chat_session.h"
#include "chat_room.h"
#include "chat_message.hpp"
#include "logger.h"

#define IDLE_TIMEOUT 10

chat_session::chat_session(tcp::socket socket, chat_room& room)
  : socket_(std::move(socket)),
    room_(room),
    username_("anonymous"),
    timer_(socket_.get_executor()),
    idle_timeout_(std::chrono::minutes(IDLE_TIMEOUT)),
    connection_time_(std::time(nullptr)) 
{
  try {
    ip_address_ = socket_.remote_endpoint().address().to_string();
  }
  catch (std::exception& e) {
    ip_address_ = "unknown";
  }
}

void chat_session::start()
{
  // Wait for registration message first before joining room
  do_read_header();
  start_idle_timer();
}

void chat_session::deliver(const chat_message& msg)
{
  bool write_in_progress = !write_msgs_.empty();
  write_msgs_.push_back(msg);
  if (!write_in_progress)
  {
    do_write();
  }
}

void chat_session::disconnect() 
{
  timer_.cancel();
  boost::asio::post(socket_.get_executor(),
      [this, self = shared_from_this()]() {
          socket_.close();
      });
}

const std::string& chat_session::username() const 
{
  return username_;
}

const std::string& chat_session::get_ip_address() const 
{
  return ip_address_;
}

std::time_t chat_session::get_connection_time() const  
{
  return connection_time_;
}

void chat_session::reset_idle_timer() {
  timer_.expires_after(idle_timeout_);
  timer_.async_wait(
      [this, self = shared_from_this()](boost::system::error_code ec) {
        if (!ec) {
          std::cout << "Client " << username_ << " disconnected due to inactivity." << std::endl;
          room_.kick_user(username_, "Disconnect the user due to inactivity");
        }
      });
}

void chat_session::start_idle_timer() 
{
  reset_idle_timer();
}

void chat_session::do_read_header()
{
  auto self(shared_from_this());
  boost::asio::async_read(socket_,
      boost::asio::buffer(read_msg_.data(), chat_message::header_length),
      [this, self](boost::system::error_code ec, std::size_t /*length*/)
      {
        if (!ec && read_msg_.decode_header())
        {
          reset_idle_timer();
          do_read_body();
        }
        else
        {
          if (joined_) {
            room_.leave(shared_from_this());
          }
        }
      });
}

void chat_session::do_read_body()
{
  auto self(shared_from_this());
  boost::asio::async_read(socket_,
      boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
      [this, self](boost::system::error_code ec, std::size_t /*length*/)
      {
        if (!ec)
        {
          chat::ChatPacket packet;
          if (read_msg_.get_protobuf_message(packet)) {
            if (packet.has_registration()) {
              // Handle registration message
              handle_registration(packet.registration());
            }
            else if (packet.has_message()) {
              // Handle chat message
              handle_chat_message(packet.message());
            }
          }

          do_read_header();
        }
        else
        {
          if (joined_) {
            room_.leave(shared_from_this());
          }
        }
      });
}

void chat_session::handle_registration(const chat::ClientRegistration& reg)
 {
  username_ = reg.username();
  if (username_.empty()) {
    username_ = "anonymous";
  }

  if (!joined_) {
    room_.join(shared_from_this(), ip_address_);
    joined_ = true;
  }
}

void chat_session::handle_chat_message(const chat::ChatMessage& chat_msg)
 {
  if (!joined_) {
    return;
  }

  Logger::getInstance().write(username_, chat_msg.content());

  // Create a new protobuf message with the correct username
  chat::ChatPacket packet;
  auto* msg = packet.mutable_message();
  msg->set_username(username_);
  msg->set_content(chat_msg.content());
  msg->set_timestamp(std::time(nullptr));

  // Deliver to all clients
  chat_message formatted_msg;
  formatted_msg.set_protobuf_message(packet);
  room_.deliver(formatted_msg);
}

void chat_session::do_write()
{
  auto self(shared_from_this());
  boost::asio::async_write(socket_,
      boost::asio::buffer(write_msgs_.front().data(),
        write_msgs_.front().length()),
      [this, self](boost::system::error_code ec, std::size_t /*length*/)
      {
        if (!ec)
        {
          write_msgs_.pop_front();
          if (!write_msgs_.empty())
          {
            do_write();
          }
        }
        else
        {
          if (joined_) {
            room_.leave(shared_from_this());
          }
        }
      });
}