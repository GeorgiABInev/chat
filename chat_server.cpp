#include <cstdlib>
#include <deque>
#include <iostream>
#include <list>
#include <memory>
#include <set>
#include <utility>
#include <iomanip>
#include <boost/asio.hpp>

#include "database.hpp"
#include "chat_message.hpp"
#include "logger.hpp"

using boost::asio::ip::tcp;

//----------------------------------------------------------------------

typedef std::deque<chat_message> chat_message_queue;

//----------------------------------------------------------------------

class chat_participant
{
public:
  virtual ~chat_participant() {}
  virtual void deliver(const chat_message& msg) = 0;
  virtual const std::string& username() const = 0;
  virtual const std::string& get_ip_address() const = 0;
  virtual std::time_t get_connection_time() const = 0;  
  virtual void disconnect() = 0;
};

typedef std::shared_ptr<chat_participant> chat_participant_ptr;

//----------------------------------------------------------------------
class chat_room
{
public:
    chat_room(std::shared_ptr<Database> db)
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

    void join(chat_participant_ptr participant, const std::string& ip_address)
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

    void leave(chat_participant_ptr participant)
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

    void deliver(const chat_message& msg)
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

    bool kick_user(const std::string& username, const std::string& reason) {
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

  std::vector<std::tuple<std::string, std::string, std::time_t>> get_connected_clients() const {
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

private:
    std::set<chat_participant_ptr> participants_;
    enum { max_recent_msgs = 100 };
    chat_message_queue recent_msgs_;
    std::shared_ptr<Database> db_;
};
//----------------------------------------------------------------------

class chat_session
  : public chat_participant,
    public std::enable_shared_from_this<chat_session>
{
public:
  chat_session(tcp::socket socket, chat_room& room)
    : socket_(std::move(socket)),
      room_(room),
      username_("anonymous"),
      timer_(socket_.get_executor()),
      idle_timeout_(std::chrono::minutes(1)),
      connection_time_(std::time(nullptr)) 
  {
    try {
      ip_address_ = socket_.remote_endpoint().address().to_string();
    }
    catch (std::exception& e) {
      ip_address_ = "unknown";
    }
  }

  void start()
  {
    // Wait for registration message first before joining room
    do_read_header();
    start_idle_timer();
  }

  void deliver(const chat_message& msg) override
  {
    bool write_in_progress = !write_msgs_.empty();
    write_msgs_.push_back(msg);
    if (!write_in_progress)
    {
      do_write();
    }
  }

  void disconnect() override {
    boost::asio::post(socket_.get_executor(),
        [this, self = shared_from_this()]() {
            socket_.close();
        });
  }

  const std::string& username() const override {
    return username_;
  }

  const std::string& get_ip_address() const override {
    return ip_address_;
  }

  std::time_t get_connection_time() const override {
    return connection_time_;
  }

private:
  void reset_idle_timer() {
    timer_.expires_after(idle_timeout_);
    timer_.async_wait(
        [this, self = shared_from_this()](boost::system::error_code ec) {
          if (!ec) {
            std::cout << "Client " << username_ << " disconnected due 10 minutes to inactivity." << std::endl;
            room_.kick_user(username_, "Disconnect the user due to inactivity");
          }
        });
  }

  void start_idle_timer() {
    reset_idle_timer();
  }

  void do_read_header()
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

  void do_read_body()
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

  void handle_registration(const chat::ClientRegistration& reg) {
    username_ = reg.username();
    if (username_.empty()) {
      username_ = "anonymous";
    }

    if (!joined_) {
      room_.join(shared_from_this(), ip_address_);
      joined_ = true;
    }
  }

  void handle_chat_message(const chat::ChatMessage& chat_msg) {
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

  void do_write()
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

//----------------------------------------------------------------------
class chat_server
{
public:
  chat_server(boost::asio::io_context& io_context,
      const tcp::endpoint& endpoint,
      std::shared_ptr<Database> db)
    : acceptor_(io_context, endpoint),
      room_(db)
  {
    do_accept();
  }

  const chat_room& get_room() const {
    return room_;
  }

  bool kick_user(const std::string& username, const std::string& reason) {
    return room_.kick_user(username, reason);
  }

private:
  void do_accept()
  {
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket)
        {
          if (!ec)
          {
            std::make_shared<chat_session>(std::move(socket), room_)->start();
          }

          do_accept();
        });
  }


  tcp::acceptor acceptor_;
  chat_room room_;
};
//----------------------------------------------------------------------

void handle_clients_command(const chat_server& server)
{
  std::cout << "Connected clients:" << std::endl;
  std::cout << "-----------------" << std::endl;
  
  int total_clients = 0;
  std::time_t current_time = std::time(nullptr);
  
  const auto& clients = server.get_room().get_connected_clients();
  total_clients += clients.size();
  
  for (const auto& client : clients) {
    std::string username = std::get<0>(client);
    std::string ip = std::get<1>(client);
    std::time_t conn_time = std::get<2>(client);
    
    // Calculate time online in seconds
    std::time_t seconds_online = current_time - conn_time;

    int hours = seconds_online / 3600;
    int minutes = (seconds_online % 3600) / 60;
    int seconds = seconds_online % 60;
    
    std::cout << "Username: " << std::left << std::setw(15) << username
              << "IP: " << std::left << std::setw(15) << ip
              << "Time online: " 
              << std::right << std::setw(2) << std::setfill('0') << hours << ":"
              << std::right << std::setw(2) << std::setfill('0') << minutes << ":"
              << std::right << std::setw(2) << std::setfill('0') << seconds 
              << std::setfill(' ') << std::endl;
  }
  
  std::cout << "-----------------" << std::endl;
  if (total_clients == 0) 
    std::cout << "There are no connected clients." << std::endl;
  else
    std::cout << "Total connected clients: " << total_clients << std::endl;
}

void handle_kick_command(chat_server& server, const std::string& command)
{
  std::string username = command.substr(6);
  bool user_found = false;
  
  // Trim leading/trailing whitespace from username
  username.erase(0, username.find_first_not_of(" \t"));
  username.erase(username.find_last_not_of(" \t") + 1);
  
  if (username.empty()) {
      std::cout << "Usage: /kick <username> [reason]" << std::endl;
      return;
  }
  
  // Extract reason if provided
  std::string reason = "No reason provided";
  size_t reason_pos = username.find(' ');
  if (reason_pos != std::string::npos) {
      reason = username.substr(reason_pos + 1);
      username = username.substr(0, reason_pos);
  }

  if (server.kick_user(username, reason)) {
      user_found = true;
      std::cout << "User '" << username << "' has been kicked." << std::endl;
      return;
  }
  
  if (!user_found) {
      std::cout << "User '" << username << "' not found." << std::endl;
  }
}

int main(int argc, char* argv[])
{
  try
  {
    if (argc < 2)
    {
      std::cerr << "Usage: chat_server <port> [--db=<database_path>]\n";
      return 1;
    }

    if (!Logger::getInstance().open_file("logs")) {
      std::cerr << "Failed to initialize logger" << std::endl;
      return 1;
    }

    Logger::getInstance().write("System", "Chat server starting up...");

    // Parse command line arguments
    int port = std::atoi(argv[1]);
    std::string db_path = "chat_history.db"; // Default database path

    // Initialize database
    std::shared_ptr<Database> db = std::make_shared<Database>(db_path);
    if (!db->initialize()) {
      std::cerr << "Failed to initialize database.\n";
      return 1;
    }

    boost::asio::io_context io_context;

    tcp::endpoint endpoint(tcp::v4(), port);
    chat_server server(io_context, endpoint, db);

    std::cout << "Chat server started with database: " << db_path << std::endl;
    std::cout << "Listening on port: " << port <<  std::endl;

    // Start the io_context in a separate thread
    std::thread io_thread([&io_context](){ io_context.run(); });

    // Main thread can now do other things, like accepting console commands
    std::cout << "Server is running.\nType '/quit' to stop the server or '/help' for available commands." << std::endl;
    
    std::string command;
    while (std::getline(std::cin, command)) {
      if (command == "/quit") {
        std::cout << "Shutting down server..." << std::endl;
        break;
      } 
      else if (command == "/clients") {
        handle_clients_command(server);
      } 
      else if (command.substr(0, 6) == "/kick ") {
        handle_kick_command(server, command);
      } 
      else if (command == "/help") {
        std::cout << "Available commands:\n"
                  << "  /help                     - Show this help message\n"
                  << "  /clients                  - Show connected clients\n"
                  << "  /kick <username> [reason] - Kick a user from the server\n"
                  << "  /quit                     - Stop the server\n";
      } 
      else {
        std::cout << "Unknown command. Type '/help' for available commands." << std::endl;
      }
    }

    // Stop io_context and wait for thread to finish
    io_context.stop();
    io_thread.join();

    Logger::getInstance().write("System", "Server shutting down");
    Logger::getInstance().close_file();
    
    std::cout << "Server shutdown complete." << std::endl;
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
    Logger::getInstance().write("System", std::string("Error: ") + e.what());
    Logger::getInstance().close_file();
  }

  return 0;
}
