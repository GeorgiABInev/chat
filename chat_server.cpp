#include <cstdlib>
#include <iomanip>

#include "chat_participant.h"
#include "chat_room.h"
#include "chat_session.h"
#include "database.h"
#include "chat_message.hpp"
#include "logger.h"

using boost::asio::ip::tcp;

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
    if (argc >= 3) {
      db_path = argv[2];
    }

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
