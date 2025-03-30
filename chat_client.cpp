#include <cstdlib>
#include <deque>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include "chat_message.hpp"

using boost::asio::ip::tcp;

typedef std::deque<chat_message> chat_message_queue;

class chat_client
{
public:
  chat_client(boost::asio::io_context& io_context,
      const tcp::resolver::results_type& endpoints,
      const std::string& username)
    : io_context_(io_context),
      socket_(io_context),
      username_(username)
  {
    do_connect(endpoints);
  }

  void write(const chat_message& msg)
  {
    boost::asio::post(io_context_,
        [this, msg]()
        {
          bool write_in_progress = !write_msgs_.empty();
          write_msgs_.push_back(msg);
          if (!write_in_progress)
          {
            do_write();
          }
        });
  }

  void close()
  {
    boost::asio::post(io_context_, [this]() { socket_.close(); });
  }

  bool should_exit() const {
    return exit_flag_;
  }

private:
  void do_connect(const tcp::resolver::results_type& endpoints)
  {
    boost::asio::async_connect(socket_, endpoints,
        [this](boost::system::error_code ec, tcp::endpoint)
        {
          if (!ec)
          {
            do_read_header();
          }
          else
          {
            std::cerr << "Connection failed: " << ec.message() << std::endl;
          }
        });
  }

  void do_read_header()
  {
    boost::asio::async_read(socket_,
        boost::asio::buffer(read_msg_.data(), chat_message::header_length),
        [this](boost::system::error_code ec, std::size_t /*length*/)
        {
          if (!ec && read_msg_.decode_header())
          {
            do_read_body();
          }
          else
          {
            std::cout << "Connection closed by server." << std::endl;
            close();
          
            // Signal main thread to exit
            exit_flag_ = true;
          }
        });
  }

  void do_read_body()
  {
    boost::asio::async_read(socket_,
        boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
        [this](boost::system::error_code ec, std::size_t /*length*/)
        {
          if (!ec)
          {
            chat::ChatPacket packet;
            if (read_msg_.get_protobuf_message(packet)) {
              if (packet.has_message()) {
                const auto& msg = packet.message();
                std::cout << msg.username() << ": " << msg.content() << std::endl;
              }
            }

            do_read_header();
          }
          else
          {
            socket_.close();
          }
        });
  }

  void do_write()
  {
    boost::asio::async_write(socket_,
        boost::asio::buffer(write_msgs_.front().data(),
          write_msgs_.front().length()),
        [this](boost::system::error_code ec, std::size_t /*length*/)
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
            socket_.close();
          }
        });
  }

private:
  boost::asio::io_context& io_context_;
  tcp::socket socket_;
  chat_message read_msg_;
  chat_message_queue write_msgs_;
  std::string username_;
  bool exit_flag_ = false;
};

int main(int argc, char* argv[])
{
  try
  {
    if (argc != 4)
    {
      std::cerr << "Usage: chat_client <host> <port> <username>\n";
      return 1;
    }

    boost::asio::io_context io_context;

    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(argv[1], argv[2]);

    std::string username = argv[3];
    chat_client c(io_context, endpoints, username);

    std::thread t([&io_context](){ io_context.run(); });

    // Send registration message first
    {
      chat::ChatPacket packet;
      packet.mutable_registration()->set_username(username);

      chat_message msg;
      msg.set_protobuf_message(packet);
      c.write(msg);
    }

    std::cout << "Connected to chat server as " << username << std::endl;
    std::cout << "Type /help for available commands" << std::endl;

    // Then handle normal chat messages
    std::string line;
    while (!c.should_exit() && std::getline(std::cin, line))
    {
      // Process special commands
      if (line == "/help") {
        std::cout << "Available commands:\n"
                  << "  /help     - Show this help message\n"
                  << "  /quit     - Exit the chat client\n";
        continue;
      }
      else if (line == "/quit") {
        break;
      }

      // Regular message
      chat::ChatPacket packet;
      packet.mutable_message()->set_content(line);

      chat_message msg;
      msg.set_protobuf_message(packet);
      c.write(msg);
    }

    c.close();
    t.join();
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
