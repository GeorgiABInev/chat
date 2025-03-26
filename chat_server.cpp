#include <cstdlib>
#include <deque>
#include <iostream>
#include <list>
#include <memory>
#include <set>
#include <utility>
#include <boost/asio.hpp>

#include "database.hpp"
#include "chat_message.hpp"

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

    void join(chat_participant_ptr participant)
    {
        // Store/update user in database
        int user_id = db_->get_or_create_user(participant->username());

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
                int user_id = db_->get_or_create_user(username);
                db_->save_message(user_id, chat_msg.content(), chat_msg.timestamp());
            }
        }

        recent_msgs_.push_back(msg);
        while (recent_msgs_.size() > max_recent_msgs)
            recent_msgs_.pop_front();

        for (auto participant: participants_)
            participant->deliver(msg);
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
      username_("anonymous") // Default username until registration
  {
  }

  void start()
  {
    // Wait for registration message first before joining room
    do_read_header();
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

  const std::string& username() const override {
    return username_;
  }

private:
  void do_read_header()
  {
    auto self(shared_from_this());
    boost::asio::async_read(socket_,
        boost::asio::buffer(read_msg_.data(), chat_message::header_length),
        [this, self](boost::system::error_code ec, std::size_t /*length*/)
        {
          if (!ec && read_msg_.decode_header())
          {
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
    // Set the username for this session
    username_ = reg.username();
    if (username_.empty()) {
      username_ = "anonymous";
    }

    // Now join the room after username is set
    if (!joined_) {
      room_.join(shared_from_this());
      joined_ = true;
    }
  }

  void handle_chat_message(const chat::ChatMessage& chat_msg) {
    // Only deliver messages if user has joined
    if (!joined_) {
      return;
    }

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
  bool joined_ = false;
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

int main(int argc, char* argv[])
{
  try
  {
    if (argc < 2)
    {
      std::cerr << "Usage: chat_server <port> [<port> ...] [--db=<database_path>]\n";
      return 1;
    }

    // Parse command line arguments
    std::vector<int> ports;
    std::string db_path = "chat_history.db"; // Default database path

    for (int i = 1; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg.substr(0, 5) == "--db=") {
        db_path = arg.substr(5);
      } else {
        ports.push_back(std::atoi(argv[i]));
      }
    }

    if (ports.empty()) {
      std::cerr << "At least one port must be specified.\n";
      return 1;
    }

    // Initialize database
    std::shared_ptr<Database> db = std::make_shared<Database>(db_path);
    if (!db->initialize()) {
      std::cerr << "Failed to initialize database.\n";
      return 1;
    }

    boost::asio::io_context io_context;

    // Create servers on specified ports
    std::list<chat_server> servers;
    for (int port : ports) {
      tcp::endpoint endpoint(tcp::v4(), port);
      servers.emplace_back(io_context, endpoint, db);
    }

    std::cout << "Chat server started with database: " << db_path << std::endl;
    std::cout << "Listening on port(s): ";
    for (int port : ports) {
      std::cout << port << " ";
    }
    std::cout << std::endl;

    io_context.run();
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
