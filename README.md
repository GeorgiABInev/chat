# Chat Application

This is a real-time chat application built with C++, using Boost.Asio for networking, Protocol Buffers for message serialization, and SQLite for persistent storage of chat history.

## Features

- Real-time messaging using async I/O
- User registration and persistence
- Chat history storage in SQLite database
- Protocol Buffers for efficient, type-safe message serialization
- Support for multiple concurrent clients
- Multi-port server capability

## Prerequisites

To build and run this application, you'll need the following:

### Ubuntu/Debian

```bash
# Install build tools
sudo apt-get update
sudo apt-get install -y build-essential cmake

# Install Boost libraries
sudo apt-get install -y libboost-all-dev

# Install Protocol Buffers
sudo apt-get install -y protobuf-compiler libprotobuf-dev

# Install SQLite3
sudo apt-get install -y libsqlite3-dev
```

## Building the Application

```bash
# Clone the repository
git clone https://github.com/GeorgiABInev/chat.git
cd cpp-chat-app

# Create a build directory
mkdir build
cd build

# Configure and build
cmake ..
make
```

## Running the Application

### Server

```bash
# Run the server on port 9000 with default database
./chat_server 9000

# Run the server on port 9000 with custom database
./chat_server 9000 --db=my_chat_history.db
```

### Client

```bash
# Connect to a server with a username
./chat_client 127.0.0.1 9000 YourUsername
```

## Server Commands

On the server you can use the following commands:

- `/help` - Show available commands
- `/clients` - Show connected clients
- `/kick <username> [reason]` - Kick a user from the server
- `/quit` - Exit the chat client

## Client Commands

While connected to the server, you can use the following commands:

- `/help` - Show available commands
- `/quit` - Exit the chat client

## Project Structure

- `chat.proto` - Protocol Buffers message definitions
- `chat_message.hpp` - Message encapsulation with Protocol Buffers
- `chat_client.cpp` - Client implementation
- `chat_server.cpp` - Server implementation
- `chat_participant.h` - Participant interface 
- `chat_room.h` and `chat_room.cpp` - Room implementation
- `chat_session.h` and `chat_session.cpp` - Session implementation
- `logger.h` and `logger.cpp` - Logger implementation
- `database.h` and `database.cpp` - Database access layer

## Database Schema

The application uses SQLite with the following schema:

### Users Table
Stores information about all users who have connected:
```sql
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    ip_address TEXT NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Messages Table
Stores all chat messages:
```sql
CREATE TABLE messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
```
