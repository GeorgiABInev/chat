cmake_minimum_required(VERSION 3.10)
project(ProtobufChat CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(Protobuf REQUIRED)
find_package(SQLite3 REQUIRED)  # Add SQLite3

# Generate protobuf files
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS chat.proto)

# Include directories
include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${Protobuf_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
    ${SQLite3_INCLUDE_DIRS}  # Add SQLite3 includes
)

# Server executable
add_executable(chat_server
    chat_server.cpp
    chat_room.cpp
    chat_session.cpp
    database.cpp  # Add new database file
    logger.cpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

target_link_libraries(chat_server
    ${Protobuf_LIBRARIES}
    ${Boost_LIBRARIES}
    ${SQLite3_LIBRARIES}  # Add SQLite3 library
    pthread
)

# Client executable
add_executable(chat_client
    chat_client.cpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

target_link_libraries(chat_client
    ${Protobuf_LIBRARIES}
    ${Boost_LIBRARIES}
    pthread
)

# Copy the proto file to the build directory for easier access
configure_file(chat.proto ${CMAKE_CURRENT_BINARY_DIR}/chat.proto COPYONLY)
