// chat_message.hpp
#ifndef CHAT_MESSAGE_HPP
#define CHAT_MESSAGE_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <netinet/in.h> // For htonl and ntohl
#include "chat.pb.h"

class chat_message {
public:
  static constexpr std::size_t header_length = 4;

  chat_message() : body_length_(0) {
    data_.resize(header_length);
  }

  // Data access for raw buffer
  const char* data() const {
    return data_.data();
  }

  char* data() {
    return data_.data();
  }

  std::size_t length() const {
    return header_length + body_length_;
  }

  const char* body() const {
    return data() + header_length;
  }

  char* body() {
    return data() + header_length;
  }

  std::size_t body_length() const {
    return body_length_;
  }

  void body_length(std::size_t length) {
    body_length_ = length;
    if (data_.size() < header_length + body_length_)
      data_.resize(header_length + body_length_);
  }

  bool decode_header() {
    uint32_t msg_size = 0;
    std::memcpy(&msg_size, data(), header_length);
    body_length_ = ntohl(msg_size);

    if (body_length_ > max_body_length) {
      body_length_ = 0;
      return false;
    }

    if (data_.size() < header_length + body_length_)
      data_.resize(header_length + body_length_);

    return true;
  }

  void encode_header() {
    uint32_t network_order = htonl(static_cast<uint32_t>(body_length_));
    std::memcpy(data(), &network_order, header_length);
  }

  // Protobuf specific methods
  bool set_protobuf_message(const chat::ChatPacket& packet) {
    std::string serialized;
    if (!packet.SerializeToString(&serialized))
      return false;

    body_length(serialized.size());
    std::memcpy(body(), serialized.data(), serialized.size());
    encode_header();
    return true;
  }

  bool get_protobuf_message(chat::ChatPacket& packet) const {
    return packet.ParseFromArray(body(), body_length());
  }

private:
  std::vector<char> data_;
  std::size_t body_length_;
  static constexpr std::size_t max_body_length = 4096; // Larger to accommodate protobuf
};

#endif // CHAT_MESSAGE_HPP
