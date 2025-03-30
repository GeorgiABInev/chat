#ifndef CHATPARTICIPANT_H
#define CHATPARTICIPANT_H

#include <iostream>

#include "chat_message.hpp"

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

#endif // CHATPARTICIPANT_H