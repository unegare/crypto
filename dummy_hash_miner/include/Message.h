#pragma once

#include <thread>
#include <array>
#include <string>

class Message {
public:
  enum class MessageType {
    randomInitValueSet,
    newSolution
  };
protected:
  MessageType _type;
  std::thread::id _thread_id;
  int64_t _timestamp;
public:
  Message() = delete;
  Message(MessageType, int64_t timestamp, std::thread::id) noexcept;
  virtual ~Message() = 0;

  virtual std::string toJSON() const = 0;

  MessageType getType() const noexcept;
  std::thread::id getThreadId() const noexcept;
  int64_t getTimestamp() const noexcept;
};

class MessageNewRandomInitValueSet : public Message {
  std::array<uint8_t, 32> _initValue;
public:
  MessageNewRandomInitValueSet(std::array<uint8_t, 32>,
      int64_t timestamp = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count(),
      std::thread::id = std::this_thread::get_id()) noexcept;
  virtual ~MessageNewRandomInitValueSet() override;

  virtual std::string toJSON() const override;

  const std::array<uint8_t, 32>& getInitValue() const noexcept;
};

class MessageNewSolution : public Message {
  std::array<uint8_t, 32> _data;
  std::array<uint8_t, 32> _hash;
  int64_t _timestamp;
public:
  MessageNewSolution(std::array<uint8_t, 32> _data, std::array<uint8_t, 32> _hash,
      int64_t timestamp = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count(),
      std::thread::id = std::this_thread::get_id()) noexcept;
  virtual ~MessageNewSolution() override;

  virtual std::string toJSON() const override;

  const std::array<uint8_t, 32>& getData() const noexcept;
  const std::array<uint8_t, 32>& getHash() const noexcept;
};
