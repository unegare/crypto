#include <sstream>
#include <iomanip>

#include <Message.h>

Message::Message(Message::MessageType type, int64_t timestamp, std::thread::id thread_id) noexcept: _type{type}, _timestamp{timestamp}, _thread_id{std::move(thread_id)} {}

Message::~Message() {}

Message::MessageType Message::getType() const noexcept {
  return _type;
}

std::thread::id Message::getThreadId() const noexcept {
  return _thread_id;
}

int64_t Message::getTimestamp() const noexcept {
  return _timestamp;
}

MessageNewRandomInitValueSet::MessageNewRandomInitValueSet(std::array<uint8_t, 32> initValue, int64_t timestamp, std::thread::id thread_id) noexcept:
      Message(MessageType::randomInitValueSet, timestamp, std::move(thread_id)), _initValue{std::move(initValue)} {}

MessageNewRandomInitValueSet::~MessageNewRandomInitValueSet() {}

const std::array<uint8_t, 32>& MessageNewRandomInitValueSet::getInitValue() const noexcept {
  return _initValue;
}

std::string MessageNewRandomInitValueSet::toJSON() const {
  std::ostringstream oss;
  oss << "{\n\t\"message\": \"new random init value is set\",\n\t\"thread_id\": " << std::dec << getThreadId()
    << ",\n\t\"timestamp\": " << std::dec << getTimestamp()
    << ",\n\t\"initValue\": \"";
  for (const auto el : _initValue) oss << std::hex << std::setw(2) << std::setfill('0') << (int)el;
  oss << "\"\n}";
  return std::move(oss.str());
}

MessageNewSolution::MessageNewSolution(std::array<uint8_t, 32> data, std::array<uint8_t, 32> hash, int64_t timestamp, std::thread::id thread_id) noexcept :
      Message(MessageType::newSolution, timestamp, std::move(thread_id)),
      _data{std::move(data)}, _hash{std::move(hash)} {}

MessageNewSolution::~MessageNewSolution() {}

const std::array<uint8_t, 32>& MessageNewSolution::getData() const noexcept {
  return _data;
}

const std::array<uint8_t, 32>& MessageNewSolution::getHash() const noexcept {
  return _hash;
}

std::string MessageNewSolution::toJSON() const {
  std::ostringstream oss;
  oss << "{\n\t\"message\": \"new solution was founded\",\n\t\"thread_id\": " << std::dec << getThreadId()
    << ",\n\t\"timestamp\": " << std::dec << getTimestamp() << ",\n\t\"hash\": \"";
  for (const auto el : _hash) oss << std::hex << std::setw(2) << std::setfill('0') << (int)el;
  oss << "\",\n\t\"data\": \"";
  for (const auto el : _data) oss << std::hex << std::setw(2) << std::setfill('0') << (int)el;
  oss << "\"\n}";
  return std::move(oss.str());
}
