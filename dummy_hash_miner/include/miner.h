#pragma once

#include <iostream>
#include <list>
#include <array>
#include <utility>
#include <thread>
#include <memory>
#include <mutex>
#include <atomic>
#include <condition_variable>

#include <openssl/sha.h>

#include <Message.h>

namespace miner {

extern size_t numOfZeros;
extern std::mutex m_recieved;
extern std::condition_variable cv;
extern std::atomic_bool ready;

extern std::list<std::unique_ptr<Message>> messages;

class Task {
  SHA256_CTX ctx;
public:
  Task() = default;
  ~Task() = default;

  void operator() ();
};

}
