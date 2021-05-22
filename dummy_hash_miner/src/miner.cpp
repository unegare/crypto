#include <iterator>
#include <iomanip>
#include <sstream>
#include <random>
#include <chrono>
#include <new>

#include <miner.h>
#include <log.h>
#include <sighandlers.h>

namespace miner {

size_t numOfZeros = 3;

std::mutex m_recieved;
std::condition_variable cv;
std::atomic_bool ready = false;
std::list<std::unique_ptr<Message>> messages;

std::random_device rd;
//std::mt19937_64 g(rd());

static inline bool isFound(const unsigned char * const res) {
  for (int i = 32 - numOfZeros; i < 32; i++) {
    if (res[i]) return false;
  }
  return true;
}

void Task::operator() (){
  SHA256_Init(&ctx);

  uint8_t arr[32] = {0,};
  uint8_t res[32] = {1,};

  while (!sighandlers::flagToExit) {
    arr[16 + rd()%16] = rd();
    {
      std::array<uint8_t, 32> initValue;
      std::copy(std::cbegin(arr), std::cend(arr), std::begin(initValue));

      std::unique_lock lk(m_recieved);
      try {
        messages.emplace_back(std::make_unique<MessageNewRandomInitValueSet>(std::move(initValue)));
      } catch(const std::exception &ex) {
        BOOST_LOG_TRIVIAL(error) << std::this_thread::get_id() << ": " << ex.what() << std::endl;
      }
      ready = true;
      lk.unlock();
      cv.notify_one();
    }
    do {
      do {
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, arr, 32);
        SHA256_Final(res, &ctx);
        if (isFound(res)) {
          std::array<uint8_t, 32> data, hash;
          std::copy(std::begin(arr), std::end(arr), std::begin(data));
          std::copy(std::begin(res), std::end(res), std::begin(hash));

          std::unique_lock lk(m_recieved);
          try {
            messages.emplace_back(std::make_unique<MessageNewSolution>(std::move(data), std::move(hash)));
          } catch (const std::exception &ex) {
            BOOST_LOG_TRIVIAL(error) << std::this_thread::get_id() << ": " << ex.what() << std::endl;
          }
          ready = true;
          lk.unlock();
          cv.notify_one();
        }
      } while(++*(uint64_t*)arr && !sighandlers::flagToExit);
    } while (++(*(uint64_t*)(arr+1)) && !sighandlers::flagToExit);
  }
  cv.notify_one();
}

}
