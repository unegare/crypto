#include <endian.h>

#include <iostream>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "KeyPairProvider.h" 

#include "miner.h"

std::optional<KeyPairProvider::KeyPair> ethMiner(std::string_view pattern, std::optional<std::string_view> priv_start, unsigned char step) {
  using KeyPair = KeyPairProvider::KeyPair;
  KeyPairProvider kpp;
  std::optional<KeyPair> okp = priv_start.has_value() ? kpp.getPairWithPriv(priv_start.value(), false) : kpp.getRandomPair(false);
  if (!okp) {
    return std::nullopt;
  }
  KeyPair kp = std::move(okp.value());
  size_t num = 0;
  auto ethAddr = kp.getEthAddr();
  BIGNUM *step_bn = BN_new();
  if (!step_bn) {
    return std::nullopt;
  }
//  std::unique_ptr<BIGNUM> step_bn = std::unique_ptr(BN_new(), BN_free);
  BN_bin2bn(&step, 1, step_bn);
  while (ethAddr && !ethAddr.value().starts_with(pattern)) {
    if (!kp.add(step_bn)) {
      BN_free(step_bn);
      return std::nullopt;
    }
    ethAddr = kp.getEthAddr();
    num++;
  }
  std::cout << "num: " << num << std::endl;
  BN_free(step_bn);
  return kp;
}

EthAddrMiner::EthAddrMiner(): kpp() { }
EthAddrMiner::~EthAddrMiner() { }

void EthAddrMiner::mine(std::string_view pttn, size_t thread_num, std::optional<std::string_view> priv_start) {
  using KeyPair = KeyPairProvider::KeyPair;
  std::vector<std::jthread> thread_pool;
  std::condition_variable cv;
  std::mutex m;
  std::vector<KeyPair> solutions;
  size_t recv_num = 0;
  for (size_t i = 0; i < thread_num; i++) {
    thread_pool.emplace_back([&]() {
      while(1) {
        std::optional<KeyPair> pair = ethMiner(pttn, priv_start, thread_num);
        if (pair.has_value()) {
          {
            std::scoped_lock lock(m);
            solutions.emplace_back(std::move(pair.value()));
          }
          cv.notify_one();
        }
      }
    });
  }

  while(1) {
    std::unique_lock lock(m);
    cv.wait(lock, [&]{return solutions.size() > recv_num;});
    while (recv_num < solutions.size()) {
      std::cout << solutions[recv_num] << std::endl;
      recv_num++;
    }
  }

}

