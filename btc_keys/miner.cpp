#include <endian.h>

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>

#include <cstdlib>

#include "KeyPairProvider.h" 

#include "miner.h"

std::optional<KeyPairProvider::KeyPair> ethMiner(std::string_view pattern, std::optional<std::string_view> priv_start, unsigned char step, bool next, uint64_t *offset) {
  using KeyPair = KeyPairProvider::KeyPair;
  KeyPairProvider kpp;
  std::optional<KeyPair> okp = priv_start.has_value() ? kpp.getPairWithPriv(std::string(priv_start.value()), false) : kpp.getRandomPair(false);
  if (!okp) {
    return std::nullopt;
  }
  KeyPair kp(std::move(okp.value()));
  uint64_t num = 0;
  std::optional<std::string_view> ethAddr;
  BIGNUM *step_bn = BN_new();
  if (!step_bn) {
    return std::nullopt;
  }
//  std::unique_ptr<BIGNUM> step_bn = std::unique_ptr(BN_new(), BN_free);
  if (!BN_bin2bn(&step, 1, step_bn)) {
    BN_free(step_bn);
    return std::nullopt;
  }
  if (next) {
    if (!kp.add(step_bn)) {
      BN_free(step_bn);
      return std::nullopt;
    }
    ethAddr = kp.getEthAddr();
  } else {
    ethAddr = kp.getEthAddr();
  }
  while (ethAddr && !ethAddr.value().starts_with(pattern)) {
    if (!kp.add(step_bn)) {
      BN_free(step_bn);
      return std::nullopt;
    }
    ethAddr = kp.getEthAddr();
    num++;
  }
//  std::cout << "num: " << num << std::endl;
  BN_free(step_bn);
  if (offset) *offset = num * step;
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
  std::vector<uint32_t> solution_finders;
  std::vector<uint64_t> offsets(thread_num);
  size_t recv_num = 0;
  std::chrono::time_point time_start = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < thread_num; i++) {
    thread_pool.emplace_back([&, i]() {
      char *start = NULL;
      if (priv_start.has_value()) {
        BIGNUM *bn = NULL;
        if (!BN_hex2bn(&bn, std::string(priv_start.value()).c_str())) {
          std::cerr << i << ": [" << std::this_thread::get_id() << "] BN_hex2bn failed" << std::endl;
          return;
        }
        BIGNUM *shift = BN_new();
        if (!shift) {
          BN_free(bn);
          std::cerr << i << ": [" << std::this_thread::get_id() << "] BN_new failed" << std::endl;
          return;
        }
        size_t ind = i;
        if (!BN_bin2bn(reinterpret_cast<unsigned char*>(&ind), 1, shift) || !BN_add(bn, bn, shift)) {
          BN_free(bn);
          BN_free(shift);
          std::cerr << i << ": [" << std::this_thread::get_id() << "] BN_bin2bn failed" << std::endl;
          return;
        }
        start = BN_bn2hex(bn);
        if (!start) {
          BN_free(bn);
          BN_free(shift);
          std::cerr << i << ": [" << std::this_thread::get_id() << "] BN_bn2hex failed" << std::endl;
          return;
        }
        BN_free(bn);
        BN_free(shift);
      }
      uint64_t offset;
      std::optional<KeyPair> pair = ethMiner(pttn, start, thread_num, false, &offset);
      offsets[i] += offset;
      free(start);
      while(pair.has_value()) {
        if (!pair.value().getPrivHex().has_value()) {
          break;
          std::cout << __PRETTY_FUNCTION__ << ":" << __LINE__ << ": failed to getPrivHex()" << std::endl;
        }
        std::string priv(pair.value().getPrivHex().value());
//        std::cout << "i: " << i << " | priv: " << priv << std::endl;
        {
          std::scoped_lock lock(m);
          solutions.emplace_back(std::move(pair.value()));
          solution_finders.push_back(i);
        }
        cv.notify_one();
        pair = ethMiner(pttn, priv, thread_num, true, &offset);
        offsets[i] += offset;
      }
      std::cout << std::this_thread::get_id() << " thread finished" << std::endl;
    });
  }

  while(1) {
    std::unique_lock lock(m);
    cv.wait(lock, [&]{return solutions.size() > recv_num;});
    std::chrono::time_point time_recv = std::chrono::high_resolution_clock::now();
    while (recv_num < solutions.size()) {
      std::cout << solution_finders[recv_num] << ": offset == " << std::setw(10) << offsets[solution_finders[recv_num]] << " | " << std::chrono::duration_cast<std::chrono::milliseconds>(time_recv - time_start).count() << " ms\n";
      std::cout << solutions[recv_num] << std::endl;
      recv_num++;
    }
  }
}

