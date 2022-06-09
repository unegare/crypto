#include <optional>
#include <iostream>
#include <chrono>

#include "KeyPairProvider.h"
#include "miner.h"

template<typename T>
std::ostream& operator<< (std::ostream &os, const std::optional<T> &t) {
  if (t.has_value()) {
    os << t.value();
  } else {
    os << "std::nullopt\n";
  }
  return os;
}

int main()
{
  
//  using KeyPair = KeyPairProvider::KeyPair;
//  KeyPairProvider kpp;
////  std::optional<KeyPair> k = kpp.getPairWithPriv("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D", false);
//  std::optional<KeyPair> k = kpp.getPairWithPriv("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", false);
//  std::optional<KeyPair> k1 = kpp.getRandomPair();
//  std::cout << k << '\n' << k1;
//
////  return 0;
//
//  std::chrono::time_point t0 = std::chrono::high_resolution_clock::now();
//  std::optional k2 = ethMiner("0xa", std::nullopt);
//  std::chrono::time_point t1 = std::chrono::high_resolution_clock::now();
//  std::cout << '\n' << k2;
//
//  std::cout << "\n\nduration: " << std::chrono::duration<double, std::milli>(t1 -t0).count() << " ms" << std::endl;

  EthAddrMiner miner;
  miner.mine("0xaabb", 16, "761898019c0dd12b981e37b1f3f484cfe506f77b9c36061a01bfdaea5bd91eb1");

  return 0;
}
