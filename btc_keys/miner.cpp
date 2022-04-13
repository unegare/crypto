#include <iostream>
#include "KeyPairProvider.h" 

std::optional<KeyPairProvider::KeyPair> ethMiner(std::string_view pattern) {
  using KeyPair = KeyPairProvider::KeyPair;
  KeyPairProvider kpp;
  std::optional<KeyPair> okp = kpp.getRandomPair(false);
  if (!okp) {
    return std::nullopt;
  }
  KeyPair kp = std::move(okp.value());
  size_t num = 0;
  while (kp.getEthAddr() && !kp.getEthAddr().value().starts_with(pattern)) {
    if (!kp.inc()) {
      return std::nullopt;
    }
    num++;
  }
  std::cout << "num: " << num << std::endl;
  return kp;
}
