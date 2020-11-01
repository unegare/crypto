#include <optional>
#include <iostream>

#include "KeyPairProvider.h"

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
  using KeyPair = KeyPairProvider::KeyPair;
  KeyPairProvider kpp;
  //std::optional<KeyPair> k = kpp.getRandomPair();
  std::optional<KeyPair> k = kpp.getPairWithPriv("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D", false);
  if (!k.has_value()) {
    std::cout << "Error" << std::endl;
  } else {
    std::cout << k;
  }
  return 0;
}
