#include <optional>
#include <string_view>

#include "KeyPairProvider.h"

std::optional<KeyPairProvider::KeyPair> ethMiner(std::string_view pattern, std::optional<std::string_view> priv_start = std::nullopt, unsigned char step = 1, bool next = false, uint64_t *offset = nullptr);

class EthAddrMiner {
  KeyPairProvider kpp;
public:
  EthAddrMiner();
  ~EthAddrMiner();

  void mine(std::string_view pttn, size_t thread_num, std::optional<std::string_view> priv_start = std::nullopt);
};
