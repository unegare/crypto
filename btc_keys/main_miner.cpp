#include <iostream>
#include <iomanip>

#include "miner.h"
#include "KeyPairProvider.h"

int main() {
  EthAddrMiner eam;
  eam.mine("0xffff", 16, "0000000000000000000000000000000000000000000000000000000000000001");
  return 0;
}
