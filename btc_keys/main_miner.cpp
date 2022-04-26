#include <iostream>
#include <iomanip>

#include "miner.h"
#include "KeyPairProvider.h"

int main() {
  EthAddrMiner eam;
  eam.mine("0xffffff", 16);
  return 0;
}
