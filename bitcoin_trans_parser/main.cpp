#include <iostream>
#include <sstream>
#include <fstream>
#include <kaitai/kaitaistream.h>
#include "bitcoin_transaction.h"

int main () {
	try {
		std::ifstream fsstr("trans.bin", std::ifstream::binary);
		if (!fsstr.is_open()) {
			std::cout << "ERROR" << std::endl;
			return 0;
		} else {
			std::cout << "Ok" << std::endl;
		}
		kaitai::kstream ks(&fsstr);
		bitcoin_transaction_t data(&ks);
		std::cout << data.version() << std::endl;
		std::cout << data.toJSON() << std::endl;
		fsstr.close();
	} catch (std::exception &err) {
		std::cout << err.what() << std::endl;
	}
	return 0;
}
