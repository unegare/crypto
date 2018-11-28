all: main.cpp bitcoin_transaction.cpp
	g++ ./main.cpp ./bitcoin_transaction.cpp -lcrypto -lkaitai_struct_cpp_stl_runtime -lfc_light -I../../kaitai_struct_cpp_stl_runtime/ -I../../array-io-keychain/libraries/fc_light/include/ -lboost_system -lboost_filesystem -lboost_chrono -lboost_date_time -L. -L../../array-io-keychain/libraries/fc_light/build/ -Wl,-rpath,.

