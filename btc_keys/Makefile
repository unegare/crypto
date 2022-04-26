CXX=g++-10
CFLAGS+=-Wall -O2 -std=c99
CXXFLAGS+=-Wall -O2 -std=c++20
LDFLAGS+=-lstdc++ -lssl -lcrypto -pthread


.PHONY: all
all: main.o miner.o KeyPairProvider.o libbase58/base58.o hash-library/keccak.o
	$(CXX) $^ ${LDFLAGS}

miner: main_miner.o miner.o KeyPairProvider.o libbase58/base58.o hash-library/keccak.o
	$(CXX) $^ ${LDFLAGS} -o miner

.PHONY: clean
clean:
	$(RM) -f *~ *.o ./**/*.o a.out miner
