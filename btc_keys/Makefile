CFLAGS+=-Wall -O2 -std=c99
CXXFLAGS+=-Wall -O2 -std=c++17
LDFLAGS+=-lstdc++ -lssl -lcrypto

.PHONY: all
all: main.o KeyPairProvider.o libbase58/base58.o
	${CC} $^ ${LDFLAGS}

.PHONY: clean
clean:
	${RM} -f *~ *.o ./**/*.o a.out
