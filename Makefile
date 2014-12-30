# Cameron Bielstein, 12/22/2014
# UbiPAL Makefile

CXX = g++
test_files = test/tests.cpp test/rsa_wrapper_tests.cpp
tested_files = src/rsa_wrappers.cpp

CFLAGS = -std=c++11 -lcrypto

ifeq ($(DEBUG), 1)
    CFLAGS += -g
endif

test: bin/tests
	bin/tests
	rm -f bin/tests

bin/tests: $(test_files) $(tested_files)
	$(CXX) test/tests.cpp $(tested_files) -o bin/tests $(CFLAGS)

clean:
	rm -f bin/*
