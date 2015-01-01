# Cameron Bielstein, 12/22/2014
# UbiPAL Makefile

CXX = g++
CFLAGS = -c -Wall -std=c++11
LIBS = -lcrypto
LDFLAGS =
SOURCES = src/rsa_wrappers.cpp src/error.cpp test/tests.cpp test/rsa_wrapper_tests.cpp test/test_helpers.cpp
HEADERS = src/rsa_wrappers.h src/error.h test/rsa_wrapper_tests.h test/test_helpers.h
OBJECTS = $(SOURCES:.cpp=.o)

ifeq ($(DEBUG), 1)
    CFLAGS += -g
endif

all: depend $(OBJECTS)

depend: .depend

.depend: $(SOURCES) $(HEADERS)
	rm -f ./.depend
	$(CXX) $(CFLAGS) -MM $^ >  ./.depend;

include ./.depend

%.o: %.cpp
	$(CXX) $(CFLAGS) $< -o $@

test: $(OBJECTS)
	rm -f bin/test
	$(CXX) $(LDFLAGS) $(OBJECTS) -o bin/test $(LIBS)
	bin/test

clean:
	rm -f bin/* ./.depend src/*.o test/*.o
