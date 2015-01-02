# Cameron Bielstein, 12/22/2014
# UbiPAL Makefile

CXX = g++
CFLAGS = -c -Wall -std=c++11
LIBS = -lcrypto
LDFLAGS =

# folders used in build
BINDIR = bin
SRCDIR = src
TESTDIR = test

# gather source files
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
HEADERS = $(wildcard $(SRCDIR)/*.h)
OBJECTS = $(addprefix $(BINDIR)/, $(SOURCES:.cpp=.o))
SRCDEPS = $(OBJECTS:.o=.d)

# gather test source files
TEST_SOURCES = $(wildcard $(TESTDIR)/*.cpp)
TEST_HEADERS = $(wildcard $(TESTDIR)/*.h)
TEST_OBJECTS = $(addprefix $(BINDIR)/, $(TEST_SOURCES:.cpp=.o))
TESTDEPS = $(TEST_OBJECTS:.o=.d)

# If DEBUG=1 in build command, allow debugging
# else, optimize
ifeq ($(DEBUG), 1)
    CFLAGS += -g -O0
else
    CFLAGS += -O2
endif

# include dependency info
-include $(SRCDEPS)
-include $(TESTDEPS)

# creates any needed directories
dir_guard = @mkdir -p $(@D)

all: $(OBJECTS)

# build dependency files and places them in bin
$(BINDIR)/%.d: %.cpp
	$(dir_guard)
	$(CXX) $(CFLAGS) -MM -MT$(BINDIR)/$(<:.cpp=.o) $< > $@

# builds object files and places them in bin
%.o: $(%.cpp:$(BINDIR)/=./)
	$(dir_guard)
	$(CXX) $(CFLAGS) $< -o $@

.PHONY: test
# builds and runs the unit tests
test: $(OBJECTS) $(TEST_OBJECTS)
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(OBJECTS) $(TEST_OBJECTS) -o $(BINDIR)/run_tests $(LIBS)
	$(BINDIR)/run_tests

.PHONY: clean
clean:
	rm -f $(BINDIR)/$(SRCDIR)/* $(BINDIR)/$(TESTDIR)/* $(BINDIR)/run_tests
