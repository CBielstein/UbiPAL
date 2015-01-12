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

TESTFLAGS =

# If DEBUG=1 in build command, allow debugging
# else, optimize
ifeq ($(DEBUG), 1)
    CFLAGS += -g -O0
else
    CFLAGS += -O2
endif

ifeq ($(VALGRIND), 1)
    TESTFLAGS += valgrind --leak-check=full
endif

ifeq ($(GDB), 1)
    TESTFLAGS += gdb --args
endif

# include dependency info
-include $(SRCDEPS)
-include $(TESTDEPS)

# creates any needed directories
dir_guard = @mkdir -p $(@D)

.PHONY: help
help:
	echo "Use the following commands:\n\
           all: makes all files\n\
           test: runs unit tests\n\
           DEBUG=1: builds with symbols and no optimization\n\
           VALGRIND=1: runs the tests under valgrind\n\
           GDB=1: runs the tests under gdb\n"

.PHONY: all
all: $(OBJECTS) $(TEST_OBJECTS)

# build dependency files and places them in bin
$(BINDIR)/%.d: %.cpp
	$(dir_guard)
	$(CXX) $(CFLAGS) -MM -MT$(BINDIR)/$(<:.cpp=.o) $< > $@

# builds object files and places them in bin
%.o: $(%.cpp:$(BINDIR)/=./)
	$(dir_guard)
	$(CXX) $(CFLAGS) $< -o $@

$(BINDIR)/run_tests: $(OBJECTS) $(TEST_OBJECTS)
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(OBJECTS) $(TEST_OBJECTS) -o $(BINDIR)/run_tests $(LIBS)

.PHONY: test
# builds and runs the unit tests
test: $(BINDIR)/run_tests
	$(TESTFLAGS) $(BINDIR)/run_tests

.PHONY: clean
clean:
	rm -rf $(BINDIR)/*
