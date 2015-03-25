# Cameron Bielstein, 12/22/2014
# UbiPAL Makefile

CXX = g++
CFLAGS = -c -Wall -std=c++11 -fPIC
LIBS = -lcrypto -luuid -lpthread
LDFLAGS =

# folders used in build
BINDIR = bin
SRCDIR = src
TESTDIR = test
EXDIR = examples
INCLUDE_DIR = /usr/include
LIBRARY_DIR = /usr/lib

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

# gather example source files
EXAMPLE_SOURCES = $(wildcard $(EXDIR)/*.cpp)
EXAMPLE_SOURCES += $(wildcard $(EXDIR)/telephone/*.cpp)
EXAMPLE_SOURCES += $(wildcard $(EXDIR)/sinewave/*.cpp)
EXAMPLE_SOURCES += $(wildcard $(EXDIR)/push/*.cpp)
EXAMPLE_OBJECTS = $(addprefix $(BINDIR)/, $(EXAMPLE_SOURCES:.cpp=.o))
EXDEPS = $(EXAMPLE_OBJECTS:.o=.d)

TESTFLAGS =

# If DEBUG=1 in build command, allow debugging
# else, optimize
ifeq ($(DEBUG), 1)
    CFLAGS += -ggdb -O0
else
    CFLAGS += -O2
endif

ifeq ($(VALGRIND), 1)
    TESTFLAGS += valgrind --leak-check=full
endif

ifeq ($(GDB), 1)
    TESTFLAGS += gdb --args
endif

EVAL_FLAG =
ifeq ($(EVAL), 1)
    EVAL_FLAG += -D EVALUATE
endif

# creates any needed directories
dir_guard = @mkdir -p $(@D)
lib_dir_guard = @mkdir -p $(INCLUDE_DIR)/ubipal

$(BINDIR)/libubipal.so.1.0: $(OBJECTS)
	$(dir_guard)
	$(CXX) -shared -fPIC -Wl,-soname,libubipal.so.1 -o $(BINDIR)/libubipal.so.1.0 $(OBJECTS) $(LIBS) $(EVAL_FLAG)

.PHONY: lib
lib: $(BINDIR)/libubipal.so.1.0

.PHONY: install
install: lib uninstall
	$(lib_dir_guard)
	cp $(HEADERS) $(INCLUDE_DIR)/ubipal
	mv bin/libubipal.so.1.0 $(LIBRARY_DIR)
	ln -sf $(LIBRARY_DIR)/libubipal.so.1.0 $(LIBRARY_DIR)/libubipal.so.1
	ln -sf $(LIBRARY_DIR)/libubipal.so.1.0 $(LIBRARY_DIR)/libubipal.so

.PHONY: all
all: lib examples $(BINDIR)/run_tests

.PHONY: help
help:
	@echo "Use the following commands:\n\
           lib: Create the dynamicly linked library\n\
           install: (might need sudo) copies necessary headers and libraries in to /usr/include and /usr/lib\n\
           uninstall: (might need sudo) removies headers and libraries from /usr/include and /usr/lib\n\
           all: makes all files\n\
           test: runs unit tests\n\
           clean: deletes all files generated by builds\n\
           DEBUG=1: builds with symbols and no optimization\n\
           VALGRIND=1: runs the tests under valgrind\n\
           GDB=1: runs the tests under gdb\n\
           EVAL=1: Compiles additional evaluation code.\n"

# include dependency info
-include $(SRCDEPS)
-include $(TESTDEPS)
-include $(EXDEPS)

# build dependency files and places them in bin
$(BINDIR)/%.d: %.cpp
	$(dir_guard)
	$(CXX) $(CFLAGS) -MM -MT $(BINDIR)/$(<:.cpp=.o) $< > $@

# builds object files and places them in bin
%.o: $(%.cpp:$(BINDIR)/=./)
	$(dir_guard)
	$(CXX) $(CFLAGS) $< -o $@ $(EVAL_FLAG)

$(BINDIR)/run_tests: $(OBJECTS) $(TEST_OBJECTS)
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(OBJECTS) $(TEST_OBJECTS) -o $(BINDIR)/run_tests $(LIBS) $(EVAL_FLAG)

.PHONY: test
# builds and runs the unit tests
test: $(BINDIR)/run_tests
	$(TESTFLAGS) $(BINDIR)/run_tests

.PHONY: examples
examples: $(BINDIR)/$(EXDIR)/sender $(BINDIR)/$(EXDIR)/receiver $(BINDIR)/$(EXDIR)/create_service $(BINDIR)/$(EXDIR)/delegator $(BINDIR)/$(EXDIR)/print_id $(BINDIR)/$(EXDIR)/confirmer $(BINDIR)/$(EXDIR)/telephone/house $(BINDIR)/$(EXDIR)/telephone/bed $(BINDIR)/$(EXDIR)/telephone/phone $(BINDIR)/$(EXDIR)/telephone/caller $(BINDIR)/$(EXDIR)/sinewave/producer $(BINDIR)/$(EXDIR)/sinewave/display $(BINDIR)/$(EXDIR)/sinewave/delegator $(BINDIR)/$(EXDIR)/push/producer $(BINDIR)/$(EXDIR)/push/consumer

$(BINDIR)/$(EXDIR)/push/consumer: $(BINDIR)/$(EXDIR)/push/consumer.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/push/consumer.o -o $(BINDIR)/$(EXDIR)/push/consumer $(LIBS) -lubipal

$(BINDIR)/$(EXDIR)/push/producer: $(BINDIR)/$(EXDIR)/push/producer.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/push/producer.o -o $(BINDIR)/$(EXDIR)/push/producer $(LIBS) -lubipal

$(BINDIR)/$(EXDIR)/telephone/house: $(BINDIR)/$(EXDIR)/telephone/house.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/telephone/house.o -o $(BINDIR)/$(EXDIR)/telephone/house $(LIBS) -lubipal

$(BINDIR)/$(EXDIR)/telephone/bed: $(BINDIR)/$(EXDIR)/telephone/bed.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/telephone/bed.o -o $(BINDIR)/$(EXDIR)/telephone/bed $(LIBS) -lubipal

$(BINDIR)/$(EXDIR)/telephone/phone: $(BINDIR)/$(EXDIR)/telephone/phone.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/telephone/phone.o -o $(BINDIR)/$(EXDIR)/telephone/phone $(LIBS) -lubipal

$(BINDIR)/$(EXDIR)/telephone/caller: $(BINDIR)/$(EXDIR)/telephone/caller.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/telephone/caller.o -o $(BINDIR)/$(EXDIR)/telephone/caller $(LIBS) -lubipal

$(BINDIR)/$(EXDIR)/sinewave/delegator: $(BINDIR)/$(EXDIR)/sinewave/delegator.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/sinewave/delegator.o -o $(BINDIR)/$(EXDIR)/sinewave/delegator $(LIBS) -lubipal

$(BINDIR)/$(EXDIR)/sinewave/producer: $(BINDIR)/$(EXDIR)/sinewave/producer.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/sinewave/producer.o -o $(BINDIR)/$(EXDIR)/sinewave/producer $(LIBS) -lubipal

$(BINDIR)/$(EXDIR)/sinewave/display: $(BINDIR)/$(EXDIR)/sinewave/display.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/sinewave/display.o -o $(BINDIR)/$(EXDIR)/sinewave/display $(LIBS) -lubipal

$(BINDIR)/$(EXDIR)/sender: $(BINDIR)/$(EXDIR)/sender.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/sender.o -o $(BINDIR)/$(EXDIR)/sender $(LIBS) -lubipal

.PHONY: sender
sender: $(BINDIR)/$(EXDIR)/sender

$(BINDIR)/$(EXDIR)/receiver: $(BINDIR)/$(EXDIR)/receiver.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/receiver.o -o $(BINDIR)/$(EXDIR)/receiver $(LIBS) -lubipal

.PHONY: receiver
receiver: $(BINDIR)/$(EXDIR)/receiver

$(BINDIR)/$(EXDIR)/create_service: $(BINDIR)/$(EXDIR)/create_service.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/create_service.o -o $(BINDIR)/$(EXDIR)/create_service $(LIBS) -lubipal

.PHONY: create_service
receiver: $(BINDIR)/$(EXDIR)/create_service

$(BINDIR)/$(EXDIR)/delegator: $(BINDIR)/$(EXDIR)/delegator.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/delegator.o -o $(BINDIR)/$(EXDIR)/delegator $(LIBS) -lubipal

.PHONY: delegator
receiver: $(BINDIR)/$(EXDIR)/delegator

$(BINDIR)/$(EXDIR)/print_id: $(BINDIR)/$(EXDIR)/print_id.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/print_id.o -o $(BINDIR)/$(EXDIR)/print_id $(LIBS) -lubipal

.PHONY: print_id
receiver: $(BINDIR)/$(EXDIR)/print_id

$(BINDIR)/$(EXDIR)/confirmer: $(BINDIR)/$(EXDIR)/confirmer.o
	$(dir_guard)
	$(CXX) $(LDFLAGS) $(BINDIR)/$(EXDIR)/confirmer.o -o $(BINDIR)/$(EXDIR)/confirmer $(LIBS) -lubipal

.PHONY: confirmer
receiver: $(BINDIR)/$(EXDIR)/confirmer

.PHONY: clean
clean:
	rm -rf $(BINDIR)/*

uninstall:
	rm -rf $(INCLUDE_DIR)/ubipal
	rm -rf $(LIBRARY_DIR)/libubipal.so*
