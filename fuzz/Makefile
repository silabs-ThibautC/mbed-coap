# Makefile for the mbed-coap parser fuzzer
# To be used with AFL++

# Use separate compilers for C and C++ code.
CXX = afl-clang-fast++
CC = afl-clang-fast

# Sanitizers are highly recommended to find more bugs.
# AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan)
# The user requested "all memory checks" -> ASan is the way to go.
AFL_FLAGS = -g -fsanitize=address,undefined --coverage

# Include paths for the library and stubs.
CFLAGS = -I.. -I../source/include -I../test/mbed-coap/unittest/stubs -I. -I../mbed-coap
CXXFLAGS = $(CFLAGS)

# Define C and C++ source files separately.
C_SRCS := \
	../source/sn_coap_parser.c \
	../test/mbed-coap/unittest/stubs/sn_coap_protocol_stub.c \
	../test/mbed-coap/unittest/stubs/sn_coap_builder_stub.c \
	../test/mbed-coap/unittest/stubs/sn_coap_header_check_stub.c \
	../test/mbed-coap/unittest/stubs/ns_list_stub.c \
	fuzzer.c

CPP_SRCS := ../test/mbed-coap/unittest/stubs/randLIB_stub.cpp

# Create object file lists from source lists.
C_OBJS = $(C_SRCS:.c=.o)
CPP_OBJS = $(CPP_SRCS:.cpp=.o)
OBJS = $(C_OBJS) $(CPP_OBJS)

# The target executable
TARGET = parser_fuzzer

.PHONY: all clean

all: $(TARGET)

# Linking step: Use the C++ compiler to link everything together.
$(TARGET): $(OBJS)
	$(CXX) $(AFL_FLAGS) $(OBJS) -o $(TARGET)

# C compilation rule: Compile .c files with the C compiler.
%.o: %.c
	$(CC) $(AFL_FLAGS) $(CFLAGS) -c $< -o $@

# C++ compilation rule: Compile .cpp files with the C++ compiler.
%.o: %.cpp
	$(CXX) $(AFL_FLAGS) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS) 