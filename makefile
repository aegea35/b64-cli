CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = b64
SRC     = src/b64.c
DBGFLAGS = -Wall -Wextra -std=c11 -g -O0 -fsanitize=address,undefined
TESTS   = tests/run_tests.sh
TESTTARGET = b64-debug

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET) 

$(TESTTARGET): $(SRC)
	$(CC) $(DBGFLAGS) -o $(TESTTARGET) $(SRC)

debug: $(TESTTARGET)

test: $(TARGET)
	$(TESTS) ./$(TARGET)

test-debug: $(TESTTARGET)
	$(TESTS) ./$(TESTTARGET)

clean:
	rm -f $(TARGET) $(TESTTARGET)
