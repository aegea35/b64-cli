CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = b64
SRC     = b64.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)