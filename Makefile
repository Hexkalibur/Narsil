# Narsil — Advanced Security Scanner
# Build: make all
# Clean: make clean

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I include \
           -Wno-stringop-truncation \
           -Wno-missing-field-initializers
LDFLAGS = -lws2_32 -liphlpapi -lwevtapi -lpsapi -lwintrust -lcrypt32

SRCS = src/main.c     \
       src/alert.c    \
       src/config.c   \
       src/events.c   \
       src/network.c  \
       src/process.c  \
       src/report.c   \
       src/kernel.c

TARGET = narsil.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	del /Q $(TARGET) 2>NUL || rm -f $(TARGET)