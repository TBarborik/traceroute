CC=g++
CFLAGS=-std=c++11 -Wall -Wextra -pedantic

main: trace

trace: trace.cpp
	$(CC) $(CFLAGS) -o $@ $?