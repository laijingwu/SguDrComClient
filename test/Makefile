OBJS=time.o
EXE=main
CC=g++ -std=c++11

main: $(OBJS)
	$(CC) -g -Wall -o $(EXE) $(OBJS)

time.o:
	$(CC) -c time.cpp

.PHONY: clean
clean:
	-rm -rf $(EXE) $(OBJS)
