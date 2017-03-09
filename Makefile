OBJS=test.o pcap_dealer.o get_device_addr.o eap_dealer.o md5.o utils.o udp_dealer.o config.o
EXE=main
CC=g++ -std=c++11

main: $(OBJS)
	$(CC) -g -Wall -o $(EXE) $(OBJS) -lpcap

test.o: def.h pcap_dealer.h get_device_addr.h
	$(CC) -c test.cpp

pcap_dealer.o: pcap_dealer.h sgudrcom_exception.h def.h
	$(CC) -c pcap_dealer.cpp

get_device_addr.o: get_device_addr.h def.h sgudrcom_exception.h
	$(CC) -c get_device_addr.cpp

eap_dealer.o: eap_dealer.h def.h pcap_dealer.h log.h utils.h
	$(CC) -c eap_dealer.cpp

md5.o: md5.h
	gcc -c md5.c

utils.o: utils.h get_device_addr.h md5.h log.h
	$(CC) -c utils.cpp

udp_dealer.o: udp_dealer.h def.h pcap_dealer.h log.h
	$(CC) -c udp_dealer.cpp

config.o: config.h
	$(CC) -c config.cpp

.PHONY: clean
clean:
	-rm -rf $(EXE) $(OBJS)
