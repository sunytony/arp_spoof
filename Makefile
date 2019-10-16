all: arp_spoof

arp_spoof: main.o arp_spoof.o
	g++ -o arp_spoof main.o arp_spoof.o -lpcap

arp_spoof.o: arp_spoof.cpp
	g++ -c -o arp_spoof.o arp_spoof.cpp

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f arp_spoof *.o
