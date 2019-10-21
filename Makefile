all: arp_spoof

arp_spoof: main.o arp_spoof.o getgateway.o
	g++ -o arp_spoof main.o arp_spoof.o getgateway.o -lpcap -ldl

arp_spoof.o: arp_spoof.cpp
	g++ -c -o arp_spoof.o arp_spoof.cpp

main.o: main.cpp
	g++ -c -o main.o main.cpp

getgateway.o: getgateway.cpp
	g++ -c -o getgateway.o getgateway.cpp

clean:
	rm -f arp_spoof *.o
