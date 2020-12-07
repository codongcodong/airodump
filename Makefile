all: airodump

airodump: main.o analyzePacket.o
	g++ -o airodump main.o analyzePacket.o -lpcap -lcurses

main.o: main.cpp analyzePacket.h
	g++ -Wall -c -o main.o main.cpp 

analyzePacket.o: analyzePacket.cpp analyzePacket.h
	g++ -Wall -c -o analyzePacket.o analyzePacket.cpp 

clean:
	rm airodump *.o
