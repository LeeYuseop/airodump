all: airodump

airodump: airodump.cpp
	g++ -o airodump airodump.cpp -lpcap

clean:
	rm -f airodump *.o
