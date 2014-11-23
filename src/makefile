all: main.o
	gcc -o a.out main.o -Wall -lpcap

main.o: main.c EAP.h EAPOL.h Ethernet.h
	gcc -c main.c

clean:
	rm -rf a.out *.o
	echo "clean done"
