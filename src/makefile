all: main.o
	gcc -o a.out main.o -Wall -lpcap -lcrypto

debug: main.o
	gcc -g -o a.out main.o -Wall -lpcap -lcrypto

main.o: main.c EAP.h EAPOL.h Ethernet.h
	gcc -c main.c

clean:
	rm -rf a.out *.o *~
	echo "clean done"
