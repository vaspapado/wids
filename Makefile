CC 		= gcc
INCLUDES 	= -I /home/vasilis/Desktop/wids
OBJECTS		= broadcast monitor test aes

build: $(OBJECTS)
	
clean:
	rm -f broadcast monitor test aes

broadcast: broadcast.c
	$(CC) -o broadcast broadcast.c aes.c -lpcap -lpthread $(INCLUDES)

monitor: monitor.c
	$(CC) -o monitor monitor.c -lpcap -lpthread $(INCLUDES)

test: test.c
	$(CC) -o test test.c -lpcap -lpthread $(INCLUDES)

aes: aes.c aes.h
	$(CC) -o aes -c aes.c -Wall -Os -Wl,-Map,test.map $(INCLUDES)


