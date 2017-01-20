CC 		= gcc
INCLUDES 	= -I /home/vasilis/Desktop/wids
OBJECTS		= broadcast monitor pskgen test aes

build: $(OBJECTS)
	
clean:
	rm -f broadcast monitor pskgen test aes

# Comms

broadcast: broadcast.c
	$(CC) -o broadcast broadcast.c aes.c -lpcap -lpthread $(INCLUDES)

monitor: monitor.c
	

pskgen: pskgen.c
	$(CC) -o pskgen pskgen.c -lpcap -lpthread $(INCLUDES)

aes: aes.c aes.h
	$(CC) -o aes -c aes.c -Wall -Os -Wl,-Map,test.map $(INCLUDES)

# ML

collectdata: collectdata.c
	$(CC) -o collectdata collectdata.c $(INCLUDES)

# Misc

test: test.c
	$(CC) -o test test.c -lpcap -lpthread $(INCLUDES)



