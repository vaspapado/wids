CC 		= gcc
INCLUDES 	= -I /home/vasilis/Desktop/wids
OBJECTS		= broadcast monitor pskgen aes

build: $(OBJECTS)
	
clean:
	rm -f broadcast monitor pskgen aes mkproclist collectdata

# Comms

broadcast: broadcast.c
	$(CC) -o broadcast broadcast.c aes.c -lpcap -lpthread $(INCLUDES)

monitor: monitor.c
	$(CC) -o monitor monitor.c aes.c -lpcap -lpthread $(INCLUDES)

pskgen: pskgen.c
	$(CC) -o pskgen pskgen.c $(INCLUDES)

aes: aes.c aes.h
	$(CC) -o aes -c aes.c -Wall -Os -Wl,-Map,test.map $(INCLUDES)

# ML

mkproclist: mkproclist.c
	$(CC) -o mkproclist mkproclist.c $(INCLUDES)

collectdata: collectdata.c
	$(CC) -o collectdata collectdata.c $(INCLUDES)


