CC 		= gcc
INCLUDES 	= -I /home/vasilis/Desktop/wids
OBJECTS		= broadcast monitor pskgen aes collectdata mkproclist gensequences

build: $(OBJECTS)
	
clean:
	rm -f $(OBJECTS)
	rm -f *.o *.key *.dat

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
ifeq ($(DEBUG),true)
	$(CC) -DDEBUG -o collectdata collectdata.c $(INCLUDES)
else
	$(CC) -o collectdata collectdata.c $(INCLUDES)
endif

gensequences: gensequences.c
	$(CC) -o gensequences gensequences.c $(INCLUDES)

