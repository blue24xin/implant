CC = gcc
SOURCE = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SOURCE))

#LIB = -lpthread

CTAGS = -g
ctron_client:$(BOJS)
		$(CC) $(SOURCE) $(LIB) $(CTAGS)  $(GLIB)  $(INCLUDE) -o   $@

clean:
	rm -rf *.o
	rm -rf .*.sw*
	rm -rf ctron_client 

