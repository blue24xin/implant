CC = gcc
SOURCE = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SOURCE))

#LIB = -lpthread

CTAGS = -g
send_http:$(BOJS)
		$(CC) $(SOURCE) $(LIB) $(CTAGS)  $(GLIB)  $(INCLUDE) -o   $@

clean:
	rm -rf *.o
	rm -rf .*.sw*
	rm -rf send_http 

