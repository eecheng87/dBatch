all: so test

test:
	gcc -shared -o libdummy.so -fPIC dummy.c
	gcc -I../include -L$(PWD) -Wl,-rpath=$(PWD) -o test test.c -ldummy -lpthread
so:
	gcc -I../include -shared -fPIC preload.c -o preload.so -ldl -lpthread -lrt


.PHONY: clean test preload.so
clean:
	rm -f *.o test preload.so libdummy.so
