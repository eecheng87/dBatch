all: so test

test:
	gcc -shared -o libdummy.so -fPIC dummy.c
#	gcc -I../include -L$(PWD) -Wl,-rpath=$(PWD) -o test test.c -ldummy -lpthread
so:
	gcc -I../include -shared -fPIC preload.c -o preload.so -ldl -lpthread


.PHONY: clean preload.so
clean:
	rm -f *.o  preload.so libdummy.so
