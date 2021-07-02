all: so test

test:
	gcc -shared -o libdummy.so -fPIC dummy.c
#	gcc -I../include -L$(PWD) -Wl,-rpath=$(PWD) -o test test.c -ldummy -lpthread
so:
	gcc -fPIC -shared -o preload.so preload.c vdso64.so -lpthread -ldl


.PHONY: clean preload.so
clean:
	rm -f *.o  preload.so libdummy.so
