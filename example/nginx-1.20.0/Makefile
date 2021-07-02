
default:	build

clean:
	rm -rf Makefile objs

.PHONY:	default clean

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/usr/sbin/nginx -t

	kill -USR2 `cat /var/run/nginx.pid`
	sleep 1
	test -f /var/run/nginx.pid.oldbin

	kill -QUIT `cat /var/run/nginx.pid.oldbin`

.PHONY:	build install modules upgrade
