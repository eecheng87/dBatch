obj-m := batch.o
EXTRA_CFLAGS := -I$M/../include
batch.o : scTab.h
scTab.h:
	(grep -w sys_call_table /boot/System.map-`uname -r` | \
	  sed 's/\([^ ]*\) .*/#define smSCTab ((char *)0x\1UL)/'; \
	  sudo grep -w _vdso_data /boot/System.map-`uname -r` | \
      sed 's/\([^ ]*\) .*/#define vdsoDataAddr ((char *)0x\1UL)/'; \
	 grep -w system_wq      /boot/System.map-`uname -r` | \
	  sed 's/\([^ ]*\) .*/#define smSysWQ ((char *)0x\1UL)/') > scTab.h
