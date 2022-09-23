M_NAME := mtest
obj-m := ${M_NAME}.o
KERNEL := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C ${KERNEL} M=${PWD} modules

clean:
	make -C ${KERNEL} M=${PWD} clean

insert:
	insmod ${M_NAME}.ko

remove:
	rmmod ${M_NAME}

remake: remove clean all insert

listvma:
	echo listvma > /proc/mtest

findpage:
	echo findpage $(addr) > /proc/mtest

writeval:
	echo writeval $(addr) $(val) > /proc/mtest

test:
	gcc test.c -o test

rmtest:
	rm -f test