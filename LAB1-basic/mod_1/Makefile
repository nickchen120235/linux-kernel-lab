obj-m := mod_1.o
KERNEL := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
M_NAME := mod_1

all:
	make -C ${KERNEL} M=${PWD} modules

clean:
	make -C ${KERNEL} M=${PWD} clean

insert:
	insmod ${M_NAME}.ko

remove:
	rmmod ${M_NAME}