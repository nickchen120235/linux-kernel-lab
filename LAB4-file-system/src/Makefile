M_NAME := myromfs
obj-m := ${M_NAME}.o
${M_NAME}-y := storage.o super.o
KERNEL := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C ${KERNEL} M=${PWD} modules

clean:
	make -C ${KERNEL} M=${PWD} clean

insert:
	insmod ${M_NAME}.ko hide=${hide} enc=${enc} exec=${exec}

remove:
	rmmod ${M_NAME}

remake: umount remove clean all

mount:
	mount -o loop ./test.img ./mountpoint

umount:
	umount ./mountpoint

module_test:
	insmod ${M_NAME}.ko hide=bbbbb enc=aaaaa exec=ccccc

test: module_test mount

genrom:
	genromfs -f test.img -d testromfs