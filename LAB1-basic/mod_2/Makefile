M_NAME := mod_2
obj-m := ${M_NAME}.o
KERNEL := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C ${KERNEL} M=${PWD} modules

clean:
	make -C ${KERNEL} M=${PWD} clean

insert:
	insmod ${M_NAME}.ko my_int=${my_int} my_string=${my_string} my_int_array=${my_int_array}

remove:
	rmmod ${M_NAME}