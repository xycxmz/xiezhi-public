obj-m += xiezhi_driver.o
xiezhi_driver-y := src/xiezhi_main.o src/xiezhi_kprobes.o src/xiezhi_hooks.o \
		 src/xiezhi_ring.o src/xiezhi_trace.o

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
ccflags-y += -I$(src)/include

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
