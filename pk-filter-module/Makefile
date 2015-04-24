KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)


ccflags-y :=  -I$(LDDINC)

obj-m += pk-filter.o

all:
	make -C $(KERNELDIR) M=$(PWD) LDDINC=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

