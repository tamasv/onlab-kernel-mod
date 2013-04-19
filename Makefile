obj-m := onlab.o
onlab-objs := onlab-srv.o lib/d3des.o dnscc_crypt.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf lib/*.o
