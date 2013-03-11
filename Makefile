obj-m := onlab-srv.o 
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
#onlab-srv.o: onlab-srv.o d3des.o dnscc_crypt.o
#	ld -r -o onlab-srv.o d3des.o dnscc_crypt.o
#d3des.o: d3des.c d3des.h
#dnscc_crypt.o: dnscc_crypt.c dnscc_h.h
#	$(MAKE) -C $(KDIR) M=$(PWD) modules
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
