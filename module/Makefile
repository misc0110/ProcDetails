MODULE_FILE := procdetails.ko

# Linux (default)
X86_ARCH := x86
X86_KDIR := /lib/modules/$(shell uname -r)/build

x86: ARCH := ${X86_ARCH}
x86: KDIR := ${X86_KDIR}
x86-clean : ARCH := $(X86_ARCH)

# Kernel module
obj-m := procdetails.o

# Build targets
all: x86
x86: build
x86-clean: clean

build:
	@make \
		ARCH=$(ARCH) \
		CROSS_COMPILE=$(CCPATH) \
		-C $(KDIR) \
		M=$(PWD) \
		modules

clean:
	@rm -rf \
		*.o \
		*.ko \
		*.mod.c \
		modules.order \
		Module.symvers 