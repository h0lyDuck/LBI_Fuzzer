.PHONY: clean
ARM_GCC_GLIBC = arm-linux-gnueabihf-gcc
ARM_GCC_UCLIBC = /usr/local/arm_eabi_uclibc_buildroot/bin/arm-buildroot-linux-uclibcgnueabi-gcc
MIPS_GCC_GLIBC = mips-linux-gnu-gcc
MIPS_GCC_UCLIBC = /usr/local/mips_uclibc_buildroot/bin/mips-buildroot-linux-uclibc-gcc
MIPSEL_GCC_GLIBC = mipsel-linux-gnu-gcc
MIPSEL_GCC_UCLIBC = /usr/local/mipsel_uclibc_buildroot/bin/mipsel-buildroot-linux-uclibc-gcc
RM = rm
# EXE = simple
# OBJS = main.o foo.o
# all: arm-glibc arm-uclibc mips-glibc mips-uclibc mipsel-glibc mipsel-uclibc
all: arm-glibc arm-uclibc
	@echo "make done"
arm-glibc: monitor.c hashtable.c cJSON.c
	$(ARM_GCC_GLIBC) monitor.c hashtable.c cJSON.c -lm -fPIC -shared -o ./bin/libmonitor.so.arm_glibc
	$(ARM_GCC_GLIBC) -o ./bin/process_monitor.arm_glibc process_monitor.c
arm-uclibc: monitor.c hashtable.c cJSON.c
	$(ARM_GCC_UCLIBC) monitor.c hashtable.c cJSON.c -lm -fPIC -shared -o ./bin/libmonitor.so.arm_uclibc
	$(ARM_GCC_UCLIBC) -o ./bin/process_monitor.arm_uclibc process_monitor.c
mips-glibc: monitor.c hashtable.c cJSON.c
	$(MIPS_GCC_GLIBC) monitor.c hashtable.c cJSON.c -lm -fPIC -shared -o./bin/libmonitor.so.mips_glibc
	$(MIPS_GCC_GLIBC) -o ./bin/process_monitor.mips_glibc process_monitor.c
mips-uclibc: monitor.c hashtable.c cJSON.c
	$(MIPS_GCC_UCLIBC) monitor.c hashtable.c cJSON.c -lm -fPIC -shared -o./bin/libmonitor.so.mips_uclibc
	$(MIPS_GCC_UCLIBC) -o ./bin/process_monitor.mips_uclibc process_monitor.c
mipsel-glibc: monitor.c hashtable.c cJSON.c
	$(MIPSEL_GCC_GLIBC) monitor.c hashtable.c cJSON.c -lm -fPIC -shared -o./bin/libmonitor.so.mipsel_glibc
	$(MIPSEL_GCC_GLIBC) -o ./bin/process_monitor.mipsel_glibc process_monitor.c
mipsel-uclibc: monitor.c hashtable.c cJSON.c
	$(MIPSEL_GCC_UCLIBC) monitor.c hashtable.c cJSON.c -lm -fPIC -shared -o./bin/libmonitor.so.mipsel_uclibc
	$(MIPSEL_GCC_UCLIBC) -o ./bin/process_monitor.mipsel_uclibc process_monitor.c
clean:
	$(RM) ./bin/*