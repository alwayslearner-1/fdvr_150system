CC = arm-none-linux-gnueabi-gcc
CXX = arm-none-linux-gnueabi-g++
STRIP = arm-none-linux-gnueabi-strip

## Application compile options
#TARGET = SamIPCTest
TARGET = SamP2PClient
#TARGET = SamDVRClient

#For IPC and Framer functions test
ifeq ($(TARGET), SamIPCTest)
#SAMFLAGS += -D_API_TEST
SAMFLAGS += -D_FRAMER_TEST
SRCS = 
OBJS = 
endif

#For P2PClient
ifeq ($(TARGET), SamP2PClient)
SAMFLAGS += -D_P2PCLIENT
LIBS = -L./P2PClient -lP2PDevice
SRCS = P2PClient/P2PClient.c
SRCS += P2PClient/utils.c
OBJS = P2PClient/P2PClient.o
OBJS += P2PClient/utils.o
endif

#For DVRClient
ifeq ($(TARGET), SamDVRClient)
SAMFLAGS += -D_DVRCLIENT
LIBS = -L./DVRClient -lttxdvrnet
SRCS = DVRClient/DVRClient.c
OBJS = DVRClient/DVRClient.o
endif

CCFLAGS = $(SAMFLAGS) -pipe -Os  -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D__AIPC_USERSPACE__ -Wall
INCS = -I../../boss_sdk/output.oem/build/libipc-1.1
LIBS += -L../../boss_sdk/output.oem/target/lib -L../../boss_sdk/output.oem/build/libslack-0.6 -lpthread -lipc -lrt -lslack -lutil

SRC_SKIP =
SRCS += main.c AVBuffer.c libsamipc_impl.c ipcgen/i_libsamipc_clnt.c
OBJS += main.o AVBuffer.o libsamipc_impl.o ipcgen/i_libsamipc_clnt.o

all : PREBUILD $(TARGET)

libsamipc_impl.o: libsamipc_impl.c
	@echo '>>> gcc Compiler ' $< ' to ' $@
	$(CC) $(CCFLAGS) -c $< -o $@ $(INCS) $(LIBS)

ipcgen/i_libsamipc_clnt.o: ipcgen/i_libsamipc_clnt.c
	@echo '>>> gcc Compiler ' $< ' to ' $@
	$(CC) $(CCFLAGS) -c $< -o $@ $(INCS) $(LIBS)

%.o: %.c
	@echo '>>> g++(.c) Compiler ' $< ' to ' $@
	$(CXX) $(CCFLAGS) $(CXXFLAGS) -c $< -o $@ $(INCS) $(LIBS)

%.o:%.cpp
	@echo '>>> g++(.cpp) Compiler ' $< ' to ' $@
	$(CXX) $(CCFLAGS) $(CXXFLAGS) -c $< -o $@ $(INCS) $(LIBS)

PREBUILD : 
	@echo '>>> OBJS:' $(OBJS)

$(TARGET) : $(OBJS)
#	@for file in $(DEPS); do if [ -e $$file ] && [ "$$(cat $$file)" == "" ]; then rm $$file; fi; done
	$(CXX) $(CXXFLAGS) $(OBJS) $(INCS) $(LIBS) -o $@
#	$(CC) $(CCFLAGS) $(CXXFLAGS) $(OBJS) $(LIBS) -o $@
	$(STRIP) -g $(TARGET)

-include $(DEPS)

clean:
	rm -rf *.o .*.d DVRClient/*.o P2PClient/*.o $(TARGET)
