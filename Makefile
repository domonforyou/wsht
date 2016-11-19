BUILD_LDFLAGS += -lcurl -lpthread -lm -lz
#DLIB_FLAGS += -L/home/hrd/op_install/lib 

#BUILD_CFLAGS += -I/home/hrd/op_install/include


ELF := demo_app

SRC := $(shell find . -name '*.c')

OBJ := $(SRC:%.c=%.o)

GCDA := $(patsubst %.c,%.gcda,$(SRC))

GCNO := $(patsubst %.c,%.gcno,$(SRC))

GCOV := $(patsubst %.c,%.gcov,$(SRC))

CC   := gcc

.PHONY: header build install clean

all: header build install

header:

	@echo "copying header files ......" 

	

%.o: %.c

	$(CC) -c -fpic $(BUILD_CFLAGS) $< -o $@



build: $(OBJ)

	$(CC) $(BUILD_CFLAGS) $(DLIB_FLAGS) $^ -o $(ELF) $(BUILD_LDFLAGS)



install:



clean:

	@-rm -rf  ${OBJ} ${ELF} $(GCDA) $(GCNO) $(GCOV)
