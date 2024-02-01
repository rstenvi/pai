# Env variables to pass us to control
# - compiler used
# - Output directory
# - If we should strip binaries
# - Override strip command
#   - Android NDK does not provide strip binary, but a generic one for the arch
#   will work

### -------------- Configurable vars --------------- ###

CROSS_COMPILE ?=
CC ?= gcc
OUT ?= ./
DO_STRIP ?= 0
STRIP ?= $(CROSS_COMPILE)strip

### -------------- Object files ------------ ###

OBJ += traceme
OBJ += threads
OBJ += waitpid
OBJ += forkwait
OBJ += sleep
OBJ += getpid

SO += sofile.so

### --------------- Compile flags -------------------- ###

CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -g
CFLAGS += -std=c90

LDFLAGS ?= 
LDFLAGS += -ldl

SOFLAGS += -shared
SOFLAGS += -fPIC


### -------------- Non-configurable vars --------------- ###

GCC= $(CROSS_COMPILE)$(CC)
CDIR = $(shell pwd)

# Normalize output to be relative with an appending slash
ROUT = $(shell realpath --relative-to=${CDIR} ${OUT})/

# Keep track if which compiler we used last time and delete all if we use a new
# compiler this time.
ENVIRON = $(ROUT).environ
$(shell touch $(ENVIRON))	# To ensure it exists
OCC=$(shell cat $(ENVIRON))


OBJS=$(patsubst %, $(ROUT)%, $(OBJ))
SOS=$(patsubst %, $(ROUT)%, $(SO))



### ---------- Targets -------------------- ###


all: condclean $(OBJS) $(SOS) finally

# Delete all if we have a new compiler
# Create $(ROUT) directory if it doesn't exist
condclean:
	if [ "$(OCC)" != "$(CROSS_COMPILE)" ]; then rm -f $(OBJ) $(SO) $(ENVIRON); fi
	if [ ! -d $(ROUT) ]; then mkdir $(ROUT); fi

$(ROUT)%: %.c
	$(GCC) $(CFLAGS) -o $@ $< $(LDFLAGS)
ifeq ($(DO_STRIP),1)
	$(STRIP) $@
endif

$(ROUT)%.so: %.c Makefile
	$(GCC) $(CFLAGS) $(SOFLAGS) -o $@ $<

finally:
	echo $(CROSS_COMPILE) > $(ENVIRON)

clean:
	-rm -f $(OBJS) $(SOS) $(ENVIRON)
