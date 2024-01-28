CC ?= gcc
OCC=$(shell cat ./.environ)

OBJ += traceme
OBJ += threads
OBJ += waitpid
OBJ += forkwait
OBJ += sleep 

SO += sofile.so

all: condclean $(OBJ) $(SO) finally

condclean:
	if [ "$(OCC)" != "$(CC)" ]; then rm -f $(OBJ) $(SO); fi

%: %.c
	$(CC) -Wall -Werror -std=gnu17 -g -o $@ $<

%.so: %.c Makefile
	$(CC) -Wall -Werror -g -shared -fPIC -o $@ $<

finally:
	echo $(CC) > ./.environ

clean:
	-rm -f $(OBJ) $(SO) ./.environ
