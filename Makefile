CFLAGS += -Wall -Wextra -pedantic -DPIC

.PHONY: all clean

all: pam_clockwork.so

clean:
	rm -f pam_clockwork.so *.o

pam_clockwork.so: pam_clockwork.c
	${CC} ${CFLAGS} -fPIC -shared -Xlinker -x -o $@ $< -ldl
