CC=gcc
LIBS=-lpcap
BINS=mydump

all: Linux

Linux linux:        
		${CC} -DLINUX mydump.c ${LIBS} -w -o mydump
osx osX OSX FreeBSD freebsd:        
		${CC} -DFREEBSD mydump.c ${LIBS} -w -o mydump
clean:
		rm -f a.out ${BINS}