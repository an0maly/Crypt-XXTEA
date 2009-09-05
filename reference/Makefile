
CFLAGS=-g -O0 -Wall

all:	xxtea
over: clean all
clean:
	-rm *~ *\.o xxtea cscope.*

test tests :: all
	prove test-vector.t

cscope:
	-rm -rf cscope.*
	find `pwd` -iname "*.[ch]" >cscope.files
	cscope -u -R -q -b 

xxtea:	XXTEA.o driver.o
	gcc -o $@ XXTEA.o driver.o

driver.o: driver.c
XXTEA.o: XXTEA.c
