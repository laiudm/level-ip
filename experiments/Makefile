all: prog myfopen.so

prog: prog.c
	gcc prog.c -o prog
	
myfopen.so: myfopen.c
	gcc -Wall -fPIC -shared -o myfopen.so myfopen.c
	
run:
	./prog
	LD_PRELOAD=./myfopen.so ./prog

clean:
	rm prog
	rm myfopen.so
	