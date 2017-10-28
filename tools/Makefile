CPPFLAGS = -I ../include -Wall -Werror -std=gnu99

all: liblevelip

debug: CFLAGS+= -DDEBUG_API
debug: liblevelip

liblevelip: liblevelip.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -fPIC -shared -o liblevelip.so liblevelip.c -ldl

httpstub: httpstub.c
	gcc -g -O2 -Wall -std=c99 -o httpstub -pthread httpstub.c
	
runhttp:
	./httpstub -p 8000 -f httpstub.c 

.PHONY:
clean:
	rm liblevelip.so*
