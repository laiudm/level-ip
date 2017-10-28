CPPFLAGS = -I include -Wall -Werror -pthread -std=gnu99

src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, build/%.o, $(src))
headers = $(wildcard include/*.h)

lvl-ip: $(obj)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(obj) -o lvl-ip
	@echo
	@echo "lvl-ip needs CAP_NET_ADMIN:"
	sudo setcap cap_setpcap,cap_net_admin=ep lvl-ip

build/%.o: src/%.c ${headers}
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# -fsanitize=address	
debug: CFLAGS+= -DDEBUG_SOCKET -DDEBUG_TCP -g -DDEBUG_ETH 
debug: lvl-ip

all: lvl-ip
	$(MAKE) -C tools
	$(MAKE) -C apps/curl
	$(MAKE) -C apps/curl-poll

test: all
	@echo
	@echo "Networking capabilites are required for test dependencies:"
	which arping | sudo xargs setcap cap_net_raw=ep
	which tc | sudo xargs setcap cap_net_admin=ep
	@echo
	cd tests && ./test-run-all

clean:
	rm build/*.o lvl-ip
