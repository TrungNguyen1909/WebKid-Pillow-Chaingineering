CC = clang
.PHONY: clean payload.dylib

stage3_macOS.dylib: exploit.c shelld.defs shelld_client.defs
	mig shelld.defs
	mig shelld_client.defs
	clang -shared exploit.c shelldUser.c shelld_clientUser.c -o stage3_macOS.dylib
	clang tester.c -o tester

clean:
	rm -f stage3_macOS.dylib shelld.h shelldServer.c shelldUser.c shelld_client.h shelld_clientServer.c shelld_clientUser.c tester

run: pillow_exploit
	sandbox-exec -f sandbox.sb -DBINARY=$(shell pwd)/exploit ./exploit
