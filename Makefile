CC=gcc
build: build_server build_client

rebuild: clean build

build_server:
	mkdir -p build & $(CC) server.c -lcrypto -o build/server
clean_server:
	rm -f build/server

build_client:
	mkdir -p build & $(CC) client.c -lcrypto -o build/client
clean_client:
	rm -f build/client

clean:
	rm -rf build/
