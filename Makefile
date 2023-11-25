default: build

build: clean
	gcc -Wall -o drson main.c util.c -l curl -Os `pkg-config --cflags --libs libmodbus` -lpthread

clean:
	rm -rf drson 

test: build
	./drson 

