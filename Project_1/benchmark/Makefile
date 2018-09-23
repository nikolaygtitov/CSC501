all: benchmark benchmark2 debug

#validate

benchmark: benchmark.c 
	$(CC) -g -O0 benchmark.c -o benchmark -I/usr/local/include -lpcontainer -lpthread

benchmark2: benchmark2.c 
	$(CC) -g -O0 benchmark2.c -o benchmark2 -I/usr/local/include -lpcontainer -lpthread

debug: debug.c 
	$(CC) -g -O0 debug.c -o debug -I/usr/local/include -lpcontainer
	
clean:
	rm -f benchmark 
	rm -f debug
