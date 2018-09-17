all: benchmark debug

#validate

benchmark: benchmark.c 
	$(CC) -g -O0 benchmark.c -o benchmark -I/usr/local/include -lpcontainer -lpthread

debug: debug.c 
	$(CC) -g -O0 debug.c -o debug -I/usr/local/include -lpcontainer
	
clean:
	rm -f benchmark 
	rm -f debug
