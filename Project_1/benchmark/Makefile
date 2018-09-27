all: benchmark benchmark2 benchmark3 benchmark4 debug

#validate

benchmark: benchmark.c 
	$(CC) -g -O0 benchmark.c -o benchmark -I/usr/local/include -lpcontainer -lpthread

benchmark2: benchmark2.c 
	$(CC) -g -O0 benchmark2.c -o benchmark2 -I/usr/local/include -lpcontainer -lpthread

benchmark3: benchmark3.c 
	$(CC) -g -O0 benchmark3.c -o benchmark3 -I/usr/local/include -lpcontainer -lpthread

benchmark4: benchmark4.c 
	$(CC) -g -O0 benchmark4.c -o benchmark4 -I/usr/local/include -lpcontainer -lpthread

debug: debug.c 
	$(CC) -g -O0 debug.c -o debug -I/usr/local/include -lpcontainer
	
clean:
	rm -f benchmark 
	rm -f debug
