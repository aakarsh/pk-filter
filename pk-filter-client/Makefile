LIB=

pk-client: pk-client.c
	gcc -I../pk-filter-module/ -I/usr/local/include pk-client.c -o bin/pk-client  $(LIB) -L/usr/local/lib -lnl
	gtags
clean:
	rm -r bin/*
