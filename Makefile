CC = gcc
OBJ = neopak.o helper.o
LDIR = lib
LIBS = -L $(LDIR) -l secp256k1

neopak: $(OBJ)
	$(CC) -o neopak $(OBJ) $(LIBS)

neopak.o: neopak.c 
	$(CC) -c neopak.c

helper.o: helper.c
	$(CC) -c helper.c

clean:
	rm *.o 

uninstall:
	rm neopak