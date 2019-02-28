CC = gcc
OBJ = neopak.o helper.o sha224-256.o
LDIR = lib
LIBS = -L $(LDIR) -l secp256k1

neopak: $(OBJ)
	$(CC) -o neopak $(OBJ) $(LIBS)

neopak.o: neopak.c 
	$(CC) -c neopak.c

helper.o: helper.c
	$(CC) -c helper.c

sha224-256.o: sha224-256.c
	$(CC) -c sha224-256.c 

clean:
	rm *.o 

uninstall:
	rm neopak