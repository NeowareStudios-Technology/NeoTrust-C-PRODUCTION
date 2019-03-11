CC = gcc
OBJ = neopak.o helper.o sha224-256.o sha1.o sha384-512.o usha.o
LDIR = lib
LIBS = -L $(LDIR) -l secp256k1

neopak: $(OBJ)
	$(CC) -o neopak $(OBJ) $(LIBS)

neopak.o: neopak.c 
	$(CC) -c neopak.c

helper.o: helper.c
	$(CC) -c helper.c

usha.o: usha.c
	$(CC) -c usha.c

sha224-256.o: sha224-256.c
	$(CC) -c sha224-256.c 

sha1.o: sha1.c
	$(CC) -c sha1.c

sha384-512.o: sha384-512.c
	$(CC) -c sha384-512.c

clean:
	rm *.o 
	rm neopak