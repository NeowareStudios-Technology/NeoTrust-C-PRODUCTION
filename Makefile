CC = gcc -g --std=c17 -Wall
OBJ = $(OPATH)neopak.o $(OPATH)helper.o $(OPATH)sha224-256.o $(OPATH)sha1.o $(OPATH)sha384-512.o $(OPATH)usha.o
OPATH = ./obj/
SPATH = ./sha/
LDIR = lib
LIBS = -L $(LDIR) -l secp256k1

neopak: $(OBJ)
	$(CC) -o neopak $(OBJ) $(LIBS)

$(OPATH)neopak.o: neopak.c 
	$(CC) -c neopak.c -o $(OPATH)neopak.o

$(OPATH)helper.o: helper.c
	$(CC) -c helper.c -o $(OPATH)helper.o

$(OPATH)usha.o: $(SPATH)usha.c
	$(CC) -c $(SPATH)usha.c -o $(OPATH)usha.o

$(OPATH)sha224-256.o: $(SPATH)sha224-256.c
	$(CC) -c $(SPATH)sha224-256.c -o $(OPATH)sha224-256.o

$(OPATH)sha1.o: $(SPATH)sha1.c
	$(CC) -c $(SPATH)sha1.c -o $(OPATH)sha1.o

$(OPATH)sha384-512.o: $(SPATH)sha384-512.c
	$(CC) -c $(SPATH)sha384-512.c -o $(OPATH)sha384-512.o

clean:
	rm obj/*
	rm neopak