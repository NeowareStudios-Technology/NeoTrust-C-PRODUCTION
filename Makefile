CC = gcc 
CFLAGS = -g --std=c17 -coverage
OBJ = $(OPATH)neopak.o $(OPATH)sign.o $(OPATH)digest.o $(OPATH)helper.o $(OPATH)sha224-256.o $(OPATH)sha1.o $(OPATH)sha384-512.o $(OPATH)usha.o
TEST_OBJ = $(OPATH)helper_unit_tests.o $(OPATH)helper.o
OPATH = ./obj/
SPATH = ./sha/
LDIR = lib
LIBS = -L $(LDIR) -l secp256k1

neopak: $(OBJ)
	$(CC) -o neopak $(OBJ) $(LIBS) $(CFLAGS)

$(OPATH)neopak.o: neopak.c 
	$(CC) -c neopak.c -o $(OPATH)neopak.o $(CFLAGS)

$(OPATH)sign.o: sign.c
	$(CC) -c sign.c -o $(OPATH)sign.o $(CFLAGS)

$(OPATH)digest.o: digest.c
	$(CC) -c digest.c -o $(OPATH)digest.o $(CFLAGS)

$(OPATH)helper.o: helper.c
	$(CC) -c helper.c -o $(OPATH)helper.o $(CFLAGS)

$(OPATH)usha.o: $(SPATH)usha.c
	$(CC) -c $(SPATH)usha.c -o $(OPATH)usha.o $(CFLAGS)

$(OPATH)sha224-256.o: $(SPATH)sha224-256.c
	$(CC) -c $(SPATH)sha224-256.c -o $(OPATH)sha224-256.o $(CFLAGS)

$(OPATH)sha1.o: $(SPATH)sha1.c
	$(CC) -c $(SPATH)sha1.c -o $(OPATH)sha1.o $(CFLAGS)

$(OPATH)sha384-512.o: $(SPATH)sha384-512.c
	$(CC) -c $(SPATH)sha384-512.c -o $(OPATH)sha384-512.o $(CFLAGS)

test: $(TEST_OBJ)
	$(CC) -o test $(TEST_OBJ) $(CFLAGS)
	./test
	rm ./test

$(OPATH)helper_unit_tests.o: helper_unit_tests.c 
	$(CC) -c helper_unit_tests.c -o $(OPATH)helper_unit_tests.o $(CFLAGS)

clean:
	rm obj/*
	rm neopak