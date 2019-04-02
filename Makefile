CC = gcc 
CFLAGS = -g --std=c99
OBJ = $(OPATH)neopak.o $(OPATH)sign.o $(OPATH)digest.o $(OPATH)helper.o $(OPATH)verify.o $(OPATH)sha224-256.o $(OPATH)sha1.o $(OPATH)sha384-512.o $(OPATH)usha.o
TEST_HELPER_OBJ = $(OPATH)helper_unit_tests.o $(OPATH)helper.o
TEST_DIGEST_OBJ = $(OPATH)digest_unit_tests.o $(OPATH)digest.o $(OPATH)sha224-256.o $(OPATH)sha1.o $(OPATH)sha384-512.o $(OPATH)usha.o $(OPATH)helper.o
TEST_SIGN_OBJ = $(OPATH)sign_unit_tests.o $(OPATH)sign.o $(OPATH)digest.o $(OPATH)sha224-256.o $(OPATH)sha1.o $(OPATH)sha384-512.o $(OPATH)usha.o $(OPATH)helper.o
TEST_VERIFY_OBJ = $(OPATH)verify_unit_tests.o $(OPATH)verify.o $(OPATH)helper.o
OPATH = ./obj/
SPATH = ./sha/
TPATH = ./test/
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

$(OPATH)verify.o: verify.c
	$(CC) -c verify.c -o $(OPATH)verify.o $(CFLAGS)

$(OPATH)usha.o: $(SPATH)usha.c
	$(CC) -c $(SPATH)usha.c -o $(OPATH)usha.o $(CFLAGS)

$(OPATH)sha224-256.o: $(SPATH)sha224-256.c
	$(CC) -c $(SPATH)sha224-256.c -o $(OPATH)sha224-256.o $(CFLAGS)

$(OPATH)sha1.o: $(SPATH)sha1.c
	$(CC) -c $(SPATH)sha1.c -o $(OPATH)sha1.o $(CFLAGS)

$(OPATH)sha384-512.o: $(SPATH)sha384-512.c
	$(CC) -c $(SPATH)sha384-512.c -o $(OPATH)sha384-512.o $(CFLAGS)



test: test_helper test_digest test_sign test_verify
	$(test_helper)
	$(test_digest)
	$(test_sign)
	$(test_verify)
	rm obj/*.o

test_helper: $(TEST_HELPER_OBJ)
	$(CC) -o test_helper $(TEST_HELPER_OBJ) $(CFLAGS)
	./test_helper >> unittestresults.out
	rm ./test_helper
	

$(OPATH)helper_unit_tests.o: $(TPATH)helper_unit_tests.c 
	$(CC) -c $(TPATH)helper_unit_tests.c -o $(OPATH)helper_unit_tests.o $(CFLAGS)

test_digest: $(TEST_DIGEST_OBJ)
	$(CC) -o test_digest $(TEST_DIGEST_OBJ) $(CFLAGS)
	./test_digest >> unittestresults.out
	rm ./test_digest

$(OPATH)digest_unit_tests.o: $(TPATH)digest_unit_tests.c 
	$(CC) -c $(TPATH)digest_unit_tests.c -o $(OPATH)digest_unit_tests.o $(CFLAGS)

test_sign: $(TEST_SIGN_OBJ)
	$(CC) -o test_sign $(TEST_SIGN_OBJ) $(LIBS) $(CFLAGS)
	./test_sign >> unittestresults.out
	rm ./test_sign

$(OPATH)sign_unit_tests.o: $(TPATH)sign_unit_tests.c 
	$(CC) -c $(TPATH)sign_unit_tests.c -o $(OPATH)sign_unit_tests.o $(CFLAGS)

test_verify: $(TEST_VERIFY_OBJ)
	$(CC) -o test_verify $(TEST_VERIFY_OBJ) $(LIBS) $(CFLAGS)
	./test_verify >> unittestresults.out
	rm ./test_verify

$(OPATH)verify_unit_tests.o: $(TPATH)verify_unit_tests.c 
	$(CC) -c $(TPATH)verify_unit_tests.c -o $(OPATH)verify_unit_tests.o $(CFLAGS)

cleanobject:
	rm obj/*.o

cleantest:
	rm *.out

cleanmeta:
	rm -rf testdir/META-INF

uninstall:
	rm neopak