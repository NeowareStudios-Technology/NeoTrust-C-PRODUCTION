/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <assert.h>
#include <dirent.h>

#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"
#include "include/testrand_impl.h"



size_t stringLength(const char *str);

unsigned char *stringToHex(const char *s, int *length);

static unsigned char charToHex(const char *s, char **endptr);

void countFilesInDirectory(char *basePath, const int root, long *count);

//insert spaces between each hex number for parsing into unsigned char array
char* insertSpaces(const char *s);

//print secret key, public key, digest, and signature
void printValues(unsigned char* secKey, unsigned char* pubKeyComp, unsigned char* pubKeyUncomp, unsigned char* digest, unsigned char* signatureComp, unsigned char* signatureDer);

long getFileLength(char* paramFileName, FILE *paramFilePointer);