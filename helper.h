/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <time.h>
#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"
#include "include/testrand_impl.h"


//helper function for calculating size of string
size_t strlen(const char *str);

//helper function to get hex from string char
static unsigned char gethex(const char *s, char **endptr);

//helper function to convert from string to unsigned char array of hex
unsigned char *convert(const char *s, int *length);

//insert spaces between each hex number for parsing into unsigned char array
char* insertSpaces(const char *s);

//print secret key, public key, digest, and signature
void printValues(unsigned char* secKey, unsigned char* pubKeyComp, unsigned char* pubKeyUncomp, unsigned char* digest, unsigned char* signatureComp, unsigned char* signatureDer);

long getFileLength(char* paramFileName, FILE *paramFilePointer);

void countFilesInDirectory(char *basePath, const int root, long *count);