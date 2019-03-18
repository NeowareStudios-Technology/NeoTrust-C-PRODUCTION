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




uint8_t *stringToHex(const char *s, int *length);

static uint8_t charToHex(const char *s, char **endptr);

void countFilesInDirectory(char *basePath, const int root, long *count);

//insert spaces between each hex number for parsing into uint8_t array
char* insertSpaces(const char *s);

//print secret key, public key, digest, and signature
void printValues(uint8_t* secKey, uint8_t* pubKeyComp, uint8_t* pubKeyUncomp, uint8_t* digest, uint8_t* signatureComp, uint8_t* signatureDer);

long getFileLength(char* paramFileName, FILE *paramFilePointer);