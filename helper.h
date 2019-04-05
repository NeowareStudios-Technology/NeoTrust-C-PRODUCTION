/************************************
 * Project: NeoTrust
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


uint8_t *privKeyStringToHex(const char *string);

uint8_t *compPubKeyStringToHex(const char *sring);

//insert spaces between each hex number for parsing into uint8_t array (using privKeyStringToHex())
char* privKeyInsertSpaces(const char *string);

char* compPubKeyInsertSpaces(const char *sring);

//print secret key, public key, digest, and signature
void printValues(uint8_t* secKey, uint8_t* pubKeyComp, uint8_t* pubKeyUncomp, uint8_t* digest, uint8_t* signatureComp, uint8_t* signatureDer);

long getFileLength(FILE *paramFilePointer);

int cutStringAndReturnLength(char *stringToCut, int beginningIndex, int lengthToCut);