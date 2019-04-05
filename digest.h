/************************************
 * Project: NeoTrust
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <stdlib.h>
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>

#include "./sha/sha.h"
#include "helper.h"


void CreateDigestsAndMetaInfEntries(char *paramBasePath, FILE *paramManifestFilePointer, FILE *paramSigFilePointer);

void GenerateSha256DigestFromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest);

FILE *GenerateFullManifestDigestAndSaveInSigFile(char *paramMetaInfDirPath, char *paramFileName, FILE *paramManifestFilePointer, FILE *paramSigFilePointer);

FILE* CreateBaseManifestFile(char *paramMetaInfPath, char *paramFileName, uint8_t *paramPublicKey);

FILE* CreateBaseSigFile(char *paramTargetDirectoryName);

void CreateManifestFileEntry(FILE *paramManifestFilePointer, char *paramFileName, uint8_t *paramFileDigest);

void CreateTempSigFileEntry(FILE *paramTempSigFilePointer, char *paramFileName, uint8_t *paramFileDigest);

void GenerateSigFileDigest(FILE *paramSigFilePointer, uint8_t *paramSigFileDigest);