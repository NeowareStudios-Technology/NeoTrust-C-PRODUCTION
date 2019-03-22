/************************************
 * Project: NeoPak
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


void CreateDigestsAndMetaInfEntries(char *basePath, long *paramWorkingFileIndex, FILE *paramManifestFilePointer, FILE *paramSignatureFilePointer);

void GenerateDigestFromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest);

FILE* CreateBaseManifestFile(char *paramTargetDirectoryName, uint8_t *paramPublicKey);

FILE* CreateBaseSignatureFile(char *paramTargetDirectoryName);

void CreateManifestFileEntry(FILE* paramManifestFilePointer, char *paramFileName, uint8_t *paramFileDigest);

void CreateSignatureFileEntry(FILE* paramSignatureFilePointer, char *paramFileName, uint8_t *paramFileDigest);