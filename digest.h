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


void SaveFileNameAndDigestToManifest(char *basePath, const int root, long *paramWorkingFileIndex, FILE* paramManifestFilePointer);

void GenerateDigestFromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest);

FILE* CreateBaseManifestFile(char *paramTargetDirectoryName, uint8_t *paramPublicKey);

FILE* CreateBaseSignatureFile(char *paramTargetDirectoryName);