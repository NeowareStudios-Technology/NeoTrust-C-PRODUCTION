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


void GetNameAndDigestForEachFile(char *basePath, const int root, uint8_t paramFileDigests[9999999][32], uint8_t paramFileNames[9999999][500], long *paramWorkingFileIndex);

void GenerateDigestFromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest);