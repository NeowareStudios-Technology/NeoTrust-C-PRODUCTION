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

void ComputeSha256FromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest);
void MakeDigestForEachFile(char *basePath, const int root, uint8_t paramFileDigests[9999999][32], long *paramworkingFileIndex);