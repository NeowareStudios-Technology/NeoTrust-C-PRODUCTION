/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 3/28/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "verify.h"


void VerifyNeoPakSignature(char *paramTargetDir)
{
    char *metaInfDirPath[200];
    char *signatureBlockFilePath[200];
    char *manifestFilePath[200];
    char *signatureFilePath[200];
    long signatureBlockFileLength;
    long manifestFileLength;
    long signatureFileLength;
    FILE *signatureBlockFilePointer;
    FILE *manifestFilePointer;
    FILE *signatureFilePointer;
    uint8_t *signatureBlockFileContents;

    strcpy(metaInfDirPath, paramTargetDir);
    strcat(metaInfDirPath, "/META-INF");

    strcpy(signatureBlockFilePath, metaInfDirPath);
    strcat(signatureBlockFilePath, "/neopak.ec");

    strcpy(manifestFilePath, metaInfDirPath);
    strcat(manifestFilePath, "/manifest");

    signatureBlockFilePointer = fopen(signatureBlockFilePath, "rb");
    if (!signatureBlockFilePointer)
        printf("Signature file coud not be opened to read");
    signatureBlockFileLength = getFileLength(signatureBlockFilePointer);
    signatureBlockFileContents = (uint8_t *)malloc((signatureFileLength+1)*sizeof(uint8_t)); // Enough memory for file + \0
    fread(signatureBlockFileContents, signatureFileLength, 1, signatureBlockFilePointer); // Read in the entire file

    printf("Signature (verify): \n");
    for (int i = 0; i < signatureBlockFileLength; i++)
    {
        printf("%02x", signatureBlockFileContents[i]);
    }
    printf("\n\n");
}