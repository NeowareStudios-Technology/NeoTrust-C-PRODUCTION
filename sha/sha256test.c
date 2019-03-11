#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha.h"
#include "helper.h"


uint8_t* ComputeSha256FromByteArray(uint8_t* paramFileContents, int paramFileContentsLength)
{
    USHAContext shaContext;
    uint8_t messageDigest[32];
    const char testArray[5] = {'h','e','l','l','o'};
    int testArrayLength = 5;

    int errorCode;

    errorCode = USHAReset(&shaContext, SHA256);
    printf("%d", errorCode);

    errorCode = USHAInput(&shaContext, (const uint8_t *) testArray, testArrayLength);
    printf("%d", errorCode);

    errorCode = USHAResult(&shaContext, messageDigest);
    printf("%d", errorCode);

    printf("\n");
    for (int i = 0; i < 32; i++)
        printf("%02x", messageDigest[i]);
    printf("\n");

    return messageDigest;
}

int main(int argc, char **argv)
{
    uint8_t fileContents;
    uint8_t *fileDigest;
    int fileContentsLength = readFileIntoByteArrayAndReturnLength(argv[1], &fileContents);

    fileDigest = ComputeSha256FromByteArray(&fileContents, fileContentsLength);

    printf("\n");
    for (int i = 0; i < 32; i++)
        printf("%02x", fileDigest[i]);
    printf("\n");
}