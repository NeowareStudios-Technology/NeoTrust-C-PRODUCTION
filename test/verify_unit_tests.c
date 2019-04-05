/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 4/2/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <time.h>
#include "../verify.h"

#define NUM_TESTS 1
#define TEST_META_DIR_NAME "testMETA-INF"

int GetSigObjectFromSigBlockFile_test()
{
    char metaInfDirPath[256];
    size_t derLen = 72;
    secp256k1_ecdsa_signature sigObject;
    secp256k1_context *verifyContext = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY); 
    uint8_t actualSerializedSignature[72];
    char actualSignature[143];
    char *expectedSignature = "30450221009bb45fd1dafd5dda62bd3fc9928233b8cb77a250e67ea9c9f62ad8e30797029b022040e0eac4336296b28a3311d5b5bc3ea1694e49e29430ab4ff39f29a30304bafa";
    int bufferIndex = 0;

    strcpy(metaInfDirPath, "./");
    strcat(metaInfDirPath, TEST_META_DIR_NAME);

    GetSigObjectFromSigBlockFile(metaInfDirPath, &sigObject, verifyContext);

    secp256k1_ecdsa_signature_serialize_der(verifyContext, actualSerializedSignature, &derLen, &sigObject);

    for (int i = 0; i < 71; i++)
    {
        bufferIndex += sprintf(actualSignature + bufferIndex,"%02x", actualSerializedSignature[i]);
    }

    //if generated digest does not match the expected digest, test fails
    if (strcmp(actualSignature, expectedSignature) != 0)
    {
        printf("1) GetSigObjectFromSigBlockFile_test FAILED\n");
        return 1;
    }

    printf("1) GetSigObjectFromSigBlockFile_test passed\n");

    return 0;
}


void printTestStatuses(int paramTestStatuses[NUM_TESTS])
{
    for (int i = 0; i < NUM_TESTS; i++)
    {
        printf("%d", paramTestStatuses[i]);
    }
    printf("\n");
    printf("\n");
}


void printHeader()
{
    printf("\n***** Unit Tests: verify.c *****\n");
}


int main()
{
    int testStatuses[NUM_TESTS];
    srand(time(0));

    printHeader();

    testStatuses[0] = GetSigObjectFromSigBlockFile_test();

    printTestStatuses(testStatuses);

    return 0;
}