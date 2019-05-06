/************************************
 * Project: NeoTrust
 * Author: David Lee Ramirez
 * Date: 4/2/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <time.h>
#include "../verify.h"

#define NUM_TESTS 2
#define TEST_META_DIR_NAME "testMETA-INF"

int GetSigObjectFromSigBlockFile_test()
{
    char metaInfDirPath[256];
    size_t derLen = 72;
    secp256k1_ecdsa_signature sigObject;
    secp256k1_context *verifyContext = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY); 
    uint8_t actualSerializedSig[72];
    char actualSig[143];
    char *expectedSig = "30450221009bb45fd1dafd5dda62bd3fc9928233b8cb77a250e67ea9c9f62ad8e30797029b022040e0eac4336296b28a3311d5b5bc3ea1694e49e29430ab4ff39f29a30304bafa";
    int bufferIndex = 0;

    //create path to test META-INF directory
    strcpy(metaInfDirPath, "./");
    strcat(metaInfDirPath, TEST_META_DIR_NAME);

    GetSigObjectFromSigBlockFile(metaInfDirPath, &sigObject, verifyContext);

    //serialize the der encoded signature
    secp256k1_ecdsa_signature_serialize_der(verifyContext, actualSerializedSig, &derLen, &sigObject);

    //put serialized signature into string form 
    for (int i = 0; i < 71; i++)
    {
        bufferIndex += sprintf(actualSig + bufferIndex,"%02x", actualSerializedSig[i]);
    }

    //if generated digest does not match the expected digest, test fails
    if (strcmp(actualSig, expectedSig) != 0)
    {
        printf("1) GetSigObjectFromSigBlockFile_test FAILED\n");
        return 1;
    }

    printf("1) GetSigObjectFromSigBlockFile_test passed\n");

    return 0;
}


int GetPubKeyObjectFromManifestFile_test()
{
    char metaInfDirPath[256];
    secp256k1_context *verifyContext = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY); 
    secp256k1_pubkey pubKeyObject;
    size_t compressedPubKeyLen = 33;
    uint8_t *actualSerializedPubKeyCompressed = malloc(sizeof(uint8_t)*33);
    char actualPubKey[67];
    char *expectedPubKey = "03fa03a80e61bf98c42719de4ea8dc20b34c8da94d8e9c5e416c7d74e276109a1b";
    int bufferIndex = 0;

    //create path to test META-INF directory
    strcpy(metaInfDirPath, "./");
    strcat(metaInfDirPath, TEST_META_DIR_NAME);

    GetPubKeyObjectFromManifestFile(metaInfDirPath, &pubKeyObject, actualSerializedPubKeyCompressed, verifyContext);

    //serialize the PubKey object extracted from the manifest file in compressed form
    secp256k1_ec_pubkey_serialize(verifyContext, actualSerializedPubKeyCompressed, &compressedPubKeyLen, &pubKeyObject, SECP256K1_EC_COMPRESSED);

    //put serialized signature into string form 
    for (int i = 0; i < 33; i++)
    {
        bufferIndex += sprintf(actualPubKey + bufferIndex,"%02x", actualSerializedPubKeyCompressed[i]);
    }

    //if generated digest does not match the expected digest, test fails
    if (strcmp(actualPubKey, expectedPubKey) != 0)
    {
        printf("1) GetPubKeyObjectFromManifestFile_test FAILED\n");
        return 1;
    }

    printf("1) GetPubKeyObjectFromManifestFile_test passed\n");

    return 0;
}


/****** Include the following functions in all unit test C files ********/


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
    testStatuses[1] = GetPubKeyObjectFromManifestFile_test();

    printTestStatuses(testStatuses);

    return 0;
}