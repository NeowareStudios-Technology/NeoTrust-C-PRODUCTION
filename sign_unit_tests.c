/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 3/21/19
 * Copywrite NeoWare 2019
 * *********************************/


#include <time.h>
#include "sign.h"

#define NUM_TESTS 3


//ensures the object returned by CreateTestSecp256k1ScalarObject is 32 bytes in size 
//-if object is size 32, test passes
int CreateTestSecp256k1ScalarObject_test()
{
    secp256k1_scalar testScalarObject;

    CreateTestSecp256k1ScalarObject(&testScalarObject);

    if (sizeof(testScalarObject) != 32)
    {
        printf("1) CreateTestSecp256k1ScalarObject_test FAILED\n");
        return 1;
    }

    printf("1) CreateTestSecp256k1ScalarObject_test passed\n");
    return 0;
}


//ensures a valid public key was generated from a test private key (validation done inside GeneratePubKeyFromPrivKey())
//-if public key valid, test passes
//-tests will not continue if this test fails
int GeneratePubKeyFromPrivKey_test()
{

    secp256k1_scalar testSecKey;
    uint8_t* serializedTestSecKey;
    uint8_t* serializedTestPubKeyCompressed;
    uint8_t* serializedTestPubKeyUncompressed;
    serializedTestSecKey = malloc(sizeof(uint8_t)*32);
    serializedTestPubKeyCompressed = malloc(sizeof(uint8_t)*33);
    serializedTestPubKeyUncompressed = malloc(sizeof(uint8_t)*65);
    secp256k1_context *testContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN| SECP256K1_CONTEXT_VERIFY);
    CreateTestSecp256k1ScalarObject(&testSecKey);
    secp256k1_scalar_get_b32(serializedTestSecKey, &testSecKey);
    GeneratePubKeyFromPrivKey(testContext,serializedTestSecKey, serializedTestPubKeyCompressed, serializedTestPubKeyUncompressed);

    printf("2) GeneratePubKeyFromPrivKey_test passed\n");
    return 0;
}


int VerifyParamsAndSignMessageWithEcdsa_test()
{
    uint8_t* serializedTestDigest;
    uint8_t* serializedTestSecKey;
    uint8_t* serializedTestPubKeyComp;
    uint8_t* serializedTestPubKeyUncomp;
    uint8_t* serializedSignatureComp;
    uint8_t* serializedSignatureDer;
    serializedTestDigest = malloc(sizeof(uint8_t)*32);
    serializedTestSecKey = malloc(sizeof(uint8_t)*32);
    serializedTestPubKeyComp = malloc(sizeof(uint8_t)*33);
    serializedTestPubKeyUncomp = malloc(sizeof(uint8_t)*65);
    serializedSignatureComp = malloc(sizeof(uint8_t)*64);
    //72 is max length for DER sig, but can be shorters
    serializedSignatureDer = malloc(sizeof(uint8_t)*72);
    secp256k1_scalar testMessageHash, testPrivateKey;

    //generate random message hash and private key?
    CreateTestSecp256k1ScalarObject(&testMessageHash);
    CreateTestSecp256k1ScalarObject(&testPrivateKey);
    
    //convert message hash to uint8_t 32 bytes
    secp256k1_scalar_get_b32(serializedTestDigest, &testMessageHash);
    secp256k1_scalar_get_b32(serializedTestSecKey, &testPrivateKey);

    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN| SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey myPublicKey = GeneratePubKeyFromPrivKey(myContext,serializedTestSecKey, serializedTestPubKeyComp, serializedTestPubKeyUncomp);
    VerifyParamsAndSignMessageWithEcdsa(myPublicKey, serializedTestSecKey, serializedTestDigest, serializedSignatureComp, serializedSignatureDer);

    printf("3) VerifyParamsAndSignMessageWithEcdsa_test passed\n");
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
    printf("\n***** Unit Tests: sign.c *****\n");
}


int main()
{
    int testStatuses[NUM_TESTS];
    srand(time(0));

    printHeader();

    testStatuses[0] = CreateTestSecp256k1ScalarObject_test();
    testStatuses[1] = GeneratePubKeyFromPrivKey_test();
    testStatuses[2] = VerifyParamsAndSignMessageWithEcdsa_test();

    printTestStatuses(testStatuses);

    return 0;
}
