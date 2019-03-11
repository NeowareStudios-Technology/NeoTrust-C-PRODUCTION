/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <ctype.h>

#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"
#include "include/testrand_impl.h"
#include "helper.h"
#include "./sha/sha.h"


//global
enum commands{usage, testSign, sign}command;

//function declarations
void DisplayUsageInfo();
enum commands ParseArgumentsIntoCommand(int paramArgc);
void ExecuteCommand(char **paramArgs, enum commands paramCommand);
char* ReadFileIntoByteArray(char *paramFileName);
void ComputeSha256FromCharArray(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest);
void CompleteTestSigProcess();
void CompleteSigProcess(char *paramSecKey, char *paramFileName);
int VerifyParamsAndSignMessageWithEcdsa(unsigned char* secKey, unsigned char* pubKeyComp, unsigned char* pubKeyUncomp, unsigned char* digest, unsigned char* signatureComp, unsigned char* signatureDer);


void DisplayUsageInfo()
{
    printf("\nNeoPak\nCopywrite NeoWare 2019\n");
    printf("Created by David Lee Ramirez 2/12/2019 \n");
    printf("Usage:\n");
    printf("./neopak                                  Show usage info\n");
    printf("./neopak test                             Sign with test priv key and message hash\n");
    printf("./neopak <privKey> <filePath>             Sign with provided priv key and file\n");
    printf("\n *Note: <privKey> and <messageHash> must be supplied \n        as a string of hex numbers with length 64 \n");
}


enum commands ParseArgumentsIntoCommand(int paramArgc)
{
    //if no args passed, display usage info
    if (paramArgc == 1)
    {
        return usage;
    }
    //if only "test" is passed as arg, start test sign
    else if (paramArgc == 2)
    {
        return testSign;
    }
    //if private key and message hash are passed as args, start
    //production sign
    else if (paramArgc == 3)
    {
        return sign;
    }
    //else, too many args passed
    else
    {
        printf("\nError: incorrect usage, run program with no args for usage info \n");
        exit(1);
    }
}


void ExecuteCommand(char **paramArgs, enum commands paramCommand)
{
    switch (paramCommand)
    {
        case usage:
            DisplayUsageInfo();
            break;
        case testSign:
            CompleteTestSigProcess();
            break;
        case sign:
            CompleteSigProcess(paramArgs[1], paramArgs[2]);
            break;
    }
}


//sets up all data structures necessary to sign a test message with a test private key and signs in ECDSA
void CompleteTestSigProcess()
{
    unsigned char* serializedDigest;
    unsigned char* serializedSecKey;
    unsigned char* serializedPubKeyCompressed;
    unsigned char* serializedPubKeyUncompressed;
    unsigned char* serializedSignatureComp;
    unsigned char* serializedSignatureDer;
    serializedDigest = malloc(sizeof(unsigned char)*32);
    serializedSecKey = malloc(sizeof(unsigned char)*32);
    serializedPubKeyCompressed = malloc(sizeof(unsigned char)*33);
    serializedPubKeyUncompressed = malloc(sizeof(unsigned char)*65);
    serializedSignatureComp = malloc(sizeof(unsigned char)*64);
    //72 is max length for DER sig, but can be shorters
    serializedSignatureDer = malloc(sizeof(unsigned char)*72);
    secp256k1_scalar myMessageHash, myPrivateKey;

    printf("\nStarting signing test with test pub/priv keys and test message hash");
    //generate random message hash and private key?
    random_scalar_order_test_new(&myMessageHash);
    random_scalar_order_test_new(&myPrivateKey);
    
    //convert message hash to unsigned char 32 bytes?
    secp256k1_scalar_get_b32(serializedDigest, &myMessageHash);
    secp256k1_scalar_get_b32(serializedSecKey, &myPrivateKey);

    VerifyParamsAndSignMessageWithEcdsa(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, serializedDigest, serializedSignatureComp, serializedSignatureDer);

    printValues(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, serializedDigest, serializedSignatureComp, serializedSignatureDer);
}


//DESC: 
// Sets up all data structures necessary to sign a message digest (sha256; 32 bytes; provided by user)
// with a key (ECDSA; 32 bytes; provided by user) and signs in ECDSA
//OUTPUT:
// Prints the following to consol:
//  -serialized private (secret) key
//  -serialized compressed public key
//  -serialized uncompressed public key
//  -serialized message digest
//  -serialized compressed signature
//  -serialized signature in DER format
void CompleteSigProcess(char *paramSecKey, char *paramFileName)
{
    //for calculating digest
    uint8_t fileDigest[32];
    char *fileContents;
    FILE *filePointer;
    long fileLength;

    //for signing with private key
    unsigned char* serializedDigest;
    unsigned char* serializedSecKey;
    unsigned char* serializedPubKeyCompressed;
    unsigned char* serializedPubKeyUncompressed;
    unsigned char* serializedSignatureComp;
    unsigned char* serializedSignatureDer;
    serializedDigest = malloc(sizeof(unsigned char)*32);
    serializedSecKey = malloc(sizeof(unsigned char)*32);
    serializedPubKeyCompressed = malloc(sizeof(unsigned char)*33);
    serializedPubKeyUncompressed = malloc(sizeof(unsigned char)*65);
    serializedSignatureComp = malloc(sizeof(unsigned char)*64);
    //72 is max length for DER sig, but can be shorters
    serializedSignatureDer = malloc(sizeof(unsigned char)*72);
    secp256k1_scalar myMessageHash, myPrivateKey;

    //make sure passed private key is exactly 64 chars long
    if (strlen(paramSecKey) != 64)
    {
        printf("\nError: incorrect usage, private key and message hash must be exaclty 64 chars long");
        exit(0);
    }

    filePointer = fopen(paramFileName, "r");  // Open the file in binary mode
    fseek(filePointer, 0, SEEK_END);          // Jump to the end of the file
    fileLength = ftell(filePointer);             // Get the current byte offset in the file
    rewind(filePointer);                      // Jump back to the beginning of the file

    fileContents = (char *)malloc((fileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(fileContents, fileLength, 1, filePointer); // Read in the entire file
    fclose(filePointer); // Close the file

    ComputeSha256FromCharArray(fileContents, fileLength, fileDigest);
    
    //add space between each hex number in private key and digest 
    const char* secKey = insertSpaces(paramSecKey);
    int lengthKey = strlen(secKey);
    int *keyLengthPtr = &lengthKey;
    serializedSecKey = convert(secKey, keyLengthPtr);

    VerifyParamsAndSignMessageWithEcdsa(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, fileDigest, serializedSignatureComp, serializedSignatureDer);

    printValues(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, fileDigest, serializedSignatureComp, serializedSignatureDer);
    
}


void ComputeSha256FromCharArray(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest)
{
    USHAContext shaContext;
    uint8_t messageDigest[32];

    int errorCode;

    errorCode = USHAReset(&shaContext, SHA256);
    if (errorCode == 0)
        printf("\nSHA context reset successful");
    else
        printf("\nSHA context reset failed");
    

    errorCode = USHAInput(&shaContext, (const uint8_t *) paramFileContents, paramFileLength);
    if (errorCode == 0)
        printf("\nSHA input successful");
    else
        printf("\nSHA input failed");

    errorCode = USHAResult(&shaContext, paramFileDigest);
    if (errorCode == 0)
        printf("\nSHA result successful");
    else
        printf("\nSHA result failed");
}

//DESC: 
// Creates an ECDSA signature using a passed in message hash and private key
//PARAMS:
// 1)secKey - holds serialized secret key (console arg provided by user)
// 2)pubKeyComp - will hold serialized compressed pub key (gets derived from private key in this func)
// 3)pubKeyUncomp - will hold will hold serialized uncompressed pub key (gets derived from mprivate key in this func)
// 4)digest - holds serialized message digest (console arg provided by user)
// 5)signatureComp - will hold the serialized compressed signature (gets created in this function)
// 6)signatureDer - will hold the serialized DER signature (gets created in this function)
//OUTPUT:
// pubKeyComp, pubKeyUncomp, signatureComp, signatureDer
int VerifyParamsAndSignMessageWithEcdsa(unsigned char* secKey, unsigned char* pubKeyComp, unsigned char* pubKeyUncomp, unsigned char* digest, unsigned char* signatureComp, unsigned char* signatureDer)
{
    /*a general template for this function can be found in 
    go-ethereum-master\crypto\secp256k1\libsecp256k1\src\modules\recovery\tests_impl.h
    line 150*/

    //setup params needed for signing function
    //set to both sign and verify
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN| SECP256K1_CONTEXT_VERIFY); 
    secp256k1_ecdsa_signature mySig;
    //holds four 64 bit uints (0 to 18,446,744,073,709,551,615) in an array
    secp256k1_scalar myMessageHash, myPrivateKey;
    secp256k1_pubkey myPublicKey;
    size_t pubKeyCompLen;
    size_t pubKeyUncompLen;

    //verify the private key
    if(1 == secp256k1_ec_seckey_verify(myContext, secKey))
    {
        printf("\nPrivate key verified \n");
    }
    else
    {
        printf("Private key failed verification \n");
        exit(1);
    }

    //construct the corresponding public key
    if(1 == secp256k1_ec_pubkey_create(myContext, &myPublicKey, secKey))
    {
        printf("Public key created \n");
    }
    else
    {
        printf("Public key could not be created \n");
        exit(1);
    }

    //get seralized public key (compressed)
    pubKeyCompLen = 33;
    secp256k1_ec_pubkey_serialize(myContext, pubKeyComp, &pubKeyCompLen, &myPublicKey, SECP256K1_EC_COMPRESSED);
    secp256k1_pubkey pubkeytest0;
    if (1 == secp256k1_ec_pubkey_parse(myContext, &pubkeytest0, pubKeyComp, pubKeyCompLen)) 
    {
        printf("Compressed public key able to be parsed \n");
    }
    else
    {
        printf("Error parsing compressed public key \n");
        exit(1);
    }

    //get seralized public key (uncompressed)
    pubKeyUncompLen = 65;
    secp256k1_ec_pubkey_serialize(myContext, pubKeyUncomp, &pubKeyUncompLen, &myPublicKey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_pubkey pubkeytest1;
    if (1 == secp256k1_ec_pubkey_parse(myContext, &pubkeytest1, pubKeyUncomp, pubKeyUncompLen)) 
    {
        printf("Uncompressed public key able to be parsed \n");
    }
    else
    {
        printf("Error parsing uncompressed public key \n");
        exit(1);
    }
    
    //sign message hash with private key
    secp256k1_ecdsa_sign(myContext, &mySig, digest, secKey, NULL, NULL);
    printf("Signature created \n");

    //verify signature
    if (1 == secp256k1_ecdsa_verify(myContext, &mySig, digest, &myPublicKey))
    {
        printf("Signature verified \n");
    }
    else
    {
        printf("Signature could not be verified \n");
        exit(1);
    }

    //serialize signature in compact form
    secp256k1_ecdsa_signature_serialize_compact(myContext, signatureComp, &mySig);
    //serialize signature in compact form
    size_t derLen = 72;
    secp256k1_ecdsa_signature_serialize_der(myContext, signatureDer, &derLen, &mySig);

    //check if compact signature can be parsed
    secp256k1_ecdsa_signature sigTest0;
    if (1 == secp256k1_ecdsa_signature_parse_compact(myContext, &sigTest0, signatureComp))
    {
        printf("Compact signature able to be parsed \n");
    }
    else
    {
        printf("Compact signature could not be parsed \n");
        exit(1);
    }

    //check if DER encoded signature can be parsed
    secp256k1_ecdsa_signature sigTest1;
    if (1 == secp256k1_ecdsa_signature_parse_der(myContext, &sigTest1, signatureDer, derLen))
    {
        printf("DER encoded signature able to be parsed \n\n");
    }
    else
    {
        printf("DER encoded signature could not be parsed \n");
        exit(1);
    }

    return 1;
}


int main(int argc, char **argv)
{
    //seed random for rng
    srand(time(NULL));

    //check args to see which command should be triggered (usage info, test sign, sign)
    command = ParseArgumentsIntoCommand(argc);

    //execute command (only outputs to console at the moment)
    ExecuteCommand(argv, command);
    return 0;
}

//TEST WITH THIS:
//private key: 6f910beb039b93eba3bf95eb9ab2610855f18a7512463c78bc9ebf774535e89f