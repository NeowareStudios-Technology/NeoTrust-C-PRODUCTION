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
#include <dirent.h>

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
void CompleteTestSigProcess();
void CompleteSigProcess(char *paramSecKey, char *paramFileName);
void ComputeSha256FromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest);
void VerifyParamsAndSignMessageWithEcdsa(unsigned char* secKey, unsigned char* pubKeyComp, unsigned char* pubKeyUncomp, unsigned char* digest, unsigned char* signatureComp, unsigned char* signatureDer);
void random_scalar_order_test_new(secp256k1_scalar *num);
void countFilesInDirectory(char *basePath, const int root, long *count);
void MakeDigestForEachFile(char *basePath, const int root, uint8_t paramFileDigests[9999999][32], long *paramWorkingFileCount);


void DisplayUsageInfo()
{
    printf("\nNeoPak\nCopywrite NeoWare 2019\n");
    printf("Created by David Lee Ramirez 2/12/2019 \n");
    printf("Usage:\n");
    printf("./neopak                                  Show usage info\n");
    printf("./neopak test                             Sign with test priv key and message hash\n");
    printf("./neopak <privKey> <filePath>             Sign with provided priv key and file\n");
    printf("\n *Note: <privKey> must be supplied \n        as a string of hex numbers with length 64 \n");
}


enum commands ParseArgumentsIntoCommand(int paramArgc)
{
    //if no args passed, display usage info
    if (paramArgc == 1)
        return usage;
    //if only "test" is passed as arg, start test sign
    else if (paramArgc == 2)
        return testSign;
    //if private key and message hash are passed as args, start
    //production sign
    else if (paramArgc == 3)
        return sign;
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


void random_scalar_order_test_new(secp256k1_scalar *num) {
   do {
       unsigned char b32[32];
       int overflow = 0;
       secp256k1_rand256(b32);
       secp256k1_scalar_set_b32(num, b32, &overflow);
       if (overflow || secp256k1_scalar_is_zero(num)) {
           continue;
       }
       break;
   } while(1);
}


void CompleteSigProcess(char *paramSecKey, char *paramDirName)
{
    //for calculating digest
    char **fileContents;
    FILE *filePointer;
    long fileLength;
    long fileCount = 0;

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


    countFilesInDirectory(paramDirName, 0, &fileCount);
    uint8_t fileDigests[fileCount][32];
    long workingFileCount = -1;
    printf("\nnumber of files: %d\n", fileCount);
    MakeDigestForEachFile(paramDirName,0, fileDigests, &workingFileCount);
    
/*

    //make sure passed private key is exactly 64 chars long
    if (strlen(paramSecKey) != 64)
    {
        printf("\nError: incorrect usage, private key and message hash must be exaclty 64 chars long");
        exit(0);
    }

    //read file into string
    filePointer = fopen(paramFileName, "r");
    fileLength = getFileLength(paramFileName, filePointer);
    fileContents = (char *)malloc((fileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(fileContents, fileLength, 1, filePointer); // Read in the entire file
    fclose(filePointer); // Close the file

    ComputeSha256FromString(fileContents, fileLength, fileDigest);
    
    //add space between each hex number in private key and digest 
    const char* secKey = insertSpaces(paramSecKey);
    int lengthKey = strlen(secKey);
    int *keyLengthPtr = &lengthKey;
    serializedSecKey = convert(secKey, keyLengthPtr);

    VerifyParamsAndSignMessageWithEcdsa(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, fileDigest, serializedSignatureComp, serializedSignatureDer);

    printValues(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, fileDigest, serializedSignatureComp, serializedSignatureDer);
    */
}

void countFilesInDirectory(char *basePath, const int root, long *count)
{
   int i;
   char path[1000];
   struct dirent *dp;
   DIR *dir = opendir(basePath);

   if (!dir)
       return;

   while ((dp = readdir(dir)) != NULL)
   {
       if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0)
       {
           for (i=0; i<root; i++)
           {
               if (i%2 == 0 || i == 0)
                {
                    
                }
               else
                   printf(" ");

           }
            if (dp->d_type != DT_DIR)
                *count = *count + 1;

           strcpy(path, basePath);
           strcat(path, "/");
           strcat(path, dp->d_name);
           countFilesInDirectory(path, root + 2, count);
       }
   }

   closedir(dir);
}

void MakeDigestForEachFile(char *basePath, const int root, uint8_t paramFileDigests[9999999][32], long *paramWorkingFileCount)
{
    int i;
    char path[1000];
    struct dirent *dp;
    DIR *dir = opendir(basePath);
    long fileLength;

    if (!dir)
        return; 
    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0)
        {
           for (i=0; i<root; i++)
           {
               if (i%2 == 0 || i == 0)
                {   
                }
               else
                   printf(" "); 
           }    

           strcpy(path, basePath);
           strcat(path, "/");
           strcat(path, dp->d_name);
           //if it is a file, read file into string
           if (dp->d_type != DT_DIR)
            {
                *paramWorkingFileCount= *paramWorkingFileCount + 1;
                FILE* filePointer = fopen(path, "r");
                if (!filePointer)
                    printf("%s file coud not be opened to read",path);
                fileLength = getFileLength(path, filePointer);
                char *fileContents = (char *)malloc((fileLength+1)*sizeof(char)); // Enough memory for file + \0
                fread(fileContents, fileLength, 1, filePointer); // Read in the entire file
                fclose(filePointer); // Close the file

                printf("\n");
                printf("file contents: ");
                for (int i = 0; i<fileLength; i++)
                {
                    printf("%c", fileContents[i]);
                }
                printf("\n");

                printf("file count: %d", *paramWorkingFileCount);
                ComputeSha256FromString(fileContents, fileLength, paramFileDigests[*paramWorkingFileCount]);

                printf("\n");
                for (int i = 0; i<32; i++)
                {
                    printf("%02x", paramFileDigests[*paramWorkingFileCount][i]);
                }
                printf("\n");

                free(fileContents);
            }

           MakeDigestForEachFile(path, root + 2, paramFileDigests, paramWorkingFileCount);    
        }
    }
    closedir(dir);
}

void ComputeSha256FromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest)
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


void VerifyParamsAndSignMessageWithEcdsa(unsigned char* secKey, unsigned char* pubKeyComp, unsigned char* pubKeyUncomp, unsigned char* digest, unsigned char* signatureComp, unsigned char* signatureDer)
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
        printf("\nPrivate key verified \n");
    else
    {
        printf("Private key failed verification \n");
        exit(1);
    }

    //construct the corresponding public key
    if(1 == secp256k1_ec_pubkey_create(myContext, &myPublicKey, secKey))
        printf("Public key created \n");
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
        printf("Compressed public key able to be parsed \n");
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
        printf("Uncompressed public key able to be parsed \n");
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
        printf("Signature verified \n");
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
        printf("Compact signature able to be parsed \n");
    else
    {
        printf("Compact signature could not be parsed \n");
        exit(1);
    }

    //check if DER encoded signature can be parsed
    secp256k1_ecdsa_signature sigTest1;
    if (1 == secp256k1_ecdsa_signature_parse_der(myContext, &sigTest1, signatureDer, derLen))
        printf("DER encoded signature able to be parsed \n\n");
    else
    {
        printf("DER encoded signature could not be parsed \n");
        exit(1);
    }
}


int main(int argc, char **argv)
{
    command = ParseArgumentsIntoCommand(argc);

    ExecuteCommand(argv, command);
    return 0;
}

//TEST WITH THIS:
//private key: 6f910beb039b93eba3bf95eb9ab2610855f18a7512463c78bc9ebf774535e89f