/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 3/28/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "verify.h"


void VerifyNeoPakSignature(char *paramTargetDir)
{
    char *metaInfDirPath = malloc(256);
    char *signatureBlockFilePath = malloc(256);
    char *manifestFilePath = malloc(256);
    char *signatureFilePath = malloc(256);
    long signatureBlockFileLength;
    long manifestFileLength;
    long signatureFileLength;
    FILE *signatureBlockFilePointer;
    FILE *manifestFilePointer;
    FILE *signatureFilePointer;
    uint8_t *signatureBlockFileContents;
    secp256k1_context *verifyContext = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY); 
    secp256k1_ecdsa_signature sigObject;

    //create file paths
    strcpy(metaInfDirPath, paramTargetDir);
    strcat(metaInfDirPath, "/META-INF");
    strcpy(signatureBlockFilePath, metaInfDirPath);
    strcat(signatureBlockFilePath, "/neopak.ec");
    strcpy(manifestFilePath, metaInfDirPath);
    strcat(manifestFilePath, "/manifest");

    //read signature block file into uint8_t array
    signatureBlockFilePointer = fopen(signatureBlockFilePath, "rb");
    if (!signatureBlockFilePointer)
        printf("Signature file coud not be opened to read");


    signatureBlockFileLength = getFileLength(signatureBlockFilePointer);
    
    signatureBlockFileContents = (uint8_t *)malloc((signatureFileLength+1)*sizeof(uint8_t)); // Enough memory for file + \0
    fread(signatureBlockFileContents, signatureFileLength, 1, signatureBlockFilePointer); // Read in the entire file

    //debug: print signature read
    printf("Signature (verify): \n");
    for (int i = 0; i < signatureBlockFileLength; i++)
    {
        printf("%02x", signatureBlockFileContents[i]);
    }
    printf("\n\n");

    //parse DER signature retrieved from signature block file into signature object
    secp256k1_ecdsa_signature_parse_der(verifyContext, &sigObject, signatureBlockFileContents, signatureBlockFileLength); 

    /*
    if (1 != secp256k1_ecdsa_verify(verifyContext, &sigObject, digest, &paramMyPublicKey))
    {
        printf("Signature could not be verified \n");
        exit(1);
    }
    */

}