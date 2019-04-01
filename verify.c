/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 3/28/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "verify.h"


void GetSigObjectFromSigBlockFile(char *paramMetaInfDirPath, secp256k1_ecdsa_signature *paramSigObject, secp256k1_context *paramContext)
{
    char signatureBlockFilePath[256];
    FILE *signatureBlockFilePointer;
    uint8_t *signatureBlockFileContents;
    long signatureBlockFileLength;

    strcpy(signatureBlockFilePath, paramMetaInfDirPath);
    strcat(signatureBlockFilePath, "/neopak.ec");

    //read signature block file into uint8_t array
    signatureBlockFilePointer = fopen(signatureBlockFilePath, "rb");
    if (!signatureBlockFilePointer)
    {
        printf("Signature file coud not be opened to read\n");
        exit(1);
    }
    signatureBlockFileLength = getFileLength(signatureBlockFilePointer);
    signatureBlockFileContents = (uint8_t *)malloc((signatureBlockFileLength+1)*sizeof(uint8_t)); // Enough memory for file + \0
    fread(signatureBlockFileContents, signatureBlockFileLength, 1, signatureBlockFilePointer); // Read in the entire file

    //debug: print signature read
    printf("Signature (verify): \n");
    for (int i = 0; i < signatureBlockFileLength; i++)
    {
        printf("%02x", signatureBlockFileContents[i]);
    }
    printf("\n\n");

    //parse DER signature retrieved from signature block file into signature object
    if (1 != secp256k1_ecdsa_signature_parse_der(paramContext, paramSigObject, signatureBlockFileContents, signatureBlockFileLength))
    {
        printf("Signature could not be parsed into object\n");
        exit(1);
    }

    free(signatureBlockFileContents);
    fclose(signatureBlockFilePointer);
}


void GetPubKeyObjectFromManifestFile(char *metaInfDirPath, secp256k1_pubkey *paramPubKeyObject, secp256k1_context *paramContext)
{
    char manifestFilePath[256];
    char pubKeyBuffer[256];
    long manifestFileLength;
    int pubKeyLength;
    FILE *manifestFilePointer;
    uint8_t *serializedPubKeyCompressed = malloc(sizeof(uint8_t)*33);

    strcpy(manifestFilePath, metaInfDirPath);
    strcat(manifestFilePath, "/manifest");

    manifestFilePointer = fopen(manifestFilePath, "r");
    if (!manifestFilePointer)
    {
        printf("Manifest file coud not be opened to read\n");
        exit(1);
    }

    //get third line of manifest file (which should be the public key)
    for (int i = 0; i < 3; i++)
    {
        fgets(pubKeyBuffer, 256, manifestFilePointer);
    }

    if((strstr(pubKeyBuffer, "Public Key: ")) == NULL)
    {
        printf("Public Key could not be found in manifest file\n");
    }

    //cut pub key buffer so only pub key is held in it
    pubKeyLength = cutStringAndReturnLength(pubKeyBuffer, 0, 12);

    //convert compressed pub key hex string to uint8_t hex array
    const char *pubKeyWithSpaces = compPubKeyInsertSpaces(pubKeyBuffer);
    serializedPubKeyCompressed = compPubKeyStringToHex(pubKeyWithSpaces);
    if (1 != secp256k1_ec_pubkey_parse(paramContext, paramPubKeyObject, serializedPubKeyCompressed, 33))
    {
        printf("Public Key could not be parsed into object\n");
        exit(1);
    }  

    free(serializedPubKeyCompressed);
    fclose(manifestFilePointer);
}
