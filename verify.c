/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 3/28/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "verify.h"


void VerifyNeoPakSignature(char *paramTargetDir)
{
    char metaInfDirPath[256];
    char signatureFilePath[256];
    long signatureFileLength;
    FILE *signatureFilePointer;
    secp256k1_context *verifyContext = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY); 
    secp256k1_ecdsa_signature sigObject;
    secp256k1_pubkey pubKeyObject;

    //create file paths
    strcpy(metaInfDirPath, paramTargetDir);
    strcat(metaInfDirPath, "/META-INF");

    GetSigObjectFromSigBlockFile(metaInfDirPath, &sigObject, verifyContext);
    GetPubKeyObjectFromManifestFile(metaInfDirPath, &pubKeyObject, verifyContext);
    
    //get the transaction hash (when it exists) and save it

    //create verification manifest file by hashing all files in neopak

    //create verification sig file from manifest file

    //create digest of verification sig file

    //decrypt signature using sender's public key (found in manifest file)

    //compare decrypted signature with digest of verification sig file
        //if matches, verification passes
        //if doe not match, verification fails


    //DEBUG
    /*
    if (1 != secp256k1_ecdsa_verify(verifyContext, &sigObject, digest, &paramMyPublicKey))
    {
        printf("Signature could not be verified \n");
    }
    */

}


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
    secp256k1_ecdsa_signature_parse_der(paramContext, paramSigObject, signatureBlockFileContents, signatureBlockFileLength); 
}


void GetPubKeyObjectFromManifestFile(char *metaInfDirPath, secp256k1_pubkey *pubKeyObject, secp256k1_context *paramContext)
{
    char manifestFilePath[256];
    char pubKeyBuffer[256];
    long manifestFileLength;
    int pubKeyLength;
    FILE *manifestFilePointer;

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

    pubKeyLength = cutStringAndReturnLength(pubKeyBuffer, 0, 12);

    fclose(manifestFilePointer);

}
