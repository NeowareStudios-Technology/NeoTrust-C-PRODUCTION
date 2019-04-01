/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/


#include "neopak.h"


//global
enum commands{usage, verify, sign}command;

enum commands ParseArgumentsIntoCommand(int paramArgc);
void ExecuteCommand(char **paramArgs, enum commands paramCommand);
void DisplayUsageInfo();


enum commands ParseArgumentsIntoCommand(int paramArgc)
{
    //if no args passed, display usage info
    if (paramArgc == 1)
        return usage;
    //if only target dir path is passed, start verification
    else if (paramArgc == 2)
        return verify;
    //if private key and directory path are passed, start production sign
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
        case verify:
            MainVerify(paramArgs[1]);
            break;
        case sign:
            MainSign(paramArgs[1], paramArgs[2]);
            break;
    }
}


void DisplayUsageInfo()
{
    printf("\nNeoPak\nCopywrite NeoWare 2019\n");
    printf("Created by David Lee Ramirez 2/12/2019 \n");
    printf("Usage:\n");
    printf("./neopak                                  Show usage info\n");
    printf("./neopak test                             Sign with test priv key and message hash\n");
    printf("./neopak <privKey> <directoryPath>        Sign all files in directory with private key\n");
    printf("\n *Note: <privKey> must be supplied as a string of hex numbers with length 64 \n");
}


//no return value
void MainSign(char *paramSecKey, char *paramDirName)
{
    FILE *manifestFilePointer;
    FILE *tempSignatureFilePointer;
    FILE *finalSignatureFilePointer;
    long fileLength;
    //long fileCount = 0;
    char metaInfDirPath[1024];
    char *manifestFileName = "manifest.mf";
    char *sigFileName = "neopak.sf";
    //for signing with private key
    size_t serializedSignatureDerLength;
    uint8_t *serializedDigest = malloc(sizeof(uint8_t)*32);
    uint8_t *serializedSecKey = malloc(sizeof(uint8_t)*32);
    uint8_t *signatureFileDigest = malloc(sizeof(uint8_t)*32);
    uint8_t *serializedPubKeyCompressed = malloc(sizeof(uint8_t)*33);
    uint8_t *serializedPubKeyUncompressed = malloc(sizeof(uint8_t)*65);
    uint8_t *serializedSignatureComp = malloc(sizeof(uint8_t)*64);
    //72 is max length for DER sig, but can be shorter
    uint8_t *serializedSignatureDer = malloc(sizeof(uint8_t)*72);
    secp256k1_scalar myMessageHash, myPrivateKey;

    //add space between each hex number in private key and convert to uint8_t *
    const char* secKey = privKeyInsertSpaces(paramSecKey);
    serializedSecKey = privKeyStringToHex(secKey);

    //generate public key from private key
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN| SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey myPublicKey = GeneratePubKeyFromPrivKey(myContext,serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed);

    strcpy(metaInfDirPath, paramDirName);
    strcat(metaInfDirPath, "/META-INF");
    mkdir(metaInfDirPath, 0700);
    manifestFilePointer = CreateBaseManifestFile(metaInfDirPath, manifestFileName, serializedPubKeyCompressed);   
    tempSignatureFilePointer = CreateBaseSignatureFile(metaInfDirPath); 

    //make a digest for each file, saving to manifest file
    CreateDigestsAndMetaInfEntries(paramDirName, manifestFilePointer, tempSignatureFilePointer); 
    finalSignatureFilePointer =  GenerateFullManifestDigestAndSaveInSigFile(metaInfDirPath, sigFileName, manifestFilePointer, tempSignatureFilePointer);

    //-send ethereum transaction containing pub key and full manifest digest (ie. call JavaScript function here using Duktape)
    //-append transaction hash to manifest file 

    GenerateSignatureFileDigest(finalSignatureFilePointer, signatureFileDigest);

    serializedSignatureDerLength = VerifyParamsAndSignMessageWithEcdsa(myPublicKey, serializedSecKey, signatureFileDigest, serializedSignatureComp, serializedSignatureDer);
    CreateSignatureBlockFile(metaInfDirPath, serializedSignatureDer, serializedSignatureDerLength);
    //printValues(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, signatureFileDigest, serializedSignatureComp, serializedSignatureDer);
   
    fclose(manifestFilePointer);
    fclose(tempSignatureFilePointer);
    free(serializedDigest);
    free(serializedSecKey);
    free(serializedPubKeyCompressed);
    free(serializedPubKeyUncompressed);
    free(serializedSignatureComp);
    free(serializedSignatureDer);
}


void MainVerify(char *paramTargetDir)
{
    char metaInfDirPath[256];
    long verificationSignatureFileLength;
    FILE *verificationTempSignatureFilePointer;
    FILE *verificationManifestFilePointer;
    char *verificationManifestFileName = "manifest.verify";
    secp256k1_context *verifyContext = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY); 
    secp256k1_ecdsa_signature sigObject;
    secp256k1_pubkey pubKeyObject;
    uint8_t *serializedPubKeyCompressed = malloc(sizeof(uint8_t)*33);

    //create file paths
    strcpy(metaInfDirPath, paramTargetDir);
    strcat(metaInfDirPath, "/META-INF");

    GetSigObjectFromSigBlockFile(metaInfDirPath, &sigObject, verifyContext);
    GetPubKeyObjectFromManifestFile(metaInfDirPath, &pubKeyObject, serializedPubKeyCompressed, verifyContext);
    
    //get the transaction hash (when it exists) and save it

    //create verification manifest file by hashing all files in neopak
    verificationManifestFilePointer = CreateBaseManifestFile(metaInfDirPath, verificationManifestFileName, serializedPubKeyCompressed);
    verificationTempSignatureFilePointer = CreateBaseSignatureFile(metaInfDirPath);

    CreateDigestsAndMetaInfEntries(paramTargetDir, verificationManifestFilePointer, verificationTempSignatureFilePointer); 

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


int main(int argc, char **argv)
{
    command = ParseArgumentsIntoCommand(argc);

    ExecuteCommand(argv, command);

    return 0;
}

//TEST WITH THIS:
//private key: 6f910beb039b93eba3bf95eb9ab2610855f18a7512463c78bc9ebf774535e89f