/************************************
 * Project: NeoTrust
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/


#include "neotrust.h"


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
    printf("./neotrust                                  Show usage info\n");
    printf("./neotrust test                             Sign with test priv key and message hash\n");
    printf("./neotrust <privKey> <directoryPath>        Sign all files in directory with private key\n");
    printf("\n *Note: <privKey> must be supplied as a string of hex numbers with length 64 \n");
}


void MainSign(char *paramSecKey, char *paramDirName)
{
    FILE *manifestFilePointer;
    FILE *tempSignatureFilePointer;
    FILE *finalSignatureFilePointer;
    long fileLength;
    char metaInfDirPath[1024];
    char *manifestFileName = "manifest.mf";
    char *sigFileName = "neotrust.sf";
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

    //create META-INF directory in target directory
    strcpy(metaInfDirPath, paramDirName);
    strcat(metaInfDirPath, "/META-INF");
    mkdir(metaInfDirPath, 0700);

    manifestFilePointer = CreateBaseManifestFile(metaInfDirPath, manifestFileName, serializedPubKeyCompressed);   
    tempSignatureFilePointer = CreateBaseSignatureFile(metaInfDirPath); 

    //create manifest file and signature file entries from each file in target directory
    //(target file -> digest -> manifest file entry -> digest -> signature file entry)
    CreateDigestsAndMetaInfEntries(paramDirName, manifestFilePointer, tempSignatureFilePointer); 

    //create the full signature file (this must be called last (after file iteration) as it requires the digest of the complete manifest file)
    finalSignatureFilePointer =  GenerateFullManifestDigestAndSaveInSigFile(metaInfDirPath, sigFileName, manifestFilePointer, tempSignatureFilePointer);

    //TO DO
    //-send ethereum transaction containing pub key and full manifest digest (ie. call JavaScript function here using Duktape)
    //-append transaction hash to manifest file 

    GenerateSignatureFileDigest(finalSignatureFilePointer, signatureFileDigest);

    //create signature by signing the digest of the full signature file with the user's privat key
    serializedSignatureDerLength = VerifyParamsAndSignMessageWithEcdsa(myPublicKey, serializedSecKey, signatureFileDigest, serializedSignatureComp, serializedSignatureDer);
    //save signature to binary file
    CreateSignatureBlockFile(metaInfDirPath, serializedSignatureDer, serializedSignatureDerLength);
   
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
    FILE *verificationFinalSigFilePointer;
    char *verificationManifestFileName = "manifest.mf.verify";
    char *verificationFinalSigFileName = "neotrust.sf.verify";
    char verificationManifestFilePath[256];
    char verificationFinalSigFilePath[256];
    secp256k1_context *verifyContext = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY); 
    secp256k1_ecdsa_signature sigObject;
    secp256k1_pubkey pubKeyObject;
    uint8_t *serializedPubKeyCompressed = malloc(sizeof(uint8_t)*33);
    uint8_t *signatureFileDigest = malloc(sizeof(uint8_t)*32);

    //create file paths for temporary verification manifest and signature files
    strcpy(metaInfDirPath, paramTargetDir);
    strcat(metaInfDirPath, "/META-INF");

    strcpy(verificationManifestFilePath, metaInfDirPath);
    strcat(verificationManifestFilePath, "/");
    strcat(verificationManifestFilePath, verificationManifestFileName);

    strcpy(verificationFinalSigFilePath, metaInfDirPath);
    strcat(verificationFinalSigFilePath, "/");
    strcat(verificationFinalSigFilePath, verificationFinalSigFileName);

    //Read signature from signature block file into signature object (required for use with libsecp256k1 library)
    GetSigObjectFromSigBlockFile(metaInfDirPath, &sigObject, verifyContext);
    //Read compressed public key from manifest into public key object (required for use with libsecp256k1 library)
    GetPubKeyObjectFromManifestFile(metaInfDirPath, &pubKeyObject, serializedPubKeyCompressed, verifyContext);
    
    //TO DO
    //get the transaction hash (when it exists) and save it

    //generate temporary verification manifest and signature files for digest comparisons with original values
    verificationManifestFilePointer = CreateBaseManifestFile(metaInfDirPath, verificationManifestFileName, serializedPubKeyCompressed);
    verificationTempSignatureFilePointer = CreateBaseSignatureFile(metaInfDirPath);
    CreateDigestsAndMetaInfEntries(paramTargetDir, verificationManifestFilePointer, verificationTempSignatureFilePointer); 
    verificationFinalSigFilePointer =  GenerateFullManifestDigestAndSaveInSigFile(metaInfDirPath, verificationFinalSigFileName, verificationManifestFilePointer, verificationTempSignatureFilePointer);

    //generate digest that will be used to verify signature
    GenerateSignatureFileDigest(verificationFinalSigFilePointer, signatureFileDigest);

    remove(verificationFinalSigFilePath);
    remove(verificationManifestFilePath);

    //verify signature against signature file digest that was just generated. if digest resulting from decrypting the signature with the 
    //public key matches digest of signature file just generated, verification passes. if not, verification fails.
    if (1 != secp256k1_ecdsa_verify(verifyContext, &sigObject, signatureFileDigest, &pubKeyObject))
    {
        printf("This neotrust archive could not be verified. This means that the files in the \nneopak have been tampered with since it was signed or it was signed by a \ndifferent user than the one who owns the public key in the manifest file.\n");
    }
    else
    {
        printf("Neopak verification successful.\n");
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