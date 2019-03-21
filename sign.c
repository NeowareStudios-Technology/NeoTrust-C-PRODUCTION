/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "sign.h"

//sets up all data structures necessary to sign a test message with a test private key and signs in ECDSA
void CompleteTestSigProcess()
{
    uint8_t* serializedDigest;
    uint8_t* serializedSecKey;
    uint8_t* serializedPubKeyCompressed;
    uint8_t* serializedPubKeyUncompressed;
    uint8_t* serializedSignatureComp;
    uint8_t* serializedSignatureDer;
    serializedDigest = malloc(sizeof(uint8_t)*32);
    serializedSecKey = malloc(sizeof(uint8_t)*32);
    serializedPubKeyCompressed = malloc(sizeof(uint8_t)*33);
    serializedPubKeyUncompressed = malloc(sizeof(uint8_t)*65);
    serializedSignatureComp = malloc(sizeof(uint8_t)*64);
    //72 is max length for DER sig, but can be shorters
    serializedSignatureDer = malloc(sizeof(uint8_t)*72);
    secp256k1_scalar myMessageHash, myPrivateKey;

    printf("\nStarting signing test with test pub/priv keys and test message hash");
    //generate random message hash and private key?
    CreateTestSecp256k1ScalarObject(&myMessageHash);
    CreateTestSecp256k1ScalarObject(&myPrivateKey);
    printf("SIZE::%d", sizeof(myPrivateKey));
    
    //convert message hash to uint8_t 32 bytes
    secp256k1_scalar_get_b32(serializedDigest, &myMessageHash);
    secp256k1_scalar_get_b32(serializedSecKey, &myPrivateKey);

    //replace this with generatePubKey() + SignMessage() combo
    //VerifyParamsAndSignMessageWithEcdsa(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, serializedDigest, serializedSignatureComp, serializedSignatureDer);
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN| SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey myPublicKey = GenerateAndVerifyPubKey(myContext,serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed);
    VerifyParamsAndSignMessageWithEcdsa(myPublicKey, serializedSecKey, serializedDigest, serializedSignatureComp, serializedSignatureDer);

    printValues(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, serializedDigest, serializedSignatureComp, serializedSignatureDer);

    free(serializedDigest);
    free(serializedSecKey);
    free(serializedPubKeyCompressed);
    free(serializedPubKeyUncompressed);
    free(serializedSignatureComp);
    free(serializedSignatureDer);
}

void CreateTestSecp256k1ScalarObject(secp256k1_scalar *num) {
   do {
       uint8_t b32[32];
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
    char **fileContents;
    FILE *manifestFilePointer;
    FILE *signatureFilePointer;
    long fileLength;
    long fileCount = 0;
    char* metaInfDirPath[1000];
    //for signing with private key
    uint8_t *serializedDigest;
    uint8_t *serializedSecKey;
    uint8_t *serializedPubKeyCompressed;
    uint8_t *serializedPubKeyUncompressed;
    uint8_t *serializedSignatureComp;
    uint8_t *serializedSignatureDer;
    serializedDigest = malloc(sizeof(uint8_t)*32);
    serializedSecKey = malloc(sizeof(uint8_t)*32);
    serializedPubKeyCompressed = malloc(sizeof(uint8_t)*33);
    serializedPubKeyUncompressed = malloc(sizeof(uint8_t)*65);
    serializedSignatureComp = malloc(sizeof(uint8_t)*64);
    //72 is max length for DER sig, but can be shorter
    serializedSignatureDer = malloc(sizeof(uint8_t)*72);
    secp256k1_scalar myMessageHash, myPrivateKey;

    //add space between each hex number in private key and convert to uint8_t *
    const char* secKey = insertSpaces(paramSecKey);
    serializedSecKey = stringToHex(secKey);

    printf("\n");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x",serializedSecKey[i]);
    }
    printf("\n");

    //generate public key from private key
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN| SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey myPublicKey = GenerateAndVerifyPubKey(myContext,serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed);

    //count number of files in target directory
    countFilesInDirectory(paramDirName, &fileCount);
    printf("\n(CompleteSigProcess) number of files: %d\n", fileCount);

    strcpy(metaInfDirPath, paramDirName);
    strcat(metaInfDirPath, "/META-INF");
    mkdir(metaInfDirPath, 0700);
    manifestFilePointer = CreateBaseManifestFile(metaInfDirPath, serializedPubKeyUncompressed);   
    signatureFilePointer = CreateBaseSignatureFile(metaInfDirPath); 

    //make a digest for each file, saving to manifest file
    long workingFileIndex = -1;
    SaveFileNameAndDigestToManifest(paramDirName, &workingFileIndex, manifestFilePointer); 

    printf("\n");  

    //need to do here:
    //-create manifest file from all hashe and names of files
    //-create a digest of the entire manifest file (manifestDigest)
  
    //VerifyParamsAndSignMessageWithEcdsa(myPublicKey, serializedSecKey, manifestDigest, serializedSignatureComp, serializedSignatureDer);
    //printValues(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, fileDigests[i], serializedSignatureComp, serializedSignatureDer);
   
    free(serializedDigest);
    free(serializedSecKey);
    free(serializedPubKeyCompressed);
    free(serializedPubKeyUncompressed);
    free(serializedSignatureComp);
    free(serializedSignatureDer);
}

void VerifyParamsAndSignMessageWithEcdsa(secp256k1_pubkey paramMyPublicKey, uint8_t* secKey, uint8_t* digest, uint8_t* signatureComp, uint8_t* signatureDer)
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
    

    //verify the private key
    if(1 == secp256k1_ec_seckey_verify(myContext, secKey))
        printf("\nPrivate key verified \n");
    else
    {
        printf("Private key failed verification \n");
        exit(1);
    }
    
    //sign message hash with private key
    secp256k1_ecdsa_sign(myContext, &mySig, digest, secKey, NULL, NULL);
    printf("Signature created \n");

    //verify signature
    if (1 == secp256k1_ecdsa_verify(myContext, &mySig, digest, &paramMyPublicKey))
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

secp256k1_pubkey GenerateAndVerifyPubKey(secp256k1_context *paramMyContext, uint8_t* secKey, uint8_t* pubKeyComp, uint8_t* pubKeyUncomp)
{
    secp256k1_pubkey myPublicKey;
    size_t pubKeyCompLen;
    size_t pubKeyUncompLen;

    //construct the corresponding public key
    if(1 == secp256k1_ec_pubkey_create(paramMyContext, &myPublicKey, secKey))
        printf("Public key created \n");
    else
    {
        printf("Public key could not be created \n");
        exit(1);
    }

    //get seralized public key (compressed)
    pubKeyCompLen = 33;
    secp256k1_ec_pubkey_serialize(paramMyContext, pubKeyComp, &pubKeyCompLen, &myPublicKey, SECP256K1_EC_COMPRESSED);
    secp256k1_pubkey pubkeytest0;
    if (1 == secp256k1_ec_pubkey_parse(paramMyContext, &pubkeytest0, pubKeyComp, pubKeyCompLen)) 
        printf("Compressed public key able to be parsed \n");
    else
    {
        printf("Error parsing compressed public key \n");
        exit(1);
    }

    //get seralized public key (uncompressed)
    pubKeyUncompLen = 65;
    secp256k1_ec_pubkey_serialize(paramMyContext, pubKeyUncomp, &pubKeyUncompLen, &myPublicKey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_pubkey pubkeytest1;
    if (1 == secp256k1_ec_pubkey_parse(paramMyContext, &pubkeytest1, pubKeyUncomp, pubKeyUncompLen)) 
        printf("Uncompressed public key able to be parsed \n");
    else
    {
        printf("Error parsing uncompressed public key \n");
        exit(1);
    }

    return myPublicKey;
}