/************************************
 * Project: NeoTrust
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "sign.h"


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


//return value: length of DER encoded signature
//return params: signatureComp, signatureDer
size_t VerifyParamsAndSignMessageWithEcdsa(secp256k1_pubkey paramMyPublicKey, uint8_t* secKey, uint8_t* digest, uint8_t* signatureComp, uint8_t* signatureDer)
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
    if(1 != secp256k1_ec_seckey_verify(myContext, secKey))
    {
        printf("Private key failed verification \n");
        exit(1);
    }
    
    //sign message hash with private key
    secp256k1_ecdsa_sign(myContext, &mySig, digest, secKey, NULL, NULL);

    //verify signature
    if (1 != secp256k1_ecdsa_verify(myContext, &mySig, digest, &paramMyPublicKey))
    {
        printf("Sig could not be verified \n");
        exit(1);
    }

    //serialize signature in compact form
    secp256k1_ecdsa_signature_serialize_compact(myContext, signatureComp, &mySig);
    //serialize signature in der form

    size_t derLen = 72;
    secp256k1_ecdsa_signature_serialize_der(myContext, signatureDer, &derLen, &mySig);

    //check if compact signature can be parsed
    secp256k1_ecdsa_signature sigTest0;
    if (1 != secp256k1_ecdsa_signature_parse_compact(myContext, &sigTest0, signatureComp))
    {
        printf("Compact signature could not be parsed \n");
        exit(1);
    }

    //check if DER encoded signature can be parsed
    secp256k1_ecdsa_signature sigTest1;
    if (1 != secp256k1_ecdsa_signature_parse_der(myContext, &sigTest1, signatureDer, derLen))
    {
        printf("DER encoded signature could not be parsed \n");
        exit(1);
    }

    return(derLen);
}


//return params: pubKeyComp, pubKeyUncomp
secp256k1_pubkey GeneratePubKeyFromPrivKey(secp256k1_context *paramMyContext, uint8_t* secKey, uint8_t* pubKeyComp, uint8_t* pubKeyUncomp)
{
    secp256k1_pubkey myPublicKey;
    size_t pubKeyCompLen;
    size_t pubKeyUncompLen;

    //construct the corresponding public key
    if(1 != secp256k1_ec_pubkey_create(paramMyContext, &myPublicKey, secKey))
    {
        printf("Public key could not be created \n");
        exit(1);
    }

    //get seralized public key (compressed)
    pubKeyCompLen = 33;
    secp256k1_ec_pubkey_serialize(paramMyContext, pubKeyComp, &pubKeyCompLen, &myPublicKey, SECP256K1_EC_COMPRESSED);
    secp256k1_pubkey pubkeytest0;
    if (1 != secp256k1_ec_pubkey_parse(paramMyContext, &pubkeytest0, pubKeyComp, pubKeyCompLen)) 
    {
        printf("Error parsing compressed public key \n");
        exit(1);
    }

    //get seralized public key (uncompressed)
    pubKeyUncompLen = 65;
    secp256k1_ec_pubkey_serialize(paramMyContext, pubKeyUncomp, &pubKeyUncompLen, &myPublicKey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_pubkey pubkeytest1;
    if (1 != secp256k1_ec_pubkey_parse(paramMyContext, &pubkeytest1, pubKeyUncomp, pubKeyUncompLen)) 
    {
        printf("Error parsing uncompressed public key \n");
        exit(1);
    }

    return myPublicKey;
}


//no return value
void CreateSigBlockFile(char *paramMetaInfDirPath, uint8_t *paramSerializedSigDer, size_t paramSerializedSigDerLength)
{
    FILE *signatureBlockFilePointer;
    char signatureBlockFilePath[256];

    //create file paths
    strcpy(signatureBlockFilePath, paramMetaInfDirPath);
    strcat(signatureBlockFilePath, "/neotrust.ec");

    signatureBlockFilePointer = fopen(signatureBlockFilePath, "wb");
    if (!signatureBlockFilePointer)
    {
        printf("\n\nCOULD NOT OPEN SIG BLOCK FILE\n\n");
    }
    
    //write signature (in binary form) to signature block file
    fwrite(paramSerializedSigDer, sizeof(uint8_t), paramSerializedSigDerLength, signatureBlockFilePointer);
}