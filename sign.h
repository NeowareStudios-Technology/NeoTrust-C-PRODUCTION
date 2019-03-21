/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"
#include "include/testrand_impl.h"
#include "helper.h"
#include "digest.h"

void CompleteTestSigProcess();

void CreateTestSecp256k1ScalarObject(secp256k1_scalar *num);

void CompleteSigProcess(char *paramSecKey, char *paramFileName);

void VerifyParamsAndSignMessageWithEcdsa(secp256k1_pubkey paramMyPublicKey,uint8_t* secKey,uint8_t* digest, 
    uint8_t* signatureComp, uint8_t* signatureDer);

secp256k1_pubkey GenerateAndVerifyPubKey(secp256k1_context *paramMyContext, uint8_t* secKey, uint8_t* pubKeyComp,
    uint8_t* pubKeyUncomp);