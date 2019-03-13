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

void CompleteTestSigProcess();
void CompleteSigProcess(char *paramSecKey, char *paramFileName);
void VerifyParamsAndSignMessageWithEcdsa(secp256k1_pubkey paramMyPublicKey,unsigned char* secKey,unsigned char* digest, unsigned char* signatureComp, unsigned char* signatureDer);
void random_scalar_order_test_new(secp256k1_scalar *num);
secp256k1_pubkey GenerateAndVerifyPubKey(secp256k1_context *paramMyContext, unsigned char* secKey, unsigned char* pubKeyComp, unsigned char* pubKeyUncomp);