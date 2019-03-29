/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 3/28/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "sign.h"

void VerifyNeoPakSignature(char *paramTargetDir);

void GetSigObjectFromSigBlockFile(char *paramMetaInfDirPath, secp256k1_ecdsa_signature *paramSigObject, secp256k1_context *paramContext);