/************************************
 * Project: NeoTrust
 * Author: David Lee Ramirez
 * Date: 3/28/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "sign.h"


void GetSigObjectFromSigBlockFile(char *paramMetaInfDirPath, secp256k1_ecdsa_signature *paramSigObject, secp256k1_context *paramContext);

void GetPubKeyObjectFromManifestFile(char *metaInfDirPath, secp256k1_pubkey *paramPubKeyObject, uint8_t *paramSerializedPubKeyCompressed, secp256k1_context *paramContext);