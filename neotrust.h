/***********************************
 * Project: NeoTrust
 * Author: David Lee Ramirez
 * Date: 4/1/19
 * Copywrite NeoWare 2019
 * *********************************/


#include <stdio.h>
#include "sign.h"
#include "verify.h"
#include "digest.h"


enum commands ParseArgumentsIntoCommand(int paramArgc);

void ExecuteCommand(char **paramArgs, enum commands paramCommand);

void DisplayUsageInfo();

void MainSign(char *paramSecKey, char *paramDirName);

void MainVerify(char *paramTargetDir);
