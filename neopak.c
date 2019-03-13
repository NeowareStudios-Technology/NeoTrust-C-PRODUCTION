/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <stdio.h>

#include "sign.h"


//global
enum commands{usage, testSign, sign}command;

//function declarations
void DisplayUsageInfo();
enum commands ParseArgumentsIntoCommand(int paramArgc);
void ExecuteCommand(char **paramArgs, enum commands paramCommand);


void DisplayUsageInfo()
{
    printf("\nNeoPak\nCopywrite NeoWare 2019\n");
    printf("Created by David Lee Ramirez 2/12/2019 \n");
    printf("Usage:\n");
    printf("./neopak                                  Show usage info\n");
    printf("./neopak test                             Sign with test priv key and message hash\n");
    printf("./neopak <privKey> <filePath>             Sign with provided priv key and file\n");
    printf("\n *Note: <privKey> must be supplied \n        as a string of hex numbers with length 64 \n");
}


enum commands ParseArgumentsIntoCommand(int paramArgc)
{
    //if no args passed, display usage info
    if (paramArgc == 1)
        return usage;
    //if only "test" is passed as arg, start test sign
    else if (paramArgc == 2)
        return testSign;
    //if private key and message hash are passed as args, start
    //production sign
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
        case testSign:
            CompleteTestSigProcess();
            break;
        case sign:
            CompleteSigProcess(paramArgs[1], paramArgs[2]);
            break;
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