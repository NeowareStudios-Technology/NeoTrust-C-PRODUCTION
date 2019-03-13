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
#include <dirent.h>

#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"
#include "include/testrand_impl.h"
#include "helper.h"
#include "./sha/sha.h"


//global
enum commands{usage, testSign, sign}command;

//function declarations
void DisplayUsageInfo();
enum commands ParseArgumentsIntoCommand(int paramArgc);
void ExecuteCommand(char **paramArgs, enum commands paramCommand);
void ComputeSha256FromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest);
void MakeDigestForEachFile(char *basePath, const int root, uint8_t paramFileDigests[9999999][32], long *paramworkingFileIndex);


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


void random_scalar_order_test_new(secp256k1_scalar *num) {
   do {
       unsigned char b32[32];
       int overflow = 0;
       secp256k1_rand256(b32);
       secp256k1_scalar_set_b32(num, b32, &overflow);
       if (overflow || secp256k1_scalar_is_zero(num)) {
           continue;
       }
       break;
   } while(1);
}

void MakeDigestForEachFile(char *basePath, const int root, uint8_t paramFileDigests[9999999][32], long *paramworkingFileIndex)
{
    int i;
    char path[1000];
    struct dirent *dp;
    DIR *dir = opendir(basePath);
    long fileLength;

    if (!dir)
        return; 
    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0)
        {  

           strcpy(path, basePath);
           strcat(path, "/");
           strcat(path, dp->d_name);

           //if it is a file, read file into string
           if (dp->d_type != DT_DIR)
            {
                *paramworkingFileIndex= *paramworkingFileIndex + 1;
                FILE* filePointer = fopen(path, "r");
                if (!filePointer)
                    printf("%s file coud not be opened to read",path);
                fileLength = getFileLength(path, filePointer);
                char *fileContents = (char *)malloc((fileLength+1)*sizeof(char)); // Enough memory for file + \0
                fread(fileContents, fileLength, 1, filePointer); // Read in the entire file
                fclose(filePointer); // Close the file

                printf("\n");
                printf("file contents: ");
                for (int i = 0; i<fileLength; i++)
                {
                    printf("%c", fileContents[i]);
                }
                printf("\n");

                printf("file count: %d", *paramworkingFileIndex);
                ComputeSha256FromString(fileContents, fileLength, paramFileDigests[*paramworkingFileIndex]);

                printf("\n");
                for (int i = 0; i<32; i++)
                {
                    printf("%02x", paramFileDigests[*paramworkingFileIndex][i]);
                }
                printf("\n");
                free(fileContents);
            }
           MakeDigestForEachFile(path, root + 2, paramFileDigests, paramworkingFileIndex);    
        }
    }
    closedir(dir);
}

void ComputeSha256FromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest)
{
    USHAContext shaContext;
    uint8_t messageDigest[32];
    int errorCode;

    errorCode = USHAReset(&shaContext, SHA256);
    if (errorCode == 0)
        printf("\nSHA context reset successful");
    else
        printf("\nSHA context reset failed");
    

    errorCode = USHAInput(&shaContext, (const uint8_t *) paramFileContents, paramFileLength);
    if (errorCode == 0)
        printf("\nSHA input successful");
    else
        printf("\nSHA input failed");

    errorCode = USHAResult(&shaContext, paramFileDigest);
    if (errorCode == 0)
        printf("\nSHA result successful");
    else
        printf("\nSHA result failed");
}


int main(int argc, char **argv)
{
    command = ParseArgumentsIntoCommand(argc);

    ExecuteCommand(argv, command);
    return 0;
}

//TEST WITH THIS:
//private key: 6f910beb039b93eba3bf95eb9ab2610855f18a7512463c78bc9ebf774535e89f