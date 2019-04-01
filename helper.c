/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "helper.h"



uint8_t *privKeyStringToHex(const char *stringToConvert) 
{
    uint8_t *answer = malloc(65 / 3);
    uint8_t *p;
    for (p = answer; *stringToConvert; p++)
    {
        *p = strtoul(stringToConvert, (char**)&stringToConvert, 16);
        stringToConvert++;
    }
    return answer;
}

uint8_t *compPubKeyStringToHex(const char *stringToConvert) 
{
    uint8_t *answer = malloc(67 / 3);
    uint8_t *p;
    for (p = answer; *stringToConvert; p++)
    {
        *p = strtoul(stringToConvert, (char**)&stringToConvert, 16);
        stringToConvert++;
    }
    return answer;
}


//insert spaces between each hex number in string (passed string must be length 64)
char* privKeyInsertSpaces(const char *s)
{
    char *returnString = malloc(sizeof(char)*97);
    int paramStringIndex = 0;
    
    //iterate over new array copying the passed array and adding
    //a space after every 2 chars
    for (int i = 0; i < 97; i++)
    {
        if (i == 96)
        {
            returnString[i] = '\0';
        }
        else if (i%3 == 0)
        {
            returnString[i] = ' ';
        }
        else
        {
            returnString[i] = s[paramStringIndex];
            paramStringIndex++;
        }
    }
    return returnString;
}

//insert spaces between each hex number in string (passed string must be length 64)
char* compPubKeyInsertSpaces(const char *s)
{
    char *returnString = malloc(sizeof(char)*100);
    int paramStringIndex = 0;
    
    //iterate over new array copying the passed array and adding
    //a space after every 2 chars
    for (int i = 0; i < 100; i++)
    {
        if (i == 99)
        {
            returnString[i] = '\0';
        }
        else if (i%3 == 0)
        {
            returnString[i] = ' ';
        }
        else
        {
            returnString[i] = s[paramStringIndex];
            paramStringIndex++;
        }
    }
    return returnString;
}


void printValues(uint8_t* secKey, uint8_t* pubKeyComp, uint8_t* pubKeyUncomp, uint8_t* digest, uint8_t* signatureComp, uint8_t* signatureDer)
{
    //print the private key
    printf("Private key: \n");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", secKey[i]);
    }
    printf("\n\n");

    //print the corresponding public key (compressed)
    printf("Public key (compressed): \n");
    for (int i = 0; i < 33; i++)
    {
        printf("%02x", pubKeyComp[i]);
    }
    printf("\n\n");

    //print the corresponding public key (uncompressed)
    printf("Public key (uncompressed): \n");
    for (int i = 0; i < 65; i++)
    {
        printf("%02x", pubKeyUncomp[i]);
    }
    printf("\n\n");

    //print the message hash
    printf("Message hash: \n");
    for (int i = 0; i < 32; i++)
    {
        //make sure all outputted hexes have 2 digits
        printf("%02x", digest[i]);
    }
    printf("\n\n");

    //print signature in hex
    printf("Signature (compact): \n");
    for (int i = 0; i < 64; i++)
    {
        printf("%02x", signatureComp[i]);
    }
    printf("\n\n");

    //print signature in hex
    printf("Signature (DER encoded): \n");
    for (int i = 0; i < 72; i++)
    {
        printf("%02x", signatureDer[i]);
    }
    printf("\n\n");
}


long getFileLength(FILE *paramFilePointer)
{
    long fileLength;
    
    fseek(paramFilePointer, 0, SEEK_END);
    fileLength = ftell(paramFilePointer);
    rewind(paramFilePointer);
    return fileLength;
}


int cutStringAndReturnLength(char *paramStringToCut, int paramBeginningIndex, int paramLengthToCut)
{
   int stringLength = strlen(paramStringToCut);

   if (paramLengthToCut < 0) paramLengthToCut = stringLength - paramBeginningIndex;
   if (paramBeginningIndex + paramLengthToCut > stringLength) paramLengthToCut = stringLength - paramBeginningIndex;
   memmove(paramStringToCut + paramBeginningIndex, paramStringToCut + paramBeginningIndex + paramLengthToCut, stringLength - paramLengthToCut + 1);

   return paramLengthToCut;
}