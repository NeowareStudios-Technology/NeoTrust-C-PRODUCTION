/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "helper.h"




uint8_t *stringToHex(const char *s, int *length) 
{
    uint8_t *answer = malloc(65 / 3);
    uint8_t *p;
    for (p = answer; *s; p++)
    {
        *p = charToHex(s, (char **)&s);
        s++;
    }
    *length = p - answer;
    return answer;
}


static uint8_t charToHex(const char *s, char **endptr) {
 assert(s);
 assert(*s);
 return strtoul(s, endptr, 16);
}


void countFilesInDirectory(char *basePath, const int root, long *count)
{
   int i;
   char path[1000];
   struct dirent *dp;
   DIR *dir = opendir(basePath);

   if (!dir)
       return;

   while ((dp = readdir(dir)) != NULL)
   {
       if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0)
       {
            if (dp->d_type != DT_DIR)
                *count = *count + 1;

            strcpy(path, basePath);
            strcat(path, "/");
            strcat(path, dp->d_name);
            countFilesInDirectory(path, root + 2, count);
       }
   }
   closedir(dir);
}


//insert spaces between each hex number in string
char* insertSpaces(const char *s)
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


long getFileLength(char* paramFileName, FILE *paramFilePointer)
{
    long fileLength;
    
    fseek(paramFilePointer, 0, SEEK_END);
    fileLength = ftell(paramFilePointer);
    rewind(paramFilePointer);
    return fileLength;
}