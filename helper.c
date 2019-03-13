/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "helper.h"


//helper function for calculating size of string
size_t strlen(const char *str)
{
    const char *s;
    for (s = str; *s; ++s);
    return(s - str);
}


//helper function to get hex from string char
static unsigned char gethex(const char *s, char **endptr) {
 assert(s);
 assert(*s);
 return strtoul(s, endptr, 16);
}

//helper function to convert from string to unsigned char array of hex
unsigned char *convert(const char *s, int *length) 
{
    unsigned char *answer = malloc((strlen(s) + 1) / 3);
    unsigned char *p;
    for (p = answer; *s; p++)
    {
        *p = gethex(s, (char **)&s);
        s++;
    }
    *length = p - answer;
    return answer;
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

//prints the secret key, public key, digest, and signature
void printValues(unsigned char* secKey, unsigned char* pubKeyComp, unsigned char* pubKeyUncomp, unsigned char* digest, unsigned char* signatureComp, unsigned char* signatureDer)
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
           for (i=0; i<root; i++)
           {
               if (i%2 == 0 || i == 0)
                {
                    
                }
               else
                   printf(" ");

           }
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