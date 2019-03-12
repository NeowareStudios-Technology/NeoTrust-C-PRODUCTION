/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <assert.h>
#include <time.h>

#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"
#include "include/testrand_impl.h"
#include "helper.h"

//helper function for testSignEcdsa()
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


/*
long readFileIntoByteArrayAndReturnLength(int paramFileLength, char *paramFileContents)
{
    FILE *filePointer;
    long fileLength;

    filePointer = fopen(paramFileName, "r");  // Open the file in binary mode
    fseek(filePointer, 0, SEEK_END);          // Jump to the end of the file
    fileLength = ftell(filePointer);             // Get the current byte offset in the file
    rewind(filePointer);                      // Jump back to the beginning of the file

    paramFileContents = (char *)malloc((fileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(paramFileContents, paramFileLength, 1, filePointer); // Read in the entire file
    fclose(filePointer); // Close the file

    printf("\ntesting file content string inside readFile function:");
    for (int i = 0; i < fileLength; i++)
    {
        printf("%c", paramFileContents[i]);
    }
    printf("\n");

    return fileLength;
}
*/

long GetFileLength(char* paramFileName, FILE *paramFilePointer)
{
    fseek(paramFilePointer, 0, SEEK_END);
    fileLength = ftell(paramFilePointer);
    rewind(paramFilePointer);
    return fileLength;
}