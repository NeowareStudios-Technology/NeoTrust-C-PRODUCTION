/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "digest.h"

void CreateDigestsAndMetaInfEntries(char *basePath, long *paramWorkingFileIndex, FILE* paramManifestFilePointer, FILE* paramSignatureFilePointer)
{
    int i;
    char path[1000];
    struct dirent *dp;
    DIR *dir = opendir(basePath);
    long fileLength;
    uint8_t fileDigest[32];
    uint8_t manifestEntryDigest[32];

    if (!dir)
        return; 
    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0 && strcmp(dp->d_name, "META-INF") != 0)
        {  

           strcpy(path, basePath);
           strcat(path, "/");
           strcat(path, dp->d_name);

           //if it is a file, read file into string
           if (dp->d_type != DT_DIR)
            {
                *paramWorkingFileIndex= *paramWorkingFileIndex + 1;

                //read target file contents
                FILE* filePointer = fopen(path, "r");
                if (!filePointer)
                    printf("(CreateDigestsAndMetaInfEntries) %s file coud not be opened to read",path);
                fileLength = getFileLength(filePointer);
                char *fileContents = (char *)malloc((fileLength+1)*sizeof(char)); // Enough memory for file + \0
                fread(fileContents, fileLength, 1, filePointer); // Read in the entire file
                fclose(filePointer); // Close the file

                GenerateDigestFromString(fileContents, fileLength, fileDigest);

                CreateManifestFileEntry(paramManifestFilePointer, dp->d_name, fileDigest);
                CreateSignatureFileEntry(paramSignatureFilePointer, dp->d_name, fileDigest);
                
                free(fileContents);
            }
           CreateDigestsAndMetaInfEntries(path, paramWorkingFileIndex, paramManifestFilePointer, paramSignatureFilePointer);    
        }
    }
    closedir(dir);
}

void CreateManifestFileEntry(FILE* paramManifestFilePointer, char *paramFileName, uint8_t *paramFileDigest)
{
    fputs("\n\nName: ", paramManifestFilePointer);
    fputs(paramFileName, paramManifestFilePointer);
    fputs("\nDigest-Algorithms: SHA256\n", paramManifestFilePointer);
    fputs("SHA256-Digest: ", paramManifestFilePointer);

    for (int i = 0; i < 32; i++)
    {
        fprintf(paramManifestFilePointer, "%02x", paramFileDigest[i]);
    }
}

void CreateSignatureFileEntry(FILE* paramSignatureFilePointer, char *paramFileName, uint8_t *paramFileDigest)
{
    FILE *tempFilePointer;
    char *signatureFileEntry = malloc(1000);
    char *fileDigestChars = malloc(65); 
    uint8_t signatureEntryDigest[32];
    size_t signatureEntryLength;

    strcat(signatureFileEntry, "Name: ");
    strcat(signatureFileEntry, paramFileName);
    strcat(signatureFileEntry, "\nDigest-Algorithms: SHA256\n");
    strcat(signatureFileEntry, "SHA256-Digest: ");

    tempFilePointer = fopen("tempFile", "a+");
    if (!tempFilePointer)
    {
        printf("\nerror: tempFile could not be opened\n");
        exit(1);
    }

    for (int i = 0; i < 32; i++)
        fprintf(tempFilePointer,"%02x", paramFileDigest[i]);
    
    rewind(tempFilePointer);
                
    fgets(fileDigestChars, 65, tempFilePointer);
    strcat(signatureFileEntry, fileDigestChars);
    strcat(signatureFileEntry, "\0");
    signatureEntryLength = stringLength(signatureFileEntry);

    fclose(tempFilePointer);
    remove("tempFile");

    GenerateDigestFromString(signatureFileEntry, signatureEntryLength, signatureEntryDigest);

    printf("\n");
    printf("%s\n", paramFileName);
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", signatureEntryDigest[i]);
    }
    printf("\n");

    free(signatureFileEntry);
    free(fileDigestChars);

}

void GenerateDigestFromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest)
{
    USHAContext shaContext;
    uint8_t messageDigest[32];
    int errorCode;

    errorCode = USHAReset(&shaContext, SHA256);
    if (errorCode != 0)
    {
        printf("(GenerateDigestFromString) SHA context reset failed\n");
        exit(1);
    }

    errorCode = USHAInput(&shaContext, (const uint8_t *) paramFileContents, paramFileLength);
    if (errorCode != 0)
    {
        printf("(GenerateDigestFromString) SHA input failed\n");
        exit(1);
    }

    errorCode = USHAResult(&shaContext, paramFileDigest);
    if (errorCode != 0)
    {
        printf("(GenerateDigestFromString) SHA result failed\n");
        exit(1);
    }
}

FILE* CreateBaseManifestFile(char *paramMetaInfPath, uint8_t *paramPublicKey)
{
    char manifestFilePath[1000];
    strcpy(manifestFilePath, paramMetaInfPath);
    strcat(manifestFilePath, "/manifest");
    FILE *manifestFilePointer = fopen(manifestFilePath, "a+");
    
    if (!manifestFilePointer)
        printf("error: file cant be opened\n");

    fputs("Manifest-Version: 0.1\nCreated-By: NeoPak (neopak 0.1 Beta)\nPublic Key: ", manifestFilePointer);
    for (int i = 0; i < 65; i++)
        fprintf(manifestFilePointer, "%02x", paramPublicKey[i]);
    fputs("\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.", manifestFilePointer);

    return manifestFilePointer;
}

FILE* CreateBaseSignatureFile(char *paramMetaInfPath)
{
    char signatureFilePath[1000];
    strcpy(signatureFilePath, paramMetaInfPath);
    strcat(signatureFilePath, "/signature");
    FILE *signatureFilePointer = fopen(signatureFilePath, "a+");
    
    if (!signatureFilePointer)
        printf("error: file cant be opened\n");

    fputs("Signature-Version: 0.1\nCreated-By: NeoPak (neopak 0.1 Beta)\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.", signatureFilePointer);

    return signatureFilePointer;
}