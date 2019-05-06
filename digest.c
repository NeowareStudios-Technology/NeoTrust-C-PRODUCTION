/************************************
 * Project: NeoTrust
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "digest.h"


//recursive function
void CreateDigestsAndMetaInfEntries(char *paramBasePath, FILE* paramManifestFilePointer, FILE* paramSigFilePointer)
{
    char path[1024];
    struct dirent *dp;
    DIR *dir = opendir(paramBasePath);
    long fileLength;
    uint8_t fileDigest[32];
    uint8_t manifestEntryDigest[32];

    //iterate over each subdirectory and file in the target directory
    if (!dir)
        return; 
    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0 && strcmp(dp->d_name, "META-INF") != 0)
        {  
           strcpy(path, paramBasePath);
           strcat(path, "/");
           strcat(path, dp->d_name);

            //if it is a file, read file into string, create digest from string, create manifest file entry from string,
            //and create signature file entry from manifest file entry
            if (dp->d_type != DT_DIR)
            {
                //read target file contents
                FILE* filePointer = fopen(path, "r");
                if (!filePointer)
                    printf("(CreateDigestsAndMetaInfEntries) %s file coud not be opened to read",path);
                fileLength = getFileLength(filePointer);
                char *fileContents = (char *)malloc((fileLength+1)*sizeof(char)); // Enough memory for file + \0
                fread(fileContents, fileLength, 1, filePointer); // Read in the entire file
                fclose(filePointer); // Close the file

                GenerateSha256DigestFromString(fileContents, fileLength, fileDigest);
                CreateManifestFileEntry(paramManifestFilePointer, dp->d_name, fileDigest);
                CreateTempSigFileEntry(paramSigFilePointer, dp->d_name, fileDigest);
                
                free(fileContents);
            }
            //recursive call
            CreateDigestsAndMetaInfEntries(path, paramManifestFilePointer, paramSigFilePointer);    
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


//Temp sig file will hold all signature file entries EXCEPT for the header and full manifest file hash.
//Full manifest file hash can only be created after iterating through all target directory files.
void CreateTempSigFileEntry(FILE* paramTempSigFilePointer, char *paramFileName, uint8_t *paramFileDigest)
{
    //temp digest file used to convert target file digest (uint8_t array) to string
    FILE *tempDigestFilePointer;
    char manifestFileEntry[1024];
    char fileDigestChars[65]; 
    uint8_t manifestEntryDigest[32];
    size_t manifestEntryLength;

    //create and open temp file for reading and writing
    tempDigestFilePointer = fopen("tempFile", "a+");
    if (!tempDigestFilePointer)
    {
        printf("\nerror: tempFile could not be opened\n");
        exit(1);
    }

    //print the target file digest as hex into temp file
    for (int i = 0; i < 32; i++)
        fprintf(tempDigestFilePointer,"%02x", paramFileDigest[i]);
    
    rewind(tempDigestFilePointer);
    
    //read target file digest in temp file as string
    fgets(fileDigestChars, 65, tempDigestFilePointer);
    fclose(tempDigestFilePointer);
    remove("tempFile");

    //place manifest entry text (including target file digest) into string
    strcpy(manifestFileEntry, "Name: ");
    strcat(manifestFileEntry, paramFileName);
    strcat(manifestFileEntry, "\n");
    strcat(manifestFileEntry, "Digest-Algorithms: SHA256\n");
    strcat(manifestFileEntry, "SHA256-Digest: ");
    strcat(manifestFileEntry, fileDigestChars);
    strcat(manifestFileEntry, "\0");
    manifestEntryLength = strlen(manifestFileEntry);

    //generate the digest of the manifest file entry (for use in signature file entry)
    GenerateSha256DigestFromString(manifestFileEntry, manifestEntryLength, manifestEntryDigest);

    //write signature file entry to signature file (signature file entry includes manifest entry digest)
    fputs("\n\nName: ", paramTempSigFilePointer);
    fputs(paramFileName, paramTempSigFilePointer);
    fputs("\nDigest-Algorithms: SHA256\n", paramTempSigFilePointer);
    fputs("SHA256-Digest: ", paramTempSigFilePointer);
    for (int i = 0; i < 32; i++)
    {
        fprintf(paramTempSigFilePointer, "%02x", manifestEntryDigest[i]);
    }
}


FILE *GenerateFullManifestDigestAndSaveInSigFile(char *paramMetaInfDirPath, char *paramFileName, FILE *paramManifestFilePointer, FILE *paramSigFilePointer)
{
    char *manifestFileContents;
    char *sigFileContents;
    long manifestFileLength;
    long sigFileLength;
    uint8_t manifestFileDigest[32];
    char sigFilePath[256];
    char tempSigFilePath[256];
    FILE *finalSigFilePointer;

    //read manifest file contents
    rewind(paramManifestFilePointer);
    if (!paramManifestFilePointer)
        printf("Manifest file could not be opened to read");
    manifestFileLength = getFileLength(paramManifestFilePointer);
    manifestFileContents = (char *)malloc((manifestFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(manifestFileContents, manifestFileLength, 1, paramManifestFilePointer); // Read in the entire file

    //read temporary signature file contents
    rewind(paramSigFilePointer);
    if (!paramSigFilePointer)
        printf("Sig file coud not be opened to read");
    sigFileLength = getFileLength(paramSigFilePointer);
    sigFileContents = (char *)malloc((sigFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(sigFileContents, sigFileLength, 1, paramSigFilePointer); // Read in the entire file

    //generate digest of entire manifest file
    GenerateSha256DigestFromString(manifestFileContents, manifestFileLength, manifestFileDigest);

    //create and open final signature file for writing
    strcpy(sigFilePath, paramMetaInfDirPath);
    strcat(sigFilePath, "/");
    strcat(sigFilePath, paramFileName);
    finalSigFilePointer = fopen(sigFilePath, "w+");
    if (!finalSigFilePointer)
        printf("\n error could not open final sig file\n");
    //write header to final signature file
    fputs("Sig-Version: 0.1\nCreated-By: NeoTrust (neotrust 0.1 Beta)\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.\nDigest-Algorithms: SHA256\nSHA256-Digest: ", finalSigFilePointer);
    //write full manifest file digest to signature file
    for (int i = 0; i < 32; i++)
        fprintf(finalSigFilePointer, "%02x", manifestFileDigest[i]);
    //write all contents of temporary signature file (ie. all entries except for header and full manifest hash) to final signature file
    fputs(sigFileContents, finalSigFilePointer);

    strcpy(tempSigFilePath, paramMetaInfDirPath);
    strcat(tempSigFilePath, "/tempSig");
    remove(tempSigFilePath);
    
    free(manifestFileContents);
    free(sigFileContents);

    return(finalSigFilePointer);
}


void GenerateSha256DigestFromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest)
{
    USHAContext shaContext;
    uint8_t messageDigest[32];
    int errorCode;

    errorCode = USHAReset(&shaContext, SHA256);
    if (errorCode != 0)
    {
        printf("(GenerateSha256DigestFromString) SHA context reset failed\n");
        exit(1);
    }

    errorCode = USHAInput(&shaContext, (const uint8_t *) paramFileContents, paramFileLength);
    if (errorCode != 0)
    {
        printf("(GenerateSha256DigestFromString) SHA input failed\n");
        exit(1);
    }

    errorCode = USHAResult(&shaContext, paramFileDigest);
    if (errorCode != 0)
    {
        printf("(GenerateSha256DigestFromString) SHA result failed\n");
        exit(1);
    }
}


FILE* CreateBaseManifestFile(char *paramMetaInfPath, char *paramFileName, uint8_t *paramPublicKey)
{
    char manifestFilePath[1024];
    strcpy(manifestFilePath, paramMetaInfPath);
    strcat(manifestFilePath, "/");
    strcat(manifestFilePath, paramFileName);
    FILE *manifestFilePointer = fopen(manifestFilePath, "a+");
    
    if (!manifestFilePointer)
        printf("error: file cant be opened\n");

    fputs("Manifest-Version: 0.1\nCreated-By: NeoTrust (neotrust 0.1 Beta)\nPublic Key: ", manifestFilePointer);
    for (int i = 0; i < 33; i++)
        fprintf(manifestFilePointer, "%02x", paramPublicKey[i]);
    fputs("\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.", manifestFilePointer);

    return manifestFilePointer;
}


FILE* CreateBaseSigFile(char *paramMetaInfPath)
{
    char sigFilePath[1024];
    strcpy(sigFilePath, paramMetaInfPath);
    strcat(sigFilePath, "/tempSig");
    FILE *sigFilePointer = fopen(sigFilePath, "a+");
    
    if (!sigFilePointer)
        printf("error: signature file could not be created\n");

    return sigFilePointer;
}


void GenerateSigFileDigest(FILE *paramSigFilePointer, uint8_t *paramSigFileDigest)
{
    long sigFileLength;
    char *sigFileContents;

    //read signature file contents into string
    rewind(paramSigFilePointer);
    if (!paramSigFilePointer)
        printf("Sig file could not be opened to read");
    sigFileLength = getFileLength(paramSigFilePointer);
    sigFileContents = (char *)malloc((sigFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(sigFileContents, sigFileLength, 1, paramSigFilePointer); // Read in the entire file

    GenerateSha256DigestFromString(sigFileContents, sigFileLength, paramSigFileDigest);

    free(sigFileContents);
}