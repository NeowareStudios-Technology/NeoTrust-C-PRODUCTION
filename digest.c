/************************************
 * Project: NeoTrust
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "digest.h"


//recursive function
void CreateDigestsAndMetaInfEntries(char *basePath, FILE* paramManifestFilePointer, FILE* paramSignatureFilePointer)
{
    char path[1024];
    struct dirent *dp;
    DIR *dir = opendir(basePath);
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
           strcpy(path, basePath);
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
                CreateTempSigFileEntry(paramSignatureFilePointer, dp->d_name, basePath, fileDigest);
                
                free(fileContents);
            }
            //recursive call
            CreateDigestsAndMetaInfEntries(path, paramManifestFilePointer, paramSignatureFilePointer);    
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
void CreateTempSigFileEntry(FILE* paramTempSigFilePointer, char *paramFileName, char *basePath, uint8_t *paramFileDigest)
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


FILE *GenerateFullManifestDigestAndSaveInSigFile(char *paramMetaInfDirPath, char *paramFileName, FILE *paramManifestFilePointer, FILE *paramSignatureFilePointer)
{
    char *manifestFileContents;
    char *signatureFileContents;
    long manifestFileLength;
    long signatureFileLength;
    uint8_t manifestFileDigest[32];
    char signatureFilePath[256];
    char tempSignatureFilePath[256];
    FILE *finalSignatureFilePointer;

    //read manifest file contents
    rewind(paramManifestFilePointer);
    if (!paramManifestFilePointer)
        printf("Manifest file could not be opened to read");
    manifestFileLength = getFileLength(paramManifestFilePointer);
    manifestFileContents = (char *)malloc((manifestFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(manifestFileContents, manifestFileLength, 1, paramManifestFilePointer); // Read in the entire file

    //read temporary signature file contents
    rewind(paramSignatureFilePointer);
    if (!paramSignatureFilePointer)
        printf("Signature file coud not be opened to read");
    signatureFileLength = getFileLength(paramSignatureFilePointer);
    signatureFileContents = (char *)malloc((signatureFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(signatureFileContents, signatureFileLength, 1, paramSignatureFilePointer); // Read in the entire file

    //generate digest of entire manifest file
    GenerateSha256DigestFromString(manifestFileContents, manifestFileLength, manifestFileDigest);

    //create and open final signature file for writing
    strcpy(signatureFilePath, paramMetaInfDirPath);
    strcat(signatureFilePath, "/");
    strcat(signatureFilePath, paramFileName);
    finalSignatureFilePointer = fopen(signatureFilePath, "w+");
    if (!finalSignatureFilePointer)
        printf("\n error could not open final sig file\n");
    //write header to final signature file
    fputs("Signature-Version: 0.1\nCreated-By: NeoTrust (neotrust 0.1 Beta)\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.\nDigest-Algorithms: SHA256\nSHA256-Digest: ", finalSignatureFilePointer);
    //write full manifest file digest to signature file
    for (int i = 0; i < 32; i++)
        fprintf(finalSignatureFilePointer, "%02x", manifestFileDigest[i]);
    //write all contents of temporary signature file (ie. all entries except for header and full manifest hash) to final signature file
    fputs(signatureFileContents, finalSignatureFilePointer);

    strcpy(tempSignatureFilePath, paramMetaInfDirPath);
    strcat(tempSignatureFilePath, "/tempSignature");
    remove(tempSignatureFilePath);
    
    free(manifestFileContents);
    free(signatureFileContents);

    return(finalSignatureFilePointer);
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


FILE* CreateBaseSignatureFile(char *paramMetaInfPath)
{
    char signatureFilePath[1024];
    strcpy(signatureFilePath, paramMetaInfPath);
    strcat(signatureFilePath, "/tempSignature");
    FILE *signatureFilePointer = fopen(signatureFilePath, "a+");
    
    if (!signatureFilePointer)
        printf("error: signature file could not be created\n");

    return signatureFilePointer;
}


void GenerateSignatureFileDigest(FILE *paramSignatureFilePointer, uint8_t *paramSignatureFileDigest)
{
    long signatureFileLength;
    char *signatureFileContents;

    //read signature file contents into string
    rewind(paramSignatureFilePointer);
    if (!paramSignatureFilePointer)
        printf("Signature file could not be opened to read");
    signatureFileLength = getFileLength(paramSignatureFilePointer);
    signatureFileContents = (char *)malloc((signatureFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(signatureFileContents, signatureFileLength, 1, paramSignatureFilePointer); // Read in the entire file

    GenerateSha256DigestFromString(signatureFileContents, signatureFileLength, paramSignatureFileDigest);

    free(signatureFileContents);
}