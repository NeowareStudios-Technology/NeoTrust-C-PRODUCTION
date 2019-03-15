/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "digest.h"

void GetNameAndDigestForEachFile(char *basePath, const int root, long *paramWorkingFileIndex)
{
    int i;
    char path[1000];
    struct dirent *dp;
    DIR *dir = opendir(basePath);
    long fileLength;
    uint8_t fileDigest[32];

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
                *paramWorkingFileIndex= *paramWorkingFileIndex + 1;
                FILE* filePointer = fopen(path, "r");
                if (!filePointer)
                    printf("(GetNameAndDigestForEachFile) %s file coud not be opened to read",path);
                fileLength = getFileLength(path, filePointer);
                char *fileContents = (char *)malloc((fileLength+1)*sizeof(char)); // Enough memory for file + \0
                fread(fileContents, fileLength, 1, filePointer); // Read in the entire file
                fclose(filePointer); // Close the file
/*
                printf("\n");
                printf("(GetNameAndDigestForEachFile) file contents: ");
                for (int i = 0; i<fileLength; i++)
                {
                    printf("%c", fileContents[i]);
                }
                printf("\n");
                printf("(GetNameAndDigestForEachFile) file count: %d \n", *paramWorkingFileIndex);
*/
                printf("(GetNameAndDigestForEachFile) file : %s\n", dp->d_name);

                GenerateDigestFromString(fileContents, fileLength, fileDigest);

                printf("(GetNameAndDigestForEachFile) file digest: \n");
                for (int i = 0; i<32; i++)
                {
                    printf("%02x", fileDigest[i]);
                }
                printf("\n");
                free(fileContents);
            }
           GetNameAndDigestForEachFile(path, root + 2, paramWorkingFileIndex);    
        }
    }
    closedir(dir);
}

void GenerateDigestFromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest)
{
    USHAContext shaContext;
    uint8_t messageDigest[32];
    int errorCode;

    errorCode = USHAReset(&shaContext, SHA256);
    if (errorCode == 0)
        printf("(GenerateDigestFromString) SHA context reset successful\n");
    else
        printf("(GenerateDigestFromString) SHA context reset failed\n");
    

    errorCode = USHAInput(&shaContext, (const uint8_t *) paramFileContents, paramFileLength);
    if (errorCode == 0)
        printf("(GenerateDigestFromString) SHA input successful\n");
    else
        printf("(GenerateDigestFromString) SHA input failed\n");

    errorCode = USHAResult(&shaContext, paramFileDigest);
    if (errorCode == 0)
        printf("(GenerateDigestFromString) SHA result successful\n");
    else
        printf("(GenerateDigestFromString) SHA result failed\n");
}

FILE* CreateBaseManifestFile(char *paramTargetDirectoryName)
{
    char *manifestFilePath = strcat(paramTargetDirectoryName, "/manifest");
    FILE *manifestFilePointer = fopen(manifestFilePath, "a+");
    if (!manifestFilePointer)
        printf("error: file cant be opened\n");

    fputs("Manifest-Version: 0.1\nCreated-By: NeoPak (neopak 0.1 Beta)\nPublic Key: ", manifestFilePointer);

    return manifestFilePointer;
}