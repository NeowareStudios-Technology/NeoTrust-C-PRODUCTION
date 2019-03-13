/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "digest.h"

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
                GenerateDigestFromString(fileContents, fileLength, paramFileDigests[*paramworkingFileIndex]);

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

void GenerateDigestFromString(char *paramFileContents, long paramFileLength, uint8_t *paramFileDigest)
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
