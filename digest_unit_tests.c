/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 3/18/19
 * Copywrite NeoWare 2019
 * *********************************/


#include<time.h>
#include "digest.h"

#define NUM_TESTS 5
#define TEST_DIR_NAME "testdir"


//converts each file in the "testdir" directory to sha256 digests and compares to known correct values
//-if values match, test passes
int GenerateDigestFromString_test()
{
    long fileLength = 0;
    for (int i=0; i<7; i++)
    {
        char path[100];
        char *fileContents;
        uint8_t fileDigest[33];
        char expectedDigest[65];
        char actualDigest[65];
        FILE* filePointer;
        FILE* testHexFilePointer;

        //hash and check all 7 test files
        switch(i)
        {
            case 0:
                strcpy(path,"testdir/AndroidResolverDependencies.xml");
                strcpy(expectedDigest, "e6c34570307f293125868dd1706a5bbcd8ab59ebd830cc7c5c7095e1679dbab4");
                break;
            case 1:
                strcpy(path,"testdir/subdir1/DeleteJourney-panel.prefab");
                strcpy(expectedDigest, "b0c9caa2f431c728737e4d28531fcfbf855b55acc4f2379446a091833bc347b8");
                break;
            case 2:
                strcpy(path,"testdir/subdir1/innersubdir/LightShaft.meta");
                strcpy(expectedDigest, "1d746d0bd05b3e9d15334da44c22b1413f798b36f9aa11878aec30a16b505228");
                break;
            case 3:
                strcpy(path,"testdir/subdir2/longTextFile.txt");
                strcpy(expectedDigest, "7e5a944b97321914fcfbe17746f3b7128afd82b92b2e3503958e0a5caa3f53fd");
                break;
            case 4:
                strcpy(path,"testdir/subdir1/Bugsnag.dll");
                strcpy(expectedDigest, "5d5e8e8b2c717d2b555b81558306c5800d47b9f76bc27f7f6d258e37d0ac40d2");
                break;
            case 5:
                strcpy(path,"testdir/DockerCli.pdb");
                strcpy(expectedDigest, "1175e429924aec001aab30febb1db3fe047cd6584605569a428091807258315d");
                break;
            case 6:
                strcpy(path,"testdir/subdir1/innersubdir/InstallerCli.exe");
                strcpy(expectedDigest, "a3cf159bf3eeaf0d9e600985d55b43127a4f1b07cfaa000cf50a85a746b38f90");
                break;
        }

        //read contents of file into string
        filePointer = fopen(path, "r");
        if (!filePointer)
            printf("(CreateDigestsAndMetaInfEntries) %s file coud not be opened to read",path);
        fileLength = getFileLength(filePointer);
        fileContents = (char *)malloc((fileLength+1)*sizeof(char)); // Enough memory for file + \0
        fread(fileContents, fileLength, 1, filePointer); // Read in the entire file
        fclose(filePointer); // Close the file*/

        GenerateDigestFromString(fileContents, fileLength, fileDigest);

        //print hex digest uint8_t into test file
        testHexFilePointer = fopen("testHexFile", "a+");
        for (int i = 0; i < 32; i++)
        {
            fprintf(testHexFilePointer, "%02x", fileDigest[i]);
        }
        rewind(testHexFilePointer);

        //convert contents of hex digest file to string
        fgets(actualDigest, 65, (FILE*)testHexFilePointer);

        remove("testHexFile");

        //if generated digest does not match the expected digest, test fails
        if (strcmp(actualDigest, expectedDigest) != 0)
        {
            printf("1) GenerateDigestFromString_test FAILED\n");
            return 1;
        }

    }

    printf("1) GenerateDigestFromString_test passed\n");
    return 0;
}


//creates a sample manifest file with header and ensures the content matches the expected content
//-if header matches expected content, test passes
int CreateBaseManifestFile_test()
{
    FILE *manifestFilePointer;
    char dirName[] = TEST_DIR_NAME;
    uint8_t pubKeyPlaceholder[] = "000000000000000000000000000000000";
    char expectedManifestContents[] = "Manifest-Version: 0.1\nCreated-By: NeoPak (neopak 0.1 Beta)\nPublic Key: 303030303030303030303030303030303030303030303030303030303030303030\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.";
    long manifestFileLength;
    char *actualManifestContents;
    char *metaInfDirPath = malloc(256);
    char *manifestFilePath = malloc(256);
    char *manifestFileName = "manifest.mf";

    strcpy(metaInfDirPath, dirName);
    strcat(metaInfDirPath, "/META-INF");
    mkdir(metaInfDirPath, 0700);

    strcpy(manifestFilePath, dirName);
    strcat(manifestFilePath, "/META-INF/");
    strcat(manifestFilePath, manifestFileName);
    
    //create base manifest file
    manifestFilePointer = CreateBaseManifestFile(metaInfDirPath, manifestFileName, pubKeyPlaceholder);

     //read contents of base manifest file into string
    if (!manifestFilePointer)
        printf("(CreateDigestsAndMetaInfEntries_test) testdir/manifest file coud not be opened to read");
    manifestFileLength = getFileLength(manifestFilePointer);
    actualManifestContents = (char *)malloc((manifestFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(actualManifestContents, manifestFileLength, 1, manifestFilePointer); // Read in the entire file
    actualManifestContents[manifestFileLength] = '\0';
    fclose(manifestFilePointer); // Close the file

    remove(manifestFilePath);
    rmdir(metaInfDirPath);

    //compare contents of created base manifest file and expected contents, if they don't match the test fails
    if (strcmp(expectedManifestContents, actualManifestContents)!= 0)
    {
        printf("2) CreateBaseManifestFile_test FAILED\n");
        free(actualManifestContents);
        free(metaInfDirPath);
        free(manifestFilePath);
        return 1;
    }

    free(actualManifestContents);
    free(metaInfDirPath);
    free(manifestFilePath);

    printf("2) CreateBaseManifestFile_test passed\n");
    
    return 0;
}


//creates a sample signature file with header and ensures the content matches the expected content
//-if header matches expected content, test passes
int CreateBaseSignatureFile_test()
{
    FILE *signatureFilePointer;
    char dirName[] = TEST_DIR_NAME;
    char expectedSignatureContents[] = "";
    long signatureFileLength;
    char *actualSignatureContents;
    char *metaInfDirPath = malloc(256);
    char *signatureFilePath = malloc(256);

    strcpy(metaInfDirPath, dirName);
    strcat(metaInfDirPath, "/META-INF");
    mkdir(metaInfDirPath, 0700);

    strcpy(signatureFilePath, dirName);
    strcat(signatureFilePath, "/META-INF/tempSignature");
    
    //create base signature file
    signatureFilePointer = CreateBaseSignatureFile(metaInfDirPath);

     //read contents of base signature file into string
    if (!signatureFilePointer)
        printf("(SaveFileNameAndDigestToSignature) tesfiles/signature file coud not be opened to read");
    signatureFileLength = getFileLength(signatureFilePointer);
    actualSignatureContents = (char *)malloc((signatureFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(actualSignatureContents, signatureFileLength, 1, signatureFilePointer); // Read in the entire file
    actualSignatureContents[signatureFileLength] = '\0';
    fclose(signatureFilePointer); // Close the file

    remove(signatureFilePath);
    rmdir(metaInfDirPath);

    //compare contents of created base signature file and expected contents, if they don't match the test fails
    if (strcmp(expectedSignatureContents, actualSignatureContents)!= 0)
    {
        printf("3) CreateBaseSignatureFile_test FAILED\n");
        free(metaInfDirPath);
        free(signatureFilePath);
        free(actualSignatureContents);
        return 1;
    }

    free(metaInfDirPath);
    free(signatureFilePath);
    free(actualSignatureContents);

    printf("3) CreateBaseSignatureFile_test passed\n");
    
    return 0;

}


//creates full manifest file using digests from files in testdir and matches file contents with expected correct content
//-if content matches, test passes
int CreateDigestsAndMetaInfEntries_test()
{
    long workingFileIndex = -1;
    char dirName[] = TEST_DIR_NAME;
    char *metaInfDirPath = malloc(256);
    char *manifestFilePath = malloc(256);
    char *signatureFilePath = malloc(256);
    char *manifestFileName = "manifest.mf";
    uint8_t pubKeyPlaceholder[] = "000000000000000000000000000000000";
    long manifestFileLength;
    long signatureFileLength;
    char *actualManifestContents;
    char *actualSignatureContents;
    FILE *manifestFilePointer;
    FILE *signatureFilePointer;
    char expectedManifestContents[] = "Manifest-Version: 0.1\nCreated-By: NeoPak (neopak 0.1 Beta)\nPublic Key: 303030303030303030303030303030303030303030303030303030303030303030\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.\n\nName: longTextFile.txt\nDigest-Algorithms: SHA256\nSHA256-Digest: 7e5a944b97321914fcfbe17746f3b7128afd82b92b2e3503958e0a5caa3f53fd\n\nName: AndroidResolverDependencies.xml\nDigest-Algorithms: SHA256\nSHA256-Digest: e6c34570307f293125868dd1706a5bbcd8ab59ebd830cc7c5c7095e1679dbab4\n\nName: Bugsnag.dll\nDigest-Algorithms: SHA256\nSHA256-Digest: 5d5e8e8b2c717d2b555b81558306c5800d47b9f76bc27f7f6d258e37d0ac40d2\n\nName: LightShaft.meta\nDigest-Algorithms: SHA256\nSHA256-Digest: 1d746d0bd05b3e9d15334da44c22b1413f798b36f9aa11878aec30a16b505228\n\nName: InstallerCli.exe\nDigest-Algorithms: SHA256\nSHA256-Digest: a3cf159bf3eeaf0d9e600985d55b43127a4f1b07cfaa000cf50a85a746b38f90\n\nName: DeleteJourney-panel.prefab\nDigest-Algorithms: SHA256\nSHA256-Digest: b0c9caa2f431c728737e4d28531fcfbf855b55acc4f2379446a091833bc347b8\n\nName: DockerCli.pdb\nDigest-Algorithms: SHA256\nSHA256-Digest: 1175e429924aec001aab30febb1db3fe047cd6584605569a428091807258315d";
    char expectedSignatureContents[] = "\n\nName: longTextFile.txt\nDigest-Algorithms: SHA256\nSHA256-Digest: 684517ade41b273930a71635ea1a1b86124e5098db59ae7d68c26e8671c2a008\n\nName: AndroidResolverDependencies.xml\nDigest-Algorithms: SHA256\nSHA256-Digest: 5443bb68fd6fdf4d67d98d8655bc7d41e5859a8caeaec85b07f688d0372b1aff\n\nName: Bugsnag.dll\nDigest-Algorithms: SHA256\nSHA256-Digest: b931130e7fb9e5207d948d4fd2353fbc07839c71228cacdfb876dfd1ec247d75\n\nName: LightShaft.meta\nDigest-Algorithms: SHA256\nSHA256-Digest: d85c36bd5151da5870f97e6c7d044b11eb009e6a9a4dac1521d5f39a64945bdd\n\nName: InstallerCli.exe\nDigest-Algorithms: SHA256\nSHA256-Digest: 8869e3282d553d4a7cddf60dbcf118b4562ca8d983fea69148b2de0e6b390ca9\n\nName: DeleteJourney-panel.prefab\nDigest-Algorithms: SHA256\nSHA256-Digest: 7439c2296199c9802f67a474b605e31408e7f36dcddb60a7a130e0fa3242487f\n\nName: DockerCli.pdb\nDigest-Algorithms: SHA256\nSHA256-Digest: c5216937f4c6e815561cd3492c310f0a5760d12d1b287591d6cecb6eb71f5d5a";
    
    strcpy(metaInfDirPath, dirName);
    strcat(metaInfDirPath, "/META-INF");
    mkdir(metaInfDirPath, 0700);

    strcpy(manifestFilePath, dirName);
    strcat(manifestFilePath, "/META-INF/");
    strcat(manifestFilePath, manifestFileName);

    strcpy(signatureFilePath, dirName);
    strcat(signatureFilePath, "/META-INF/tempSignature");
    
    
    manifestFilePointer = CreateBaseManifestFile(metaInfDirPath, manifestFileName, pubKeyPlaceholder);
    signatureFilePointer = CreateBaseSignatureFile(metaInfDirPath);

    
    CreateDigestsAndMetaInfEntries(dirName, &workingFileIndex, manifestFilePointer, signatureFilePointer); 
    
    rewind(manifestFilePointer);
    rewind(signatureFilePointer);

    //read contents of manifest file into string
    manifestFilePointer = fopen(manifestFilePath, "r");
    if (!manifestFilePointer)
        printf("(CreateDigestsAndMetaInfEntries) testdir/manifest file coud not be opened to read");

    
    manifestFileLength = getFileLength(manifestFilePointer);
    actualManifestContents = (char *)malloc((manifestFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(actualManifestContents, manifestFileLength, 1, manifestFilePointer); // Read in the entire file
    actualManifestContents[manifestFileLength] = '\0';
    fclose(manifestFilePointer); // Close the file

    //read contents of signature file into string
    signatureFilePointer = fopen(signatureFilePath, "r");
    if (!signatureFilePointer)
        printf("(CreateDigestsAndMetaInfEntries) testdir/tempSignature file coud not be opened to read");
    signatureFileLength = getFileLength(signatureFilePointer);
    actualSignatureContents = (char *)malloc((signatureFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(actualSignatureContents, signatureFileLength, 1, signatureFilePointer); // Read in the entire file
    actualSignatureContents[signatureFileLength] = '\0';
    fclose(signatureFilePointer); // Close the file

    remove(manifestFilePath);
    remove(signatureFilePath);
    rmdir(metaInfDirPath);

    //uncomment to print results for this test
    //printf("\n\nEXPECTED MAN\n%s\n\n", expectedManifestContents);
    //printf("\n\nACTUAL MAN\n%s\n\n", actualManifestContents);

    //uncomment to print results for this test
    //printf("\n\nEXPECTED SIG\n%s\n\n", expectedSignatureContents);
    //printf("\n\nACTUAL SIG\n%s\n\n", actualSignatureContents);

    if (strcmp(expectedManifestContents, actualManifestContents) != 0 && strcmp(expectedSignatureContents, actualSignatureContents) != 0)
    {
        printf("4) CreateDigestsAndMetaInfEntries_test FAILED\n");
        free(metaInfDirPath);
        free(manifestFilePath);
        free(signatureFilePath);
        free(actualManifestContents);
        return 1;
    }

    free(metaInfDirPath);
    free(manifestFilePath);
    free(signatureFilePath);
    free(actualManifestContents);

    printf("4) CreateDigestsAndMetaInfEntries_test passed\n");
    
    return 0;
}

int GenerateFullManifestDigestAndSaveInSigFile_test()
{
    long workingFileIndex = -1;
    char dirName[] = TEST_DIR_NAME;
    char *metaInfDirPath = malloc(256);
    char *manifestFilePath = malloc(256);
    char *signatureFilePath = malloc(256);
    char *manifestFileName = "manifest.mf";
    uint8_t pubKeyPlaceholder[] = "000000000000000000000000000000000";
    long finalSignatureFileLength;
    char *actualFinalSignatureContents;
    FILE *manifestFilePointer;
    FILE *signatureFilePointer;
    FILE *finalSignatureFilePointer;
    char expectedFinalSignatureContents[] = "Signature-Version: 0.1\nCreated-By: NeoPak (neopak 0.1 Beta)\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.\nDigest-Algorithms: SHA256\nSHA256-Digest: a9908b7dc79864e76fb595b69747a753259c96194f05c33332e0ac22befa42a5\n\nName: longTextFile.txt\nDigest-Algorithms: SHA256\nSHA256-Digest: 41cbd8ff2268204740257b7ac10c95a989fee3641551f6ba9d35fab269974a51\n\nName: AndroidResolverDependencies.xml\nDigest-Algorithms: SHA256\nSHA256-Digest: 6ecbb2c5471382acefd9cece74d75c85af157210ecb97a75d9ad4f67742b6924\n\nName: Bugsnag.dll\nDigest-Algorithms: SHA256\nSHA256-Digest: 273c9ce159af908b67fb8daa7a0bdf9daf30f998ca3ee3d08aa20c3991f387a3\n\nName: LightShaft.meta\nDigest-Algorithms: SHA256\nSHA256-Digest: eca397f4b68ce39aaa8248360aa227f8e4cc3943a1d0fe9cd9a083216f787aca\n\nName: InstallerCli.exe\nDigest-Algorithms: SHA256\nSHA256-Digest: b79bbe11741a27a8c93b55182352cad8cadc32dcc40bc8492ee092f750e943c1\n\nName: DeleteJourney-panel.prefab\nDigest-Algorithms: SHA256\nSHA256-Digest: 2b1dbba1f347f9a975ee6b2054a60022d5a501d76cd5b0d614b5aebffe7d94bc\n\nName: DockerCli.pdb\nDigest-Algorithms: SHA256\nSHA256-Digest: 15a678275e31d35482dc3afd770e433fb9790756d136921a5a7d27dcc7c81a6d";
    
    strcpy(metaInfDirPath, dirName);
    strcat(metaInfDirPath, "/META-INF");
    mkdir(metaInfDirPath, 0700);

    strcpy(manifestFilePath, dirName);
    strcat(manifestFilePath, "/META-INF/");
    strcat(manifestFilePath, manifestFileName);

    strcpy(signatureFilePath, dirName);
    strcat(signatureFilePath, "/META-INF/neopak.sf");

    manifestFilePointer = CreateBaseManifestFile(metaInfDirPath, manifestFileName, pubKeyPlaceholder);
    signatureFilePointer = CreateBaseSignatureFile(metaInfDirPath);
    CreateDigestsAndMetaInfEntries(dirName, &workingFileIndex, manifestFilePointer, signatureFilePointer); 

    finalSignatureFilePointer = GenerateFullManifestDigestAndSaveInSigFile(metaInfDirPath, manifestFilePointer, signatureFilePointer);

    //read contents of signature file into string
    if (!finalSignatureFilePointer)
        printf("(GenerateFullManifestDigestAndSaveInSigFile_test) testdir/signature file coud not be opened to read");
    finalSignatureFileLength = getFileLength(finalSignatureFilePointer);
    actualFinalSignatureContents = (char *)malloc((finalSignatureFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(actualFinalSignatureContents, finalSignatureFileLength, 1, finalSignatureFilePointer); // Read in the entire file
    actualFinalSignatureContents[finalSignatureFileLength] = '\0';
    fclose(signatureFilePointer); // Close the file

    //uncomment to print results for this test
    //printf("\n\nEXPECTED\n%s\n\n", expectedFinalSignatureContents);
    //printf("\n\nACTUAL\n%s\n\n", actualFinalSignatureContents);

    remove(manifestFilePath);
    remove(signatureFilePath);
    rmdir(metaInfDirPath);

    if (strcmp(expectedFinalSignatureContents, actualFinalSignatureContents) != 0)
    {
        printf("5) GenerateFullManifestDigestAndSaveInSigFile_test FAILED\n");
        free(metaInfDirPath);
        free(manifestFilePath);
        free(signatureFilePath);
        free(actualFinalSignatureContents);
        return 1;
    }

    free(metaInfDirPath);
    free(manifestFilePath);
    free(signatureFilePath);
    free(actualFinalSignatureContents);

    printf("5) GenerateFullManifestDigestAndSaveInSigFile_test passed\n");
    
    return 0;
}


void printTestStatuses(int paramTestStatuses[NUM_TESTS])
{
    for (int i = 0; i < NUM_TESTS; i++)
    {
        printf("%d", paramTestStatuses[i]);
    }
    printf("\n");
    printf("\n");
}


void printHeader()
{
    printf("\n***** Unit Tests: digest.c *****\n");
}


int main()
{
    int testStatuses[NUM_TESTS];
    srand(time(0));

    printHeader();

    testStatuses[0] = GenerateDigestFromString_test();
    testStatuses[1] = CreateBaseManifestFile_test();
    testStatuses[2] = CreateBaseSignatureFile_test();
    testStatuses[3] = CreateDigestsAndMetaInfEntries_test();
    testStatuses[4] = GenerateFullManifestDigestAndSaveInSigFile_test();

    printTestStatuses(testStatuses);

    return 0;
}