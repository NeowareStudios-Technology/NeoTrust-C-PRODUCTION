#include<time.h>
#include "digest.h"

#define NUM_REPEATS 100
#define NUM_TESTS 4
#define TEST_DIR_NAME "testdir"

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
            printf("(SaveFileNameAndDigestToManifest) %s file coud not be opened to read",path);
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

        //if generated digest does not match the expected digest, test fails
        if (strcmp(actualDigest, expectedDigest) != 0)
        {
            printf("1) GenerateDigestFromString_test FAILED\n");
            return 1;
        }

        remove("testHexFile");
    }

    printf("1) GenerateDigestFromString_test passed\n");
    return 0;
}

int CreateBaseManifestFile_test()
{
    FILE *manifestFilePointer;
    char dirName[] = TEST_DIR_NAME;
    uint8_t pubKeyPlaceholder[] = "00000000000000000000000000000000000000000000000000000000000000000";
    char expectedManifestContents[] = "Manifest-Version: 0.1\nCreated-By: NeoPak (neopak 0.1 Beta)\nPublic Key: 3030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.";
    long manifestFileLength;
    char *actualManifestContents;
    
    //create base manifest file
    manifestFilePointer = CreateBaseManifestFile(dirName, pubKeyPlaceholder);

     //read contents of base manifest file into string
    if (!manifestFilePointer)
        printf("(SaveFileNameAndDigestToManifest) testdir/manifest file coud not be opened to read");
    manifestFileLength = getFileLength(manifestFilePointer);
    actualManifestContents = (char *)malloc((manifestFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(actualManifestContents, manifestFileLength, 1, manifestFilePointer); // Read in the entire file
    actualManifestContents[manifestFileLength] = '\0';
    fclose(manifestFilePointer); // Close the file
    remove("testdir/manifest");

    //compare contents of created base manifest file and expected contents, if they don't match the test fails
    if (strcmp(expectedManifestContents, actualManifestContents)!= 0)
    {
        printf("2) CreateBaseManifestFile_test FAILED\n");
        return 1;
    }

    printf("2) CreateBaseManifestFile_test passed\n");

    free(actualManifestContents);
    return 0;

}

int CreateBaseSignatureFile_test()
{
    FILE *signatureFilePointer;
    char dirName[] = TEST_DIR_NAME;
    char expectedSignatureContents[] = "Signature-Version: 0.1\nCreated-By: NeoPak (neopak 0.1 Beta)\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.";
    long signatureFileLength;
    char *actualSignatureContents;
    
    //create base signature file
    signatureFilePointer = CreateBaseSignatureFile(dirName);

     //read contents of base signature file into string
    if (!signatureFilePointer)
        printf("(SaveFileNameAndDigestToSignature) tesfiles/signature file coud not be opened to read");
    signatureFileLength = getFileLength(signatureFilePointer);
    actualSignatureContents = (char *)malloc((signatureFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(actualSignatureContents, signatureFileLength, 1, signatureFilePointer); // Read in the entire file
    actualSignatureContents[signatureFileLength] = '\0';
    fclose(signatureFilePointer); // Close the file
    remove("testdir/signature");

    //compare contents of created base signature file and expected contents, if they don't match the test fails
    if (strcmp(expectedSignatureContents, actualSignatureContents)!= 0)
    {
        printf("3) CreateBaseSignatureFile_test FAILED\n");
        return 1;
    }

    printf("3) CreateBaseSignatureFile_test passed\n");

    free(actualSignatureContents);
    return 0;

}

int SaveFileNameAndDigestToManifest_test()
{
    long workingFileIndex = -1;
    char dirName[] = TEST_DIR_NAME;
    uint8_t pubKeyPlaceholder[] = "00000000000000000000000000000000000000000000000000000000000000000";
    long manifestFileLength;
    char *actualManifestContents;
    FILE *manifestFilePointer;
    char expectedManifestContents[] = "Manifest-Version: 0.1\nCreated-By: NeoPak (neopak 0.1 Beta)\nPublic Key: 3030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030\nComments: PLEASE DO NOT EDIT THIS FILE. YOU WILL BREAK IT.\n\nName: longTextFile.txt\nDigest-Algorithms: SHA256\nSHA256-Digest: 7e5a944b97321914fcfbe17746f3b7128afd82b92b2e3503958e0a5caa3f53fd\n\nName: manifest\nDigest-Algorithms: SHA256\nSHA256-Digest: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\nName: AndroidResolverDependencies.xml\nDigest-Algorithms: SHA256\nSHA256-Digest: e6c34570307f293125868dd1706a5bbcd8ab59ebd830cc7c5c7095e1679dbab4\n\nName: Bugsnag.dll\nDigest-Algorithms: SHA256\nSHA256-Digest: 5d5e8e8b2c717d2b555b81558306c5800d47b9f76bc27f7f6d258e37d0ac40d2\n\nName: LightShaft.meta\nDigest-Algorithms: SHA256\nSHA256-Digest: 1d746d0bd05b3e9d15334da44c22b1413f798b36f9aa11878aec30a16b505228\n\nName: InstallerCli.exe\nDigest-Algorithms: SHA256\nSHA256-Digest: a3cf159bf3eeaf0d9e600985d55b43127a4f1b07cfaa000cf50a85a746b38f90\n\nName: DeleteJourney-panel.prefab\nDigest-Algorithms: SHA256\nSHA256-Digest: b0c9caa2f431c728737e4d28531fcfbf855b55acc4f2379446a091833bc347b8\n\nName: DockerCli.pdb\nDigest-Algorithms: SHA256\nSHA256-Digest: 1175e429924aec001aab30febb1db3fe047cd6584605569a428091807258315d";

    manifestFilePointer = CreateBaseManifestFile(dirName,pubKeyPlaceholder);
    SaveFileNameAndDigestToManifest(dirName, &workingFileIndex, manifestFilePointer); 
    rewind(manifestFilePointer);

    //read contents of file into string
    manifestFilePointer = fopen("testdir/manifest", "r");
    if (!manifestFilePointer)
        printf("(SaveFileNameAndDigestToManifest) tesfiles/manifest file coud not be opened to read");
    manifestFileLength = getFileLength(manifestFilePointer);
    actualManifestContents = (char *)malloc((manifestFileLength+1)*sizeof(char)); // Enough memory for file + \0
    fread(actualManifestContents, manifestFileLength, 1, manifestFilePointer); // Read in the entire file
    actualManifestContents[manifestFileLength] = '\0';
    fclose(manifestFilePointer); // Close the file
    remove("testdir/manifest");

    if (strcmp(expectedManifestContents, actualManifestContents)!= 0)
    {
        printf("4) SaveFileNameAndDigestToManifest_test FAILED\n");
        return 1;
    }

    printf("4) SaveFileNameAndDigestToManifest_test passed\n");

    free(actualManifestContents);
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
    testStatuses[3] = SaveFileNameAndDigestToManifest_test();

    printTestStatuses(testStatuses);

    return 0;
}