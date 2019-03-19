#include "digest.h"
#define NUM_REPEATS 100
#define NUM_TESTS 1

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
                strcpy(path,"testfiles/AndroidResolverDependencies.xml");
                strcpy(expectedDigest, "e6c34570307f293125868dd1706a5bbcd8ab59ebd830cc7c5c7095e1679dbab4");
                break;
            case 1:
                strcpy(path,"testfiles/DeleteJourney-panel.prefab");
                strcpy(expectedDigest, "b0c9caa2f431c728737e4d28531fcfbf855b55acc4f2379446a091833bc347b8");
                break;
            case 2:
                strcpy(path,"testfiles/LightShaft.meta");
                strcpy(expectedDigest, "1d746d0bd05b3e9d15334da44c22b1413f798b36f9aa11878aec30a16b505228");
                break;
            case 3:
                strcpy(path,"testfiles/longTextFile.txt");
                strcpy(expectedDigest, "7e5a944b97321914fcfbe17746f3b7128afd82b92b2e3503958e0a5caa3f53fd");
                break;
            case 4:
                strcpy(path,"testfiles/Bugsnag.dll");
                strcpy(expectedDigest, "5d5e8e8b2c717d2b555b81558306c5800d47b9f76bc27f7f6d258e37d0ac40d2");
                break;
            case 5:
                strcpy(path,"testfiles/DockerCli.pdb");
                strcpy(expectedDigest, "1175e429924aec001aab30febb1db3fe047cd6584605569a428091807258315d");
                break;
            case 6:
                strcpy(path,"testfiles/InstallerCli.exe");
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

    printTestStatuses(testStatuses);

    return 0;
}