/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 3/18/19
 * Copywrite NeoWare 2019
 * *********************************/

//The following tests are very basic, and should incorporate RANDOM TESTING and EDGE TESTING in the future

#include <time.h>
#include <stdio.h>
#include "helper.h"

#define NUM_TESTS 2
#define TEST_DIR_NAME "testdir"
#define NUM_FILES_TEST_DIR 4


int stringToHex_test()
{
    const char *testKey = "6f910beb039b93eba3bf95eb9ab2610855f18a7512463c78bc9ebf774535e89f";
    const char* spacedTestKey = insertSpaces(testKey);  //add spaces to string to separate hex values
    uint8_t *serializedTestKey = malloc(sizeof(uint8_t)*32);
    FILE *testStringFilePointer = fopen("testStringFile", "a+");
    FILE *testHexFilePointer = fopen("testHexFile", "a+");
    char readTestHexFile[65];
    char readTestStringFile[65];

    //convert hardcoded testKey to hex (uint8_t)
    serializedTestKey = stringToHex(spacedTestKey);

    //print original testKey string into test file
    for (int i = 0; i < 64; i++)
    {
        fprintf(testStringFilePointer, "%c", testKey[i]);
    }
    //print hex converted testKey uint8_t into a seperate test file (printed as hex)
    for (int i = 0; i < 32; i++)
    {
        fprintf(testHexFilePointer, "%02x", serializedTestKey[i]);
    }

    rewind(testStringFilePointer);
    rewind(testHexFilePointer);


    //read both strings from test files into seperate strings
    fgets(readTestStringFile, 65, (FILE*)testStringFilePointer);
    fgets(readTestHexFile, 65, (FILE*)testHexFilePointer);

    remove("testStringFile");
    remove("testHexFile");
    fclose(testHexFilePointer);
    fclose(testStringFilePointer);

    //compare both strings from test files, if same then test passes
    if (strcmp(readTestStringFile, readTestHexFile) == 0)
    {
        printf("1) stringToHex_test passed\n");
    }
    else
    {
        printf("1) stringToHex_test FAILED\n");
        return 1;
    }

    return 0;
}

int countFilesInDirectory_test()
{
    long count = 0;
    countFilesInDirectory(TEST_DIR_NAME, &count);

    if (count == NUM_FILES_TEST_DIR)
    {
        printf("2) countFilesInDirectory_test passed\n");
    }
    else
    {
        printf("2) countFilesInDirectory_test FAILED\n");
        return 1;
    }

    return 0;
}

int main()
{
    int testStatuses[NUM_TESTS];

    srand(time(0));

    printf("\n");

    testStatuses[0] = stringToHex_test();
    testStatuses[1] = countFilesInDirectory_test();

    printf("\n");
    for (int i = 0; i < NUM_TESTS; i++)
    {
        printf("%d", testStatuses[i]);
    }
    printf("\n");

    return 0;
}