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

#define NUM_TESTS 3
#define TEST_DIR_NAME "testdir"
#define NUM_FILES_TEST_DIR 4
#define LONG_TEST_REPEATS 20
#define SHORT_TEST_REPEATS 1000

//this is a short test
int stringToHex_test()
{
    const char *hexPool = "0123456789abcdef";
    char testKey[65];
    const char* spacedTestKey; 
    char readTestHexFile[65];
    char readTestStringFile[65];

    //repeat this test NUM_TEST_REPEATS times
    for (int repeat = 0; repeat < SHORT_TEST_REPEATS; repeat++)
    {
        uint8_t *serializedTestKey = malloc(sizeof(uint8_t)*32);
        FILE *testStringFilePointer = fopen("testStringFile", "a+");
        FILE *testHexFilePointer = fopen("testHexFile", "a+");

        //randomly generate test key
        for (int i = 0; i < 64; i++)
        {
            testKey[i] = hexPool[rand() % 16];
        }
        testKey[64] = '\0';

        //add spaces to string to separate hex values
        spacedTestKey = insertSpaces(testKey);

        //convert test key (with spaces) into hex
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

        //compare both strings from test files, if not matching then test fails
        if (strcmp(readTestStringFile, readTestHexFile) != 0)
        {
            printf("1) stringToHex_test FAILED\n");
            return 1;
        }

        free(serializedTestKey);
        fclose(testHexFilePointer);
        fclose(testStringFilePointer);
        remove("testStringFile");
        remove("testHexFile");
    }

    //test passes if all repeated test loops pass
    printf("1) stringToHex_test passed\n");
    return 0;
}

//this test requires you to reference an existing directory with TEST_DIR_NAME and to set NUM_FILES_TEST_DIR
//to the number of files in this directory
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

//this is a long test
int getFileLength_test()
{
    for (int repeat = 0; repeat < LONG_TEST_REPEATS; repeat++)
    {
        FILE *testFilePointer = fopen("testLength", "a+");
        long stringLength = rand() % 9999999;
        long fileLength;
        char fileContents[stringLength+1];

        for (int i=0; i<stringLength; i++)
        {
            fileContents[i] = rand() % (127+1-1)+1;
        }
        fileContents[stringLength] = '\0';

        fputs(fileContents, testFilePointer);

        fileLength = getFileLength("testLength", testFilePointer);

        if (stringLength != fileLength)
        {
            printf("3) getFileLength_test FAILED");
            return 1;
        }

        fclose(testFilePointer);
        remove("testLength");

    }

    printf("3) getFileLength_test passed\n");
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
    printf("\n***** Unit Tests: helper.c *****\n");
}

int main()
{
    int testStatuses[NUM_TESTS];
    srand(time(0));

    printHeader();

    testStatuses[0] = stringToHex_test();
    testStatuses[1] = countFilesInDirectory_test();
    testStatuses[2] = getFileLength_test();

    printTestStatuses(testStatuses);

    return 0;
}