/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 4/2/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <time.h>
#include "../verify.h"

#define NUM_TESTS 1
#define TEST_META_DIR_NAME "testMETA-INF"

int GetSigObjectFromSigBlockFile_test()
{
    char metaInfDirPath[256];

    strcpy(metaInfDirPath, "./");
    strcat(metaInfDirPath, TEST_META_DIR_NAME);

    printf("%s",metaInfDirPath);

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
    printf("\n***** Unit Tests: verify.c *****\n");
}


int main()
{
    int testStatuses[NUM_TESTS];
    srand(time(0));

    printHeader();

    testStatuses[0] = GetSigObjectFromSigBlockFile_test();

    printTestStatuses(testStatuses);

    return 0;
}