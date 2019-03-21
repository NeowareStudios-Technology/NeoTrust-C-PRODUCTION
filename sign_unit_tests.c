/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 3/21/19
 * Copywrite NeoWare 2019
 * *********************************/


#include <time.h>
#include "sign.h"

#define NUM_TESTS 1

int CreateTestSecp256k1ScalarObject_test()
{
    secp256k1_scalar testScalarObject;

    CreateTestSecp256k1ScalarObject(&testScalarObject);

    if (sizeof(testScalarObject) != 32)
    {
        printf("1) CreateTestSecp256k1ScalarObject_test FAILED\n");
        return 1;
    }

    printf("1) CreateTestSecp256k1ScalarObject_test passed\n");
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
    printf("\n***** Unit Tests: sign.c *****\n");
}

int main()
{
    int testStatuses[NUM_TESTS];
    srand(time(0));

    printHeader();

    testStatuses[0] = CreateTestSecp256k1ScalarObject_test();

    printTestStatuses(testStatuses);

    return 0;
}
