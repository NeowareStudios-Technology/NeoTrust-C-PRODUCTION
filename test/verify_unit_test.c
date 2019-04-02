/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 4/2/19
 * Copywrite NeoWare 2019
 * *********************************/

#define NUM_TESTS 1


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

    testStatuses[0] = privKeyStringToHex_test();

    printTestStatuses(testStatuses);

    return 0;
}