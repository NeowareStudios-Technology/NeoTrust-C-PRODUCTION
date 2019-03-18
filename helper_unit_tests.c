/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 3/18/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "helper.h"

int stringLength_test()
{
    //int length = rand() % 300;
    //char *testRandomString = malloc(sizeof(char) * (length+1));

    int length = rand() % 300;
    char *preTestString = malloc(sizeof(char) * (length+1));

    if (preTestString)
    {
        for (int i = 0; i < length; i++)
        {
            //assign random ascii char
            preTestString[i] = rand() % 127; 
        }
        preTestString[length] = '\0';
    }

    const char *testString = preTestString;

    printf("\n%d\n",length);
    printf("\n%d\n", stringLength(testString));

    free(preTestString);
}

int main()
{
    srand(time(0));
    
    stringLength_test();

    return 0;
}