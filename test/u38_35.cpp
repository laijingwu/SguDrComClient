#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
using namespace std;

int main()
{
	uint8_t a = 0x85;
	uint8_t tmp = a >> 1;
	if (a % 2 != 0)
		tmp |= 128;
	printf("%02x\n", tmp);
	return 0;
}