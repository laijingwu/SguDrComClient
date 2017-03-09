#include <stdio.h>
#include <stdint.h>
using namespace std;

int main()
{
	uint8_t a = 0x02;
	uint8_t tmp = a << 1;
	if (a >= 128)
		tmp |= 1;
	printf("%02x\n", tmp);
	return 0;
}