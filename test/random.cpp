#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
using namespace std;

uint16_t xsrand(void) {
	return (
	 (((uint16_t)rand()<<4)&0xF0u)
	| ((uint16_t)rand()&0x0Fu));
}

int main() {
	int i;
	uint16_t xs;
	srand(time(NULL));
	for (i = 0; i < 50; i++) {
		xs = xsrand();
		printf("0x%02x\n", xs);
	}
	return 0;
}