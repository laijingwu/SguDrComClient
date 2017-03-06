#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
using namespace std;

int main(int argc, char *argv[]) {
	time_t current_time = time(0);
	uint8_t buf[2];
	memcpy(buf, &current_time, 2);
	printf("%x %x", buf[0], buf[1]);
}