#include <iostream>
#include <unistd.h>
#include <pthread.h>
using namespace std;

pthread_mutex_t mutex;

void * thread(void *ptr) {
	pthread_mutex_lock(&mutex);

	for(int i = 0; i < 3; i++) {
		sleep(1);
		cout << "This is a child pthread." << endl;
	}

	pthread_mutex_unlock(&mutex);

	return 0;
}

int main() {
	pthread_t id;
	pthread_mutex_init(&mutex, NULL);

	int ret = pthread_create(&id, NULL, thread, NULL);
	if (ret) {
		cout << "Create pthread error!" << endl;
		return 1;
	}

	pthread_mutex_lock(&mutex);
	for (int i = 0; i < 3; i++) {
		cout <<  "This is the main process." << endl;
		sleep(1);
	}
	pthread_mutex_unlock(&mutex);

	pthread_join(id, NULL);
	return 0;
}
