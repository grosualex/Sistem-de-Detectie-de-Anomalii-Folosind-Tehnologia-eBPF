#include <stdio.h>
#include <unistd.h>

int main() {
	FILE *file = fopen("file.write", "w");
	while(1) {
		fwrite("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 30, 1, file);
		fflush(file);
		sleep(1);
	}
}