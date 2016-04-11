#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>

int main(){
	struct timeval stop, start;     // start and stop time
	gettimeofday(&start, NULL);
	gettimeofday(&stop, NULL);
	cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << "\n";
}