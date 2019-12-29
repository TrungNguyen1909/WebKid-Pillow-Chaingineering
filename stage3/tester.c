#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char *argv[]) {
	dlopen("./stage3_macOS.dylib",0);
}