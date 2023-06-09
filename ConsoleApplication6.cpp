#include "explore_me.h"
#include <cstdio>
#include <string.h>
using namespace std;

// just a function with multiple paths that can be discoverd by a fuzzer
void exploreMe(int a, int b, string c) {
    printf("a: %d; b: %d; c: %s\n", a, b, c.c_str());

    if (a >= 20000) {
        if (b >= 2000000) {
            if (b - a < 100000) {
                // Trigger the undefined behavior sanitizer
                int n = 23;
                n <<= 32;
                if (c == "FUZZING") {
                    // Trigger a heap buffer overflow
                    char* s = (char*)malloc(1);
                    strcpy(s, "too long");
                }
            }
        }
    }
}
