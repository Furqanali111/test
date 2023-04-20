#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerability1(char* input) {
    char buffer[10];
    strcpy(buffer, input);
    printf("Buffer contents: %s\n", buffer);
}

void vulnerability2(char* input) {
    char* buffer = (char*)malloc(strlen(input));
    strcpy(buffer, input);
    printf("Buffer contents: %s\n", buffer);
    free(buffer);
}

void vulnerability3() {
    char buffer[10];
    printf("Enter a password:\n");
    scanf("%s", buffer);
    if (strcmp(buffer, "password123") == 0) {
        printf("Access granted!\n");
    }
    else {
        printf("Access denied.\n");
    }
}

void vulnerability4() {
    char buffer[10];
    printf("Enter your name:\n");
    gets(buffer);
    printf("Hello, %s!\n", buffer);
}

void vulnerability5(char* input) {
    char buffer[10];
    snprintf(buffer, sizeof(buffer), "%s", input);
    printf("Buffer contents: %s\n", buffer);
}

int main(int argc, char** argv) {
    vulnerability1(argv[1]); // buffer overflow
    vulnerability2(argv[1]); // heap overflow
    vulnerability3();        // format string vulnerability
    vulnerability4();        // buffer overflow
    vulnerability5(argv[1]); // potential buffer overflow
    return 0;
}