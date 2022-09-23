#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  char* dummy = (char*) malloc(64 * sizeof(char));
  memset(dummy, 'A', 64 * sizeof(char));
  printf("Ready\n");
  while (1);
}