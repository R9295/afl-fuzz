#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// The following line is needed for shared memeory testcase fuzzing
__AFL_FUZZ_INIT();

void vuln(char *buf) {
  if (strcmp(buf, "vuln") == 0) { abort(); }
}

int main(int argc, char **argv) {
  // The following line is also needed for shared memory testcase fuzzing
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

  printf("input: %s\n", buf);
  if (buf[0] == 'b') {
    if (buf[1] == 'a') {
      if (buf[2] == 'd') { abort(); }
    }
  }
  vuln(buf);

  return 0;
}
