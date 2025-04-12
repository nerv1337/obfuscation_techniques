#define BLOAT10(x)                                                             \
  x;                                                                           \
  x;                                                                           \
  x;                                                                           \
  x;                                                                           \
  x;                                                                           \
  x;                                                                           \
  x;                                                                           \
  x;                                                                           \
  x;                                                                           \
  x
#define BLOAT100(x) BLOAT10(BLOAT10(x))
#define BLOAT1000(x) BLOAT10(BLOAT100(x))

int main() {
  volatile int a = 0;
  BLOAT1000(a += 1);
  return 0;
}
