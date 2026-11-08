#ifdef APP_NEON
int neon_sum(const int *v, int n);
#else
static int neon_sum(const int *v, int n) { int s = 0; for (int i = 0; i < n; i++) s += v[i]; return s; }
#endif
int main() { int v[2] = {1, 2}; return neon_sum(v, 2) == 3 ? 0 : 1; }
