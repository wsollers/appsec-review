struct Pair { int left; long long right; };
volatile struct Pair global_pair;
static inline int add(volatile struct Pair *p) { return p->left + (int)p->right; }
int entry(void) { return add(&global_pair); }
