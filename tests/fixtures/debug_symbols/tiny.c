struct Pair { int left; long long right; };
static inline int add(struct Pair *p) { return p->left + (int)p->right; }
int entry(void) { struct Pair p = {2, 3}; return add(&p); }
