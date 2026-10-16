struct pair { int *left; int *right; };
int dispatch(int index, char *buffer, const char *input);
void guarded_alias(struct pair *value, int input);
void guarded_unrelated(int input);

int main(int argc, char **argv) {
    char buffer[16];
    int left = 0, right = 0;
    struct pair value = {&left, &right};
    guarded_alias(&value, argc);
    guarded_unrelated(argc);
    return dispatch(argc & 1, buffer, argc > 1 ? argv[1] : "x");
}
