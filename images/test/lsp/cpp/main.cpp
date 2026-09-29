static int helper(int value) {
    return value + 1;
}

int main() {
    return helper(41) == 42 ? 0 : 1;
}
