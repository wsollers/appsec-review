extern "C" int sim_step(int state);
int main() { return sim_step(0) == 1 ? 0 : 1; }
