__global__ void step_kernel(int *state) { state[threadIdx.x] += 1; }
extern "C" void sim_step_gpu(int *state, int n) { step_kernel<<<1, n>>>(state); }
