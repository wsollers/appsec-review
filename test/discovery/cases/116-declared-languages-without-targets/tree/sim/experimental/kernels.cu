__global__ void step_kernel(int *state) { state[threadIdx.x] += 1; }
