import { helper } from "./lib";

export const run = (value: number): number => helper(value) + 1;

export function main(): void {
  console.log(run(1));
}
