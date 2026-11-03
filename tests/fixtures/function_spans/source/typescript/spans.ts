export const limit: number = 4; // ANCHOR:none

export function parse(input: string): string[] { // BEGIN:parse
  return input.split(",").map((part: string) => {
    return part.trim(); // ANCHOR:parse
  });
} // END:parse

export const format: (value: string) => string = (value: string): string => { // BEGIN:format
  return value.toUpperCase(); // ANCHOR:format
}; // END:format

export class Service {
  public run(name: string): void { // BEGIN:run
    console.log(name); // ANCHOR:run
  } // END:run
}
