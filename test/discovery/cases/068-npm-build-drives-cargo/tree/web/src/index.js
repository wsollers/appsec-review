import init, { add } from "../pkg/wasm_core.js";

init().then(() => {
  document.title = String(add(2, 3));
});
