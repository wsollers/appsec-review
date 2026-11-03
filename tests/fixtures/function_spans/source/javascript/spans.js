const limit = 4; // ANCHOR:none

function render(items) { // BEGIN:render
  const out = [];
  items.forEach((item) => {
    out.push(`<li>${item}</li>`); // ANCHOR:render
  });
  return out.join(""); // ANCHOR:render
} // END:render

const handler = async (request) => { // BEGIN:handler
  const body = request.body; // ANCHOR:handler
  return body;
}; // END:handler

class Widget {
  draw(context) { // BEGIN:draw
    context.fill(limit); // ANCHOR:draw
  } // END:draw
}

module.exports = { render, handler, Widget };
