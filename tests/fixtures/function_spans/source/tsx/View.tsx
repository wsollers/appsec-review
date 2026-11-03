import React from "react";

const title = "items"; // ANCHOR:none

export function View(props: { items: string[] }) { // BEGIN:View
  const rows = props.items.map((item) => {
    return <li key={item}>{item}</li>; // ANCHOR:View
  });
  return <ul title={title}>{rows}</ul>; // ANCHOR:View
} // END:View
