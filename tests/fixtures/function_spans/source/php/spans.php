<?php

$limit = 4; // ANCHOR:none

function render(array $items): string { // BEGIN:render
    # a hash comment with a brace {
    $out = array_map(function ($item) use ($limit) {
        return htmlspecialchars($item); // ANCHOR:render
    }, $items);
    return implode(",", $out); // ANCHOR:render
} // END:render

class Spans
{
    public function run(string $name): void // BEGIN:run
    {
        echo $name; // ANCHOR:run
    } // END:run
}
