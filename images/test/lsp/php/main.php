<?php

function helper(int $value): int
{
    return $value + 1;
}

function main(): int
{
    return helper(41);
}
