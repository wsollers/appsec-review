<?php
namespace App\Support;

class Helpers
{
    public static function clean(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES);
    }
}
