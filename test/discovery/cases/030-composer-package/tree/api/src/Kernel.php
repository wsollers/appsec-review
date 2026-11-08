<?php

namespace Acme\Api;

final class Kernel
{
    public function handle(string $path): string
    {
        return 'ok ' . $path;
    }
}
