<?php

require __DIR__ . '/../vendor/autoload.php';

echo (new Acme\Api\Kernel())->handle($_SERVER['REQUEST_URI'] ?? '/');
