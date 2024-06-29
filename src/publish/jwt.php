<?php

declare(strict_types=1);

/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://hyperf.wiki
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */
return [
    'secret' => \Hyperf\Support\env('JWT_SECRET', 3600000),
    'algorithm' => 'HS256',
    'exp' => \Hyperf\Support\env('JWT_TOKEN_TIME_OUT',3600),
    'exclude' => [
        '/api/login/loginApi',
    ],
    'x-forwarded-for'=>[
        '127.0.0.1'
    ]
];
