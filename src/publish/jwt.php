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
    'secret' => \Hyperf\Support\env('JWT_SECRET', 'azqwrzbie3d5d0061126d0ca0320daf761444bdbe52ba4fac580932ce0ddc9ad'),
    'algorithm' => 'HS256',
    'exp' => \Hyperf\Support\env('JWT_TOKEN_TIME_OUT',3600),
    'exclude' => [
        '/api/login/loginApi',
    ],
    'x-forwarded-for'=>[
        '127.0.0.1'
    ]
];
