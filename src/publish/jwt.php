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
    'exp' => \Hyperf\Support\env('JWT_TOKEN_TIME_OUT'),
    'exclude' => [
        '/api/login/loginApi',
    ],
    'api_token'=>[
        'secret' => 'your-secret-key44444444',
        'algorithm' => 'HS256',
        'exclude' => [
            '/api/login/loginApi',
            '/api/wxWorkInside/wxWorkErpLogin',
        ],
    ],
];
