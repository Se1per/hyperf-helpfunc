<?php

namespace Japool\HyperfHelpFunc;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            // 合并到  config/autoload/dependencies.php 文件
            'dependencies' => [],
            // 合并到  config/autoload/annotations.php 文件
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__,
                    ],
                ],
            ],
            // 默认 Command 的定义，合并到 Hyperf\Contract\ConfigInterface 内，换个方式理解也就是与 config/autoload/commands.php 对应
            'commands' => [],
            // 与 commands 类似
            'listeners' => [],
            // 组件默认配置文件，即执行命令后会把 source 的对应的文件复制为 destination 对应的的文件
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'The config for generate', // 描述
                    'source' => __DIR__ . '/publish/jwt.php',  // 对应的配置文件路径
                    'destination' => BASE_PATH . '/config/autoload/jwt.php', // 复制为这个路径下的该文件
                ],
                [
                    'id' => 'jwt_middleware',
                    'description' => 'JwtTokenMiddleware generate', // 描述
                    'source' => __DIR__ . '/publish/JwtTokenMiddleware.stub',  // 对应的配置文件路径
                    'destination' => BASE_PATH . '/app/Middleware/JwtTokenMiddleware.php', // 复制为这个路径下的该文件
                ],
                [
                    'id' => 'request_middleware',
                    'description' => 'RequestMiddleware generate',
                    'source' => __DIR__ . '/publish/RequestMiddleware.stub',  // 对应的配置文件路径
                    'destination' => BASE_PATH . '/app/Middleware/RequestMiddleware.php', // 复制为这个路径下的该文件
                ],
                [
                    'id' => 'cors_middleware',
                    'description' => 'CorsMiddleware generate',
                    'source' => __DIR__ . '/publish/CorsMiddleware.stub',  // 对应的配置文件路径
                    'destination' => BASE_PATH . '/app/Middleware/CorsMiddleware.php', // 复制为这个路径下的该文件
                ],
            ],
            // 亦可继续定义其它配置，最终都会合并到与 ConfigInterface 对应的配置储存器中
        ];
    }
}