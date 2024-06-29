
php bin/hyperf.php vendor:publish japool/hyperf-help-func

# 添加中间件 config/autoload/middlewares.php
\App\Middleware\JwtTokenMiddleware::class