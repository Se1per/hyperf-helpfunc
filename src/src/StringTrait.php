<?php

namespace Japool\HyperfHelpFunc\src;


trait StringTrait
{
    /**
     * 判断变量是否中文字
     * @param $str
     * @return false|int
     * User: Se1per
     * Date: 2023/7/25 9:58
     */
    public function containsChinese($str)
    {
        return preg_match("/\p{Han}/u", $str);
    }

    /**
     * 获取当前域名
     * @return string
     */
    public static function getHttpType(): string
    {
        $http = ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')) ? 'https://' : 'http://';
        return $http . $_SERVER['HTTP_HOST'];
    }

    /**
     * 替换字符串
     * @param $replaceStr @被替换得字符串或数组
     * @param $search @搜索被替换得字符串
     * @param $replace @需要替换值
     * @return array|mixed
     */
    public static function replaceStr($replaceStr, $search, $replace)
    {
        if (is_array($replaceStr)) {

            array_walk($replaceStr, function (&$q) use ($search, $replace) {
                $q = str_replace($search, $replace, $q);
            });

        } else {
            str_replace($search, $replace, $replaceStr);
        }

        return $replaceStr;

    }

    /**
     * 字符串裁剪内容转成数组
     * @param $str
     * @param $search
     * @return array
     */
    public static function cropStrToArray($str, $search): array
    {
        $arr = [];

        if (is_array($str)) {
            foreach ($str as $val) {
                list($key, $value) = explode($search, $val);
                if (!empty($value)) {
                    $arr[$key] = $value;
                }
            }
        } else {
            list($key, $value) = explode($search, $str);

            if (!empty($value)) {
                $arr[$key] = $value;
            }
        }

        return $arr;
    }

    /**
     * 正则匹配字符串返回匹配内容
     * @param $matches
     * @param $rules
     * @param $str
     * @return false|mixed
     */
    public static function regularityStr($matches, $rules, $str)
    {
        $isMatched = preg_match($rules, $str, $matches);

        if ($isMatched) {
            return $matches[0];
        } else {
            return false;
        }
    }

    /**
     * 创建随机字符串
     * @param int $length 长度
     * @param int $type 运算字符类型
     * @param string|null $confound 混淆
     * @param string|null $Patching 填充
     * @param int $PatchingType 0从头部填充 1从尾部填充
     * @return string
     * @throws Exception
     * User: Se1per
     * Date: 2023/7/5 17:56
     */
    public function createNonceStr(int $length = 32, int $type = 1, string $confound = null, string $Patching = null, int $PatchingType = 0): string
    {
        static $chars = [
            1 => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
            2 => 'abcdefghijklmnopqrstuvwxyz0123456789',
            3 => '0123456789',
        ];

        if (!isset($chars[$type])) throw new Exception(get_called_class() . '数据参数类型不支持');

        $str = '';

        if ($confound !== null) {
            $chars[$type] = $chars[$type] . $str;
        }

        //长度
        $max = strlen($chars[$type]) - 1;

        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars[$type], random_int(0, $max), 1);
        }

        if ($Patching !== null) {
            if ($PatchingType == 0) {
                $str = $Patching.$str;
                $str = substr($str, 0, $length);
            } else {
                $str = $str.$Patching;
                $str = substr($str, -$length);
            }
        }

        return $str;
    }

    /**
     * 下划线转驼峰
     * 思路:
     * step1.原字符串转小写,原字符串中的分隔符用空格替换,在字符串开头加上分隔符
     * step2.将字符串中每个单词的首字母转换为大写,再去空格,去字符串首部附加的分隔符.
     */
    public static function camelize($uncamelized_words, $separator = '_')
    {
        $uncamelized_words = $separator . str_replace($separator, " ", strtolower($uncamelized_words));
        return ltrim(str_replace(" ", "", ucwords($uncamelized_words)), $separator);
    }

    /**
     * 驼峰命名转下划线命名
     * 思路:
     * 小写和大写紧挨一起的地方,加上分隔符,然后全部转小写
     */
    public static function uncamelize($camelCaps, $separator = '_')
    {
        return strtolower(preg_replace('/([a-z])([A-Z])/', "$1" . $separator . "$2", $camelCaps));
    }

    /**
     * 获取控制器方法名称
     * @return bool 返回数组
     */
    public static function getControllerMethodName()
    {
        //获取访问得控制器
        $action = request()->route()->getActionName();

        list($class, $method) = explode('@', $action);
        //截取class
        return $method;
    }

    /**
     * 获取控制器类名称
     * @return bool 返回数组
     */
    public static function getControllerActionName($action = null)
    {
        //获取访问得控制器
        if (!$action) {
            $action = request()->route()->getActionName();
            list($action, $method) = explode('@', $action);
        }

        //截取class
        return str_replace('Controller', '', substr(strrchr($action, '\\'), 1));
    }

    /**
     * bzip2 压缩
     * @param $string
     * @return string
     */
    public function compressBz2String($string)
    {
        return base64_encode(bzcompress(json_encode($string, JSON_UNESCAPED_UNICODE)));
    }

    /**
     * bzip2 解压缩
     * @param $string
     * @return mixed
     */
    public function decompressBz2String($string){
        return json_decode(bzdecompress(base64_decode($string)), true);
    }

    /**
     * Deflate 压缩
     * @param $string
     * @return string
     */
    public function compressString($string)
    {
        return base64_encode(gzdeflate(json_encode($string, JSON_UNESCAPED_UNICODE)));
    }

    /**
     * Deflate 解压缩
     * @param $string
     * @return mixed
     */
    public function decompressString($string){
        return json_decode(gzinflate(base64_decode($string)), true);
    }

    /**
     * Gzip 压缩
     * @param $obj
     * @return string
     */
    function enStringCompress($obj)
    {
        return base64_encode(gzcompress(json_encode($obj, JSON_UNESCAPED_UNICODE)));
    }

    /**
     * Gzip 解压缩
     * @param $obj
     * @return mixed
     */
    function deStringCompress($obj)
    {
        return json_decode(gzuncompress(base64_decode($obj)), true);
    }
}