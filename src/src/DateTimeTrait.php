<?php

namespace Japool\HyperfHelpFunc\src;


trait DateTimeTrait
{
    /** 简便转换时间
     * @param $time
     * @return false|string
     */
    public static function pretty($time)
    {
        $return = '';

        if (!is_numeric($time)) {
            $time = strtotime($time);
        }

        $htime = date('H:i', $time);

        $dif = abs(time() - $time);
        if ($dif < 10) {
            $return = '刚刚';
        } else if ($dif < 3600) {
            $return = floor($dif / 60) . '分钟前';
        } else if ($dif < 10800) {
            $return = floor($dif / 3600) . '小时前';
        } else if (date('Y-m-d', $time) == date('Y-m-d')) {
            $return = '今天 ' . $htime;
        } else if (date('Y-m-d', $time) == date('Y-m-d', strtotime('-1 day'))) {
            $return = '昨天 ' . $htime;
        } else if (date('Y-m-d', $time) == date('Y-m-d', strtotime('-2 day'))) {
            $return = '前天 ' . $htime;
        } else if (date('Y', $time) == date('Y')) {
            $return = date('m-d H:i', $time);
        } else {
            $return = date('Y-m-d H:i', $time);
        }
        return $return;
    }

    /** 根据年月获取时间戳
     * @param int $year
     * @param int $mouth
     * @return array
     */
    public static function getYearMouth(int $year = 0, int $mouth = 0): array
    {

        if (empty($year) || empty($mouth)) {
            $now = time();
            $year = date("Y", $now);
            $mouth = date("m", $now);
        }

        $time['begin'] = date('Y-m-d H:i:s', mktime(0, 0, 0, $mouth, 1, $year));

        $time['end'] = date('Y-m-d H:i:s', mktime(23, 59, 59, ($year + 1), 0, $year));

        return $time;
    }

    /**  获取时间周期段
     * @param string $type
     * @return mixed
     */
    public static function getTypeTime(string $type = 'today'): array
    {
        switch ($type) {
            case 'yesterday';
                // 获取昨日起始时间 结束时间 和 时间戳
                $data['begin_time'] = mktime(0, 0, 0, date('m'), date('d') - 1, date('Y'));
                $data['begin_day'] = date('Y-m-d H:i:s', $data['begin_time']);
                $data['end_time'] = mktime(0, 0, 0, date('m'), date('d'), date('Y')) - 1;
                $data['end_day'] = date('Y-m-d H:i:s', $data['end_time']);
                return $data;
            case 'thisweek';
                // 获取本周起始时间 结束时间 和 时间戳
                $data['begin_time'] = mktime(0, 0, 0, date('m'), date('d') - date('w') + 1, date('Y'));
                $data['begin_day'] = date('Y-m-d H:i:s', $data['begin_time']);
                $data['end_time'] = mktime(23, 59, 59, date('m'), date('d') - date('w') + 7, date('Y'));
                $data['end_day'] = date('Y-m-d H:i:s', $data['end_time']);
                return $data;
            case 'season';
                $season = ceil((date('n')) / 3);//当月是第几季度
                $data['begin_day'] = date('Y-m-d H:i:s', mktime(0, 0, 0, $season * 3 - 3 + 1, 1, date('Y')));
                $data['begin_time'] = mktime(0, 0, 0, $season * 3 - 3 + 1, 1, date('Y'));
                $data['end_day'] = date('Y-m-d H:i:s', mktime(23, 59, 59, $season * 3, date('t', mktime(0, 0, 0, $season * 3, 1, date("Y"))), date('Y')));
                $data['end_time'] = mktime(0, 0, 0, $season * 3 - 3 + 1, 1, date('Y'));
                return $data;
            case 'month':
                $data['begin_time'] = mktime(0, 0, 0, date('m'), 1, date('Y'));
                $data['begin_day'] = date('Y-m-d H:i:s', $data['begin_time']);
                $data['end_time'] = mktime(23, 59, 59, date('m'), date('t'), date('Y'));
                $data['end_day'] = date('Y-m-d H:i:s', $data['end_time']);
                return $data;
            default:
                //取今天的 起始时间
                $data['begin_time'] = mktime(0, 0, 0, date('m'), date('d'), date('Y'));
                $data['begin_day'] = date('Y-m-d H:i:s', $data['begin_time']);
                $data['end_time'] = mktime(0, 0, 0, date('m'), date('d') + 1, date('Y')) - 1;
                $data['end_day'] = date('Y-m-d H:i:s', $data['end_time']);
                return $data;
        }
    }

    /**  获取年份的所有月份开始和结束时间 TODO 没做按年份生产 当前只有获取当年的所有月份
     * @param $year //初始年份
     * @param $num //循环生成年份
     */
    public static function getMonthTimes(string $year): array
    {
        $new = [];

        for ($i = 1; $i <= 12; $i++) {
            $arr['start'] = mktime(0, 0, 0, $i, 1, $year);

            $arr['end'] = mktime(23, 59, 59, ($i + 1), 0, $year);

            $arr['start'] = date('Y-m-d H:i:s', $arr['start']);

            $arr['end'] = date('Y-m-d H:i:s', $arr['end']);

            $new[] = $arr;

//            array_push($new,$arr);
        }

        return $new;

    }

    /** 获取指定日期所在月的开始日期与结束日期
     * @param $date
     * @param bool $returnFirstDay
     * @return false|string
     */
    public function getMonthRange($date, bool $returnFirstDay = true )
    {
        $timestamp = strtotime($date);

        if ($returnFirstDay) {
            return date('Y-m-1 00:00:00', $timestamp);
        }

        $mDays = date('t', $timestamp);
        return date('Y-m-' . $mDays . ' 23:59:59', $timestamp);
    }

    /**  获取时间周期段内所有时间
     * @param string $startDate 开始时间
     * @param string $endDate 结束时间
     * @return array
     */
    public static function getDateRange(string $startDate, string $endDate): array
    {
        $sTime = strtotime($startDate);
        $eTime = strtotime($endDate);

        $dateArr = [];

        while ($sTime <= $eTime) {
            $dateArr[] = date('Y-m-d', $sTime);//得到dataArr的日期数组。
            $sTime = $sTime + 86400;
        }

        return $dateArr;
    }

    /**
     * 求两个日期之间相差的天数
     * (针对1970年1月1日之后，求之前可以采用泰勒公式)
     * @param string $day1 开始时间
     * @param string $day2 结束时间
     * @return number
     */
    public static function diffBetweenTwoDays(string $day1, string $day2): int
    {
        $second1 = strtotime($day1);

        $second2 = strtotime($day2);

        if ($second1 < $second2) {
            $tmp = $second2;
            $second2 = $second1;
            $second1 = $tmp;
        }
        return ($second1 - $second2) / 86400;
    }

    /** 计算两个日期相隔多少年，多少月，多少天
     * @param $date1 $date1[格式如：2011-11-5]
     * @param $date2 $date2[格式如：2012-12-01]
     * @return array
     */
    public static function diffDate(string $date1, string $date2): array
    {

        if (strtotime($date1) > strtotime($date2)) {
            $tmp = $date2;
            $date2 = $date1;
            $date1 = $tmp;
        }

        list($Y1, $m1, $d1) = explode('-', $date1);
        list($Y2, $m2, $d2) = explode('-', $date2);

        $Y = $Y2 - $Y1;
        $m = $m2 - $m1;
        $d = $d2 - $d1;

        if ($d < 0) {
            $d += (int)date('t', strtotime("-1 month $date2"));
            $m--;
        }

        if ($m < 0) {
            $m += 12;
            $Y--;
        }
        return array('year' => $Y, 'month' => $m, 'day' => $d);
    }

    /**  根据身份证 计算岁数
     * @param string $id
     * @return false|float|int|string
     */
    public static function getAgeByID(string $id)
    {
        //过了这年的生日才算多了1周岁
        if (empty($id)) return '';
        $date = strtotime(substr($id, 6, 8));
        //获得出生年月日的时间戳
        $today = strtotime('today');
        //获得今日的时间戳 111cn.net
        $diff = floor(($today - $date) / 86400 / 365);
        //得到两个日期相差的大体年数

        //strtotime加上这个年数后得到那日的时间戳后与今日的时间戳相比
        $age = strtotime(substr($id, 6, 8) . ' +' . $diff . 'years') > $today ? ($diff + 1) : $diff;

        return $age;
    }
}