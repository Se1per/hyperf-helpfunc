<?php

namespace Japool\HyperfHelpFunc;

class XlsWriteMain
{
    public $excel;

    public function excelExport($path = './template/download/')
    {
        $config = [
            'path' => $path // xlsx文件保存路径
        ];

        $this->excel = new \Vtiful\Kernel\Excel($config);

        return $this;
    }

    /** 创建并写入xls (常规表格)
     * @param $fileName 
     * @param array $header
     * @param array $data
     * @return $this
     */
        // Return the current object instance for method chaining.
    public function generateXls($fileName, array $header, array $data,$memory = true,$sheet = 'sheet1')
    {
        // fileName 会自动创建一个工作表，你可以自定义该工作表名称，工作表名称为可选参数
        if($memory){
            $this->excel =  $this->excel->constMemory($fileName, $sheet,false);
        }else{
            $this->excel =  $this->excel->fileName($fileName, $sheet);
        }

        $this->excel
            ->header($header)
            ->data($data);

        return $this;
    }

    /**
     * 输出excel
     */
    public function outputAll()
    {
        $file = $this->excel->output();

        $this->excel->close();

        return $file;
    }
    
    //
    public function openFile($path, $fileName)
    {
        $excel = new \Vtiful\Kernel\Excel(['path' => $path]);

        $this->excel = $excel->openFile($fileName);

        return $this;
    }

    /**
     * 打开工作表
     * @param $name
     * @return $this
     */
    public function openSheet($name,$configType = null)
    {
        if($configType){
            $configType  = \Vtiful\Kernel\Excel::SKIP_EMPTY_CELLS;
        }

        $this->excel = $this->excel->openSheet($name,$configType);

        return $this->excel;
    }

    /**
     * 游标按行读取
     * @return $this
     */
    public function nextRow()
    {
        $this->excel = $this->excel->nextRow($configType);

        return $this;
    }

    /**
     * 全量读取
     * @return $this
     */
    public function getSheetData()
    {
        $this->excel = $this->excel->getSheetData();

        return $this;
    }

    /**
     * 配置转换类型
     * [ //配置转换格式
     * ]
     * const TYPE_STRING = 0x01;    // 字符串
     * const TYPE_INT = 0x02;       // 整型
     * const TYPE_DOUBLE = 0x04;    // 浮点型
     * const TYPE_TIMESTAMP = 0x08; // 时间戳，可以将 xlsx 文件中的格式化时间字符转为时间戳
     * @param $configType
     * @return $this
     * User: Se1per
     * Date: 2023/7/28 17:02
     */
    public function setType(array $configType)
    {
        $this->excel = $this->excel->setType($configType);

        return $this;
    }


}