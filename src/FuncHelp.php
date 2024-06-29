<?php

namespace Japool\HyperfHelpFunc;

use Japool\HyperfHelpFunc\src\AesTrait;
use Japool\HyperfHelpFunc\src\ArrayTrait;
use Japool\HyperfHelpFunc\src\DateTimeTrait;
use Japool\HyperfHelpFunc\src\GeographyTrait;
use Japool\HyperfHelpFunc\src\McryptAes;
use Japool\HyperfHelpFunc\src\StringTrait;
use Japool\HyperfHelpFunc\src\XmlTrait;

class FuncHelp
{
    use AesTrait,ArrayTrait,DateTimeTrait,GeographyTrait,StringTrait,XmlTrait;
}