<?php

class ScanerDetector
{
    private $patterns;
    private $user_ip;
    private $user_agent;
    private $user_id;
    private $check_result;
    private $check_value;
    private $ban_limit = 1;

    function __construct()
    {
        $this->patterns['user-agent'] = [
            "/^Java.*/s",
            "/^Jakarta.*/s",
            "/.*User-Agent.*/s",
            "/.*compatible ;*/s",
            "/^Mozilla$/s",
            "/^libwww$/s",
            "/^lwp-trivial$/s",
            "/^curl$/s",
            "/scrapy\.org/s",
            "/^PHP\/$/s",
            "/^GT::WWW$/s",
            "/Snoopy/s",
            "/commoncrawl\.org/s",
            "/MFC_Tear_Sample/s",
            "/HTTP::Lite/s",
            "/PHPCrawl/s",
            "/ZmEu/s",
            "/URI::Fetch/s",
            "/Zend_Http_Client/s",
            "/http client/s",
            "/PECL::HTTP/s",
            "/panscient.com/s",
            "/IBM EVV/s",
            "/Bork-edition/s",
            "/Fetch API Request/s",
            "/[A-Z][a-z]{3,} [a-z]{4,} [a-z]{4,}/s",
            "/WEP Search/s",
            "/Wells Search II/s",
            "/Missigua Locator/s",
            "/ISC Systems iRc Search 2.1/s",
            "/Microsoft URL Control/s",
            "/Mozilla\/5\.0 \(X11; Linux x86_64; rv:57\.0\) Gecko\/20100101 Firefox\/57\.0/s",
            "/Mozilla\/5\.0 \(Windows NT 6\.1; WOW64; rv:11\.0\) Gecko\/20100101 Firefox\/11\.0/s",
            "/Indy Library/s",
            "/select pg_sleep/s",
            "/.*Python.*aiohttp.*/s",
            "/waitfor delay/s",
            "/now\(\)=sysdate\(\)/s",
        ];

        $this->patterns['request'] = [
            "/^555-666-0606$/is" => 10,
            "/^sample@email.tst$/is" => 10,
            "/netsparker/is" => 10,
            "/phpMyAdmin/is" => 10,
            "/select pg_sleep/is" => 10,
            "/waitfor delay/is" => 10,
            "/document\.cookie/is" => 10,
            "/now\(\)=sysdate\(\)/is" => 10,
            "/select\(sleep\(/is" => 10,
            "/select sleep\(/is" => 10,
            "/cast\(\(select/is" => 10,
            "/select dbms_pipe\.receive_message/is" => 10,
            "/\.\.\/etc\/passwd/is" => 10,
            "/\.\.\/windows\/win\.ini/is" => 10,
            "/WEB\-INF\/web\.xml/is" => 10,
            "/acu:Expre\/\*\*\/SSion/is" => 10,
            "/onmouseover%3dprompt/is" => 10,
            "/Copy%20(.*)of(.*)\.php/is" => 10,
            "/Copy_(.*)of(.*)\.php/is" => 10,
            "/SomeCustomInjectedHeader\:injected_by_wvs/is" => 10,
        ];
    }

    function check()
    {
        $this->check_result = [];
        $this->check_value = 0;
        $this->generateUserId();
        $this->checkIsBanned();
        $this->checkUserAgent();
        $this->checkRequest();

        if (sizeof($this->check_result)) {
            $this->writeToLogs();
        }

        if ($this->check_value > $this->ban_limit) {
            header("HTTP/1.0 500 Internal Server Error", true, 500);
            echo "Maintenance. Please, come back later.";
            die();
        }
    }

    function generateUserId()
    {
        if (!empty($_SERVER['HTTP_CLIENT_IP']) && $_SERVER['HTTP_CLIENT_IP'] != '127.0.0.1') {
            $this->user_ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR'] != '127.0.0.1') {
            $this->user_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $this->user_ip = $_SERVER['REMOTE_ADDR'];
        } else {
            $this->user_ip = '127.0.0.1';
        }

        $this->user_agent = $_SERVER['HTTP_USER_AGENT'];

        $this->user_id = md5($this->user_ip . $this->user_agent);
    }

    function writeToLogs()
    {
        // переопределите функцию, чтобы писать логи
        $file = fopen(__DIR__ . DIRECTORY_SEPARATOR . 'scaner_detector.log', 'a+');
        fwrite($file, '======' . PHP_EOL
            . 'time: ' . date('d.m.Y H:i:s') . PHP_EOL
            . 'banned: ' . $this->user_id . PHP_EOL
            . 'ip: ' . $this->user_ip . PHP_EOL
            . 'agent: ' . $this->user_agent . PHP_EOL
            . 'value: ' . $this->check_value . PHP_EOL
            . 'reason: ' . json_encode($this->check_result) . PHP_EOL);
        fclose($file);
    }

    function checkIsBanned()
    {
        // опишите процесс проверки того, что пользователь уже забанен.
        $is_banned = false; // из логов по user_id смотреть, совершал ли пользователь действия, которые ведут к бану, в последние 15 минут
        if ($is_banned) {
            $this->check_value++;
            $this->check_result[] = array("pattern-type" => 'was-banned',
                "user-id" => $this->user_id);
        }
    }

    function checkUserAgent()
    {
        foreach ($this->patterns['user-agent'] as $pattern) {
            if (preg_match($pattern, $_SERVER['HTTP_USER_AGENT'])) {
                $this->check_result[] = array("pattern-type" => 'user-agent',
                    "pattern" => $pattern,
                    "user-agent" => $_SERVER['HTTP_USER_AGENT']);
                $this->check_value++;
            }
        }
    }

    function checkRequest()
    {

        foreach ($_GET as $k => $value) {
            $this->checkValue($k, $value, 'get');
        }
        foreach ($_POST as $k => $value) {
            $this->checkValue($k, $value, 'post');
        }
        $this->checkValue('HTTP_USER_AGENT', $_SERVER['HTTP_USER_AGENT'], 'user-agent');

        if (isset($_SERVER['HTTP_X_ORIGINAL_URI'])) {
            $this->checkValue('HTTP_X_ORIGINAL_URI', $_SERVER['HTTP_X_ORIGINAL_URI'], 'original-url');
        }
    }

    function checkValue($key, $value, $type = 'get')
    {
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                $this->checkValue($k, $v, $type);
            }
        } else {
            foreach ($this->patterns['request'] as $pattern => $weight) {

                if (preg_match($pattern, $value)) {
                    $this->check_result[] = array("pattern-type" => 'request-' . $type,
                        "pattern" => $pattern,
                        "key" => $key,
                        "value" => $value);
                    $this->check_value += $weight;
                }

                if (preg_match($pattern, $key)) {
                    $this->check_result[] = array("pattern-type" => 'request-' . $type,
                        "pattern" => $pattern,
                        "key" => $key,
                        "value" => $value);
                    $this->check_value += $weight;
                }
            }
        }
    }
}
