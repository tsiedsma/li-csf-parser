<?php
namespace LithiumDev\CSFParser;


use Carbon\Carbon;

/**
 * Class CSFParser
 * @package LithiumDev\CSFParser
 */
class CSFParser {

    /**
     * @var string
     */
    protected $rawCSFLogData = '';
    /**
     * @var string
     */
    protected $cleanCSFLogData = '';
    /**
     * @var array
     */
    protected $parsedData = [
        'ip'     => null,
        'host'   => null,
        'reason' => null,
        'count'  => null,
        'date'   => null,
    ];
    /**
     * @var bool|false
     */
    protected $hostnameCheck = false;
    /**
     * @var string
     */
    protected $timeZone = 'America/New_York';

    /**
     * @param            $csf_log_data
     * @param bool|false $hostnameCheck
     *
     * @throws \Exception
     */
    public function __construct($csf_log_data, $hostnameCheck = false)
    {
        if (! is_string($csf_log_data))
        {
            throw new \Exception('Cannot parse data, string expected and ' . gettype($this->parsedData) . ' received.');
        }

        if (empty($csf_log_data))
        {
            throw new \Exception('Cannot parse data, string expected and nothing received');
        }

        $this->hostnameCheck = $hostnameCheck;

        $this->rawCSFLogData = $csf_log_data;

        return $this;
    }

    /**
     * @param $timezone
     *
     * @return $this
     */
    public function setTimeZone($timezone)
    {
        $this->timeZone = $timezone;

        return $this;
    }

    /**
     * @return array
     */
    public function parse()
    {
        $this->cleanCSFLogData = $this->sanitizeLogData();

        $this->parsedData = $this->processLines();

        return $this->getParsedData();
    }

    /**
     * @return string
     */
    private function sanitizeLogData()
    {
        $lines = explode("\n", $this->rawCSFLogData);
        $newLines = [];
        foreach ($lines as $line)
        {
            $line = trim(rtrim($line));

            if (empty($line))
            {
                continue;
            }

            if (substr($line, 0, 1) === '#')
            {
                continue;
            }

            $newLines[] = $line;
        }

        return implode("\n", $newLines);
    }

    /**
     * @return array
     * @throws \Exception
     */
    private function processLines()
    {
        $parsed = [];

        if (empty($this->cleanCSFLogData))
        {
            throw new \Exception('Cannot parse data, empty string received.');
        }

        $lines = explode("\n", $this->cleanCSFLogData);
        foreach ($lines as $line)
        {
            if ($this->isModSecurity($line))
            {
                $parsed[] = $this->parseModSecurity($line);
            }
            else if (preg_match('/(\([sshd|cpanel|ftpd|pop3d|imapd|htaccess]+\))/', $line))
            {
                $parsed[] = $this->parseLoginFailure($line);
            }
            else if ($this->isManualEntry($line))
            {
                $parsed[] = $this->parseManualEntry($line);
            }
        }

        $this->parsedData = $parsed;

        return $this->parsedData;
    }

    /**
     * @param $line
     *
     * @return bool
     */
    private function isModSecurity($line)
    {
        return (false !== strstr($line, 'mod_security'));
    }

    /**
     * @param $line
     *
     * @return array
     * @throws \Exception
     */
    private function parseModSecurity($line)
    {
        $split1 = $this->splitString($line, '#');
        $ip = $split1[0];
        $host = $this->hostnameCheck ? gethostbyaddr($ip) : null;

        $split2 = $this->splitString($split1[1], ': ');
        $reasons = preg_match('/(mod_security)\s(\(id:\d{2,9})\)+\s(triggered)/', $split2[1], $matches);
        $reason = str_replace('(id:', 'rule id:', $matches[0]);
        $reason = str_replace(')', '', $reason);

        $split3 = $this->splitString($split2[2], ' - ');

        $countString = trim(rtrim($split3[0]));
        $countStringPos = strpos($countString, ' in the');
        $count = substr($countString, 0, $countStringPos);

        $date = Carbon::parse($split3[1], $this->timeZone);

        return [
            'ip'     => $ip,
            'host'   => ($host != $ip) ? $host : null,
            'reason' => $reason,
            'count'  => (int) $count,
            'date'   => $date->toDateTimeString(),
        ];
    }

    /**
     * @param $string
     * @param $split
     *
     * @return array
     * @throws \Exception
     */
    private function splitString($string, $split)
    {
        $return = [];
        if (! strstr($string, $split))
        {
            throw new \Exception('Cannot split string, "' . $split . '"" not found in "' . $string . '"');
        }

        $split = explode($split, $string);
        foreach ($split as $item)
        {
            $return[] = trim(rtrim($item));
        }

        return $return;
    }

    /**
     * @param $line
     *
     * @return array
     * @throws \Exception
     */
    private function parseLoginFailure($line)
    {
        $split1 = $this->splitString($line, '#');
        $ip = $split1[0];
        $host = $this->hostnameCheck ? gethostbyaddr($ip) : null;

        $split2 = $this->splitString($split1[1], ': ');
        $reason = $split2[1];

        $reason = $this->findTextBetween($reason, ')', ' from');

        $split3 = $this->splitString($split2[2], ' - ');

        $countString = trim(rtrim($split3[0]));
        $countStringPos = strpos($countString, ' in the');
        $count = substr($countString, 0, $countStringPos);

        $date = Carbon::parse($split3[1], $this->timeZone);

        return [
            'ip'     => $ip,
            'host'   => ($host != $ip) ? $host : null,
            'reason' => $reason,
            'count'  => (int) $count,
            'date'   => $date->toDateTimeString(),
        ];
    }

    /**
     * @param $string
     * @param $start_tag
     * @param $end_tag
     *
     * @return null|string
     */
    private function findTextBetween($string, $start_tag, $end_tag)
    {
        $startpos = strpos($string, $start_tag) + strlen($start_tag);
        if ($startpos !== false)
        {
            $endpos = strpos($string, $end_tag, $startpos);
            if ($endpos !== false)
            {
                $value = substr($string, $startpos, $endpos - $startpos);

                return trim(rtrim($value));
            }
        }

        return null;
    }

    /**
     * @param $line
     *
     * @return bool
     */
    private function isManualEntry($line)
    {
        if (false !== strstr($line, 'Manually denied'))
        {
            return true;
        }

        if (false === strstr($line, 'lfd'))
        {
            return true;
        }

        return false;
    }

    /**
     * @param $line
     *
     * @return array
     * @throws \Exception
     */
    private function parseManualEntry($line)
    {
        $split1 = $this->splitString($line, '#');
        $ip = $split1[0];

        $host = (false !== ip2long($ip) && $this->hostnameCheck) ? gethostbyaddr($ip) : null;

        $split2 = $this->splitString($split1[1], ' - ');
        $reason = (false === strstr($split2[0], 'Manually denied:')) ? $split2[0] : null;

        $date = Carbon::parse($split2[1], $this->timeZone);

        return [
            'ip'     => $ip,
            'host'   => ($host != $ip) ? $host : null,
            'reason' => $reason,
            'count'  => 1,
            'date'   => $date->toDateTimeString(),
        ];
    }

    /**
     * @return array
     */
    private function getParsedData()
    {
        return $this->parsedData;
    }
}