<?php


$scan_signatures    = null;
$clean_signatures   = null;
$start_time         = time();
$print              = true;
$report             = null;
$lic                = null;
$detached           = null;

if (!isset($argv)) {
    $argv = $_SERVER['argv'];
}

$config = new MDSConfig();
$cli = new MDSCliParse($argv, $config);

Factory::configure($config->get(MDSConfig::PARAM_FACTORY_CONFIG));

if (!$config->get(MDSConfig::PARAM_DO_NOT_SEND_STATS)) {
    $lic = Factory::instance()->create(ImLicense::class, ['/var/imunify360/license.json', '/opt/alt/python35/share/imunify360/cln-pub.key']);
    if (!$lic->isValid()) {
        $config->set(MDSConfig::PARAM_DO_NOT_SEND_STATS, true);
    }
}

if ($config->get(MDSConfig::PARAM_SEARCH_CONFIGS) !== '') {
    $filter = new MDSCMSConfigFilter();
    $finder = new Finder($filter, $config->get(MDSConfig::PARAM_SEARCH_DEPTH));
    $creds = new MDSDBCredsFromConfig($finder, $config->get(MDSConfig::PARAM_SEARCH_CONFIGS));
    $tty = true;
    if (function_exists('stream_isatty') && !@stream_isatty(STDOUT)) {
        $tty = false;
    }
    if ($tty) {
        $creds->printCreds();
    } else {
        $creds->printForXArgs();
    }
    exit(0);
}

echo 'MDS - an Intelligent Malware Database Scanner for Websites.' . PHP_EOL;

$log_levels = explode(',', $config->get(MDSConfig::PARAM_LOG_LEVEL));
$log = new Logger($config->get(MDSConfig::PARAM_LOG_FILE), $log_levels);
$log->info('MDS: start');

$state = null;
$state_filepath = $config->get(MDSConfig::PARAM_STATE_FILEPATH);
if ($state_filepath) {
    $state = new MDSState($state_filepath);
    $state->setWorking();
}

set_exception_handler(function ($ex) use ($report, $print) {
    if ($ex instanceof MDSException) {
        if (isset($report) && $report->getError() === null) {
            $report->addError($ex->getErrCode(), $ex->getErrMsg());
            $report->save();
        }
        if ($print) {
            print('Error: ' . $ex->getErrMsg() . PHP_EOL);
        }
        exit($ex->getErrCode());
    } else {
        echo $ex->getMessage();
        exit(-1);
    }
});

$progress = new MDSProgress($config->get(MDSConfig::PARAM_PROGRESS));
$progress->setPrint(
    function ($text) {
        $text = str_pad($text, 160, ' ', STR_PAD_RIGHT);
        echo str_repeat(chr(8), 160) . $text;
    }
);

$tables_config = new MDSTablesConfig(__DIR__ . '/mds_tables.config.json');

if (is_string($config->get(MDSConfig::PARAM_AVD_APP))) {
    $config->set(MDSConfig::PARAM_AVD_APP, [$config->get(MDSConfig::PARAM_AVD_APP)]);
} else {
    $config->set(MDSConfig::PARAM_AVD_APP, $tables_config->getSupportedApplications());
}

if (is_string($config->get(MDSConfig::PARAM_AVD_PATH)) && substr($config->get(MDSConfig::PARAM_AVD_PATH), -1) == DIRECTORY_SEPARATOR) {
    $config->set(MDSConfig::PARAM_AVD_PATH, substr($config->get(MDSConfig::PARAM_AVD_PATH), 0, -1));
}

if ($config->get(MDSConfig::PARAM_AVD_PATHS) && file_exists($config->get(MDSConfig::PARAM_AVD_PATHS))) {
    $paths = file($config->get(MDSConfig::PARAM_AVD_PATHS), FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);
    foreach ($paths as &$path) {
        $path = base64_decode($path);
        if (substr($path, -1) == DIRECTORY_SEPARATOR) {
            $path = substr($path, 0, -1);
        }
    }
    $config->set(MDSConfig::PARAM_AVD_PATHS, $paths);
}

$creds = getCreds($config, $argc, $argv, $progress);

$prescan ='';
if (file_exists(__DIR__ . '/mds_prescan.config.bin')) {
    $prescan = trim(file_get_contents(__DIR__ . '/mds_prescan.config.bin'));
} else {
    throw new MDSException(MDSErrors::MDS_PRESCAN_CONFIG_ERROR, __DIR__ . '/mds_prescan.config.bin');
}

list($scan_signatures, $clean_db) = loadMalwareSigns($config);

if ($config->get(MDSConfig::PARAM_DETACHED)) {
    $detached = Factory::instance()->create(MDSDetachedMode::class, [$config->get(MDSConfig::PARAM_DETACHED)]);
    $config->set(MDSConfig::PARAM_DO_NOT_SEND_STATS, true);
}

$filter = new MDSAVDPathFilter($config->get(MDSConfig::PARAM_IGNORELIST));

$scanned = 0;

foreach($creds as $i => $cred) {
    if (($cred === false) || (isset($cred['db_path']) && $filter && MDSConfig::PARAM_AVD_PATH && !$filter->needToScan($cred['db_path']))) {
        continue;
    }
    $config->set(MDSConfig::PARAM_HOST, gethostbyname($cred['db_host']));
    $config->set(MDSConfig::PARAM_PORT, $cred['db_port']);
    $config->set(MDSConfig::PARAM_LOGIN, $cred['db_user']);
    $config->set(MDSConfig::PARAM_PASSWORD, $cred['db_pass']);
    $config->set(MDSConfig::PARAM_DATABASE, $cred['db_name']);
    $config->set(MDSConfig::PARAM_PREFIX, $cred['db_prefix']);

    if ($config->get(MDSConfig::PARAM_OVERRIDE_PORT)) {
        $config->set(MDSConfig::PARAM_PORT, $config->get(MDSConfig::PARAM_OVERRIDE_PORT));
    }
    if ($config->get(MDSConfig::PARAM_OVERRIDE_HOST)) {
        $config->set(MDSConfig::PARAM_HOST, $config->get(MDSConfig::PARAM_OVERRIDE_HOST));
    }

    scanDB($config, $scan_signatures, $progress, $log, $tables_config, $prescan, $clean_db, $state, $lic, $i, $detached, $cred);
    if ($config->get(MDSConfig::PARAM_RESTORE) && $config->get(MDSConfig::PARAM_DETACHED)) {
        $config->set(MDSConfig::PARAM_RESCAN, true);
        $config->set(MDSConfig::PARAM_SCAN, true);
        $config->set(MDSConfig::PARAM_RESTORE, false);
        scanDB($config, $scan_signatures, $progress, $log, $tables_config, $prescan, $clean_db, $state, $lic, $i, $detached, $cred);
    }
    $scanned++;
}

if ($scanned === 0 && !$detached) {
    throw new MDSException(MDSErrors::MDS_NO_SCANNED);
}

if ($detached) {
    if ($scanned === 0) {
        $report = new MDSJSONReport(
            time(),
            $detached->getWorkDir() . '/' . 'report0.json',
            '0.001-dev',
            isset($scan_signatures) ? $scan_signatures->getDBMetaInfoVersion() : '',
            '',
            '',
            '',
            ''
        );
        setOpFromConfig($config, $report);
        $report->setPath(null);
        $report->setApp(null);
        $report->save();
    }
    $detached->complete();
}

if ($state && !$state->isCanceled()) {
    $state->setDone();
}

exit(0);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function getCreds($config, $argc, $argv, $progress)
{
    $creds = [];
    if ($config->get(MDSConfig::PARAM_AVD_PATH) || $config->get(MDSConfig::PARAM_AVD_PATHS)) {
        $avd_creds = Factory::instance()->create(MDSDBCredsFromAVD::class);
        $recursive = $config->get(MDSConfig::PARAM_SCAN);
        $paths = $config->get(MDSConfig::PARAM_AVD_PATHS) ? $config->get(MDSConfig::PARAM_AVD_PATHS) : [$config->get(MDSConfig::PARAM_AVD_PATH)];
        $avd_creds->countApps($paths, $config->get(MDSConfig::PARAM_AVD_APP), $recursive);
        $creds = $avd_creds->getCredsFromApps($paths, $config->get(MDSConfig::PARAM_AVD_APP), $recursive);
        $progress->setDbCount($avd_creds->getAppsCount());
    } elseif ($config->get(MDSConfig::PARAM_CREDS_FROM_XARGS)) {
        $creds_xargs = explode(';;', $argv[$argc - 1]);
        $creds[] = [
            'db_host'   => $creds_xargs[0],
            'db_port'   => $creds_xargs[1],
            'db_user'   => $creds_xargs[2],
            'db_pass'   => $creds_xargs[3],
            'db_name'   => $creds_xargs[4],
            'db_prefix' => $creds_xargs[5],
        ];
        $progress->setDbCount(1);
    } else {
        $password = $config->get(MDSConfig::PARAM_PASSWORD);
        if ($config->get(MDSConfig::PARAM_PASSWORD_FROM_STDIN)) {
            $f = @fopen('php://stdin', 'r');
            echo "Enter password for db:" . PHP_EOL;
            $password = str_replace("\n","", fgets($f));
            fclose($f);
        }
        $creds[] = [
            'db_host'   => $config->get(MDSConfig::PARAM_HOST),
            'db_port'   => $config->get(MDSConfig::PARAM_PORT),
            'db_user'   => $config->get(MDSConfig::PARAM_LOGIN),
            'db_pass'   => $password,
            'db_name'   => $config->get(MDSConfig::PARAM_DATABASE),
            'db_prefix' => $config->get(MDSConfig::PARAM_PREFIX),
        ];
        $progress->setDbCount(1);
    }
    return $creds;
}

function scanDB($config, $scan_signatures, $progress, $log, $tables_config, $prescan, $clean_db, $state, $lic, $i, $detached, $cred)
{
    try {
        $backup = null;
        if (empty($config->get(MDSConfig::PARAM_DATABASE))) {
            throw new MDSException(MDSErrors::MDS_NO_DATABASE);
        }

        if ($progress->getDbCount() > 1 && !$config->get(MDSConfig::PARAM_SCAN)) {
            throw new MDSException(MDSErrors::MDS_MULTIPLE_DBS);
        }

        $progress->setCurrentDb($i, $config->get(MDSConfig::PARAM_DATABASE));

        $log->info('MDS DB scan: started ' . $config->get(MDSConfig::PARAM_DATABASE));

        $report_filename = 'dbscan-' . $config->get(MDSConfig::PARAM_DATABASE) . '-' . $config->get(MDSConfig::PARAM_LOGIN) . '-' . time() . '.json';


        if ($config->get(MDSConfig::PARAM_DETACHED) && !$config->get(MDSConfig::PARAM_RESTORE)) {
            $config->set(MDSConfig::PARAM_REPORT_FILE, $detached->getWorkDir() . '/' . 'report' . $i . '.json');
        }

        if ($config->get(MDSConfig::PARAM_DETACHED) && $config->get(MDSConfig::PARAM_RESTORE)) {
            $config->set(MDSConfig::PARAM_REPORT_FILE, $detached->getWorkDir() . '/' . 'report' . $i . '_restore.json');
        }

        if ($config->get(MDSConfig::PARAM_DETACHED) && $config->get(MDSConfig::PARAM_RESCAN)) {
            $config->set(MDSConfig::PARAM_REPORT_FILE, $detached->getWorkDir() . '/' . 'report' . $i . '_rescan.json');
        }

        if (!$config->get(MDSConfig::PARAM_REPORT_FILE)) {
            $report_file = __DIR__ . '/' . $report_filename;
        } else {
            if (is_dir($config->get(MDSConfig::PARAM_REPORT_FILE))) {
                $report_file = $config->get(MDSConfig::PARAM_REPORT_FILE) . '/' . $report_filename;
            } else {
                $report_file = $config->get(MDSConfig::PARAM_REPORT_FILE);
            }
        }

        $report = new MDSJSONReport(
            time(),
            $report_file,
            '0.001-dev',
            isset($scan_signatures) ? $scan_signatures->getDBMetaInfoVersion() : '',
            $config->get(MDSConfig::PARAM_HOST),
            $config->get(MDSConfig::PARAM_DATABASE),
            $config->get(MDSConfig::PARAM_LOGIN),
            $config->get(MDSConfig::PARAM_PORT)
        );

        if ($report->getError() !== null) {
            throw $report->getError();
        }

        $report->setMalwareDbVer($scan_signatures->getDBMetaInfoVersion());

        setOpFromConfig($config, $report);

        $report->setScanId($config->get(MDSConfig::PARAM_DETACHED));

        if (isset($cred['db_app'])) {
            $report->setApp($cred['db_app']);
        }

        if (isset($cred['app_owner_uid'])) {
            $report->setAppOwnerUId($cred['app_owner_uid']);
        }

        if (isset($cred['db_path'])) {
            $report->setPath($cred['db_path']);
        }

        if ($config->get(MDSConfig::PARAM_CLEAN)) {
            $backup = new MDSBackup($config->get(MDSConfig::PARAM_BACKUP_FILEPATH));
        }

        mysqli_report(MYSQLI_REPORT_STRICT);
        $db_connection = mysqli_init();
        $db_connection->options(MYSQLI_OPT_CONNECT_TIMEOUT, $config->get(MDSConfig::PARAM_DB_TIMEOUT));
        $db_connection->options(MYSQLI_OPT_READ_TIMEOUT, $config->get(MDSConfig::PARAM_DB_TIMEOUT));
        if (!$db_connection->real_connect($config->get(MDSConfig::PARAM_HOST), $config->get(MDSConfig::PARAM_LOGIN),
            $config->get(MDSConfig::PARAM_PASSWORD),
            $config->get(MDSConfig::PARAM_DATABASE), $config->get(MDSConfig::PARAM_PORT))) {
            $log->error('Can\'t connect to database: ' . $db_connection->connect_error);
            throw new MDSException(MDSErrors::MDS_CONNECT_ERROR, $db_connection->connect_error);
        }

        $mds_find = new MDSFindTables($db_connection, $tables_config);

        if (!$config->get(MDSConfig::PARAM_DONT_SEND_UNK_URLS)) {
            $report->setUnknownUrlsSend(new MDSSendUrls(Factory::instance()->create(MDSCollectUrlsRequest::class)));
        }

        if ($config->get(MDSConfig::PARAM_CLEAN) || $config->get(MDSConfig::PARAM_SCAN)) {
            MDSScanner::scan($prescan, $config->get(MDSConfig::PARAM_DATABASE), $config->get(MDSConfig::PARAM_PREFIX),
                $mds_find, $db_connection, $scan_signatures,
                $config->get(MDSConfig::PARAM_MAX_CLEAN_BATCH), $clean_db, $progress, $state, $report, $backup,
                $config->get(MDSConfig::PARAM_SCAN), $config->get(MDSConfig::PARAM_CLEAN), $log);
        }

        if ($config->get(MDSConfig::PARAM_RESTORE)) {
            $report->setOp(MDSJSONReport::OP_RESTORE);
            $restore = new MDSRestore($config->get(MDSConfig::PARAM_RESTORE), $db_connection, $progress, $report,
                $state,
                $log);
            $restore->restore($config->get(MDSConfig::PARAM_MAX_RESTORE_BATCH));
            $restore->finish();
        }

        $ch = null;
        if (!$config->get(MDSConfig::PARAM_DO_NOT_SEND_STATS)) {
            $request = new MDSCHRequest();
            $ch = Factory::instance()->create(MDSSendToCH::class, [$request, $lic]);
        }

        if ($report) {
            $report->setCH($ch);
            $report->save();
        }

        $db_connection->close();
        $log->info('MDS DB scan: finished ' . $config->get(MDSConfig::PARAM_DATABASE));

    } catch (MDSException $ex) {
        onError($detached, $progress, $report, $ex);
    } catch (mysqli_sql_exception $e) {
        $ex = new MDSException(MDSErrors::MDS_CONNECT_ERROR, $config->get(MDSConfig::PARAM_LOGIN) . '@' . $config->get(MDSConfig::PARAM_HOST));
        onError($detached, $progress, $report, $ex);
    }
}

function onError($detached, $progress, $report, $ex)
{
    if ((isset($detached) || ($progress->getDbCount() > 1)) && (isset($report) && $report->getError() === null)) {
        $report->setPath(null);
        $report->setApp(null);
        $report->addError($ex->getErrCode(), $ex->getErrMsg());
        $report->save();
    } else {
        throw $ex;
    }
}

function setOpFromConfig($config, $report)
{
    if ($config->get(MDSConfig::PARAM_SCAN)) {
        $report->setOp(MDSJSONReport::OP_SCAN);
    } else if ($config->get(MDSConfig::PARAM_CLEAN)) {
        $report->setOp(MDSJSONReport::OP_CLEAN);
    } else if ($config->get(MDSConfig::PARAM_RESTORE)) {
        $report->setOp(MDSJSONReport::OP_RESTORE);
    }
}

function loadMalwareSigns($config)
{
    $scan_signatures = null;
    $clean_signatures = null;

    if ($config->get(MDSConfig::PARAM_SCAN) || $config->get(MDSConfig::PARAM_CLEAN) || $config->get(MDSConfig::PARAM_RESTORE)) {
        $avdb = trim($config->get(MDSConfig::PARAM_AV_DB));
        $scan_signatures = new LoadSignaturesForScan($avdb, 2, 0);
        if ($scan_signatures->getResult() == LoadSignaturesForScan::SIGN_EXTERNAL) {
            echo 'Loaded external scan signatures from ' . $avdb . PHP_EOL;
        }
        $sign_count = $scan_signatures->getDBCount();
        echo 'Malware scan signatures: ' . $sign_count . PHP_EOL;

        $scan_signatures->blackUrls = new MDSUrls(__DIR__ . '/blacklistedUrls.db');
        $scan_signatures->whiteUrls = new MDSUrls(__DIR__ . '/whitelistUrls.db');

        if ($config->get(MDSConfig::PARAM_CLEAN)) {
            $procudb = trim($config->get(MDSConfig::PARAM_PROCU_DB));
            $clean_signatures = new LoadSignaturesForClean('', $procudb);
            if ($clean_signatures->getDBLocation() == 'external') {
                echo 'Loaded external clean signatures from ' . $procudb . PHP_EOL;
            }
            $clean_db = $clean_signatures->getDB();
            $clean_signatures->setScanDB($scan_signatures);
            echo 'Malware clean signatures: ' . count($clean_db) . PHP_EOL;
        }
        echo PHP_EOL;
    }
    return [$scan_signatures, $clean_signatures];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/**
 * Class Factory.
 */
class Factory
{
    /**
     * @var Factory
     */
    private static $instance;
    /**
     * @var array
     */
    private static $config;

    /**
     * Factory constructor.
     *
     * @throws Exception
     */
    private function __construct()
    {

    }

    /**
     * Instantiate and return a factory.
     *
     * @return Factory
     * @throws Exception
     */
    public static function instance()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Configure a factory.
     *
     * This method can be called only once.
     *
     * @param array $config
     * @throws Exception
     */
    public static function configure($config = [])
    {
        if (self::isConfigured()) {
            throw new Exception('The Factory::configure() method can be called only once.');
        }

        self::$config = $config;
    }

    /**
     * Return whether a factory is configured or not.
     *
     * @return bool
     */
    public static function isConfigured()
    {
        return self::$config !== null;
    }

    /**
     * Creates and returns an instance of a particular class.
     *
     * @param string $class
     *
     * @param array $constructorArgs
     * @return mixed
     * @throws Exception
     */
    public function create($class, $constructorArgs = [])
    {
        if (!isset(self::$config[$class])) {
            throw new Exception("The factory is not contains configuration for '{$class}'.");
        }

        if (is_callable(self::$config[$class])) {
            return call_user_func(self::$config[$class], $constructorArgs);
        } else {
            return new self::$config[$class](...$constructorArgs);
        }
    }
}
class Config
{
    /**
     * @var array Configuration data 
     */
    private $config     = [];

    /**
     * Returns valued of a particular option.
     *
     * @param string $key
     * @return mixed
     * @throws Exception
     */
    public function get($key)
    {
        if (!array_key_exists($key, $this->config)) {
            throw new Exception('An invalid option requested. Key: ' . $key);
        }
        return $this->config[$key];
    }

    /**
     * Set value to config by key
     *
     * @param string $key
     * @param mixed $value
     * @return mixed
     * @throws Exception
     */
    public function set($key, $value)
    {
        $this->config[$key] = $value;
    }

    /**
     * Set default config
     *
     * @param array $defaults
     */
    protected function setDefaultConfig($defaults)
    {
        $this->config = $defaults;
    }
}
class MDSConfig extends Config
{
    const PARAM_HELP                = 'help';
    const PARAM_VERSION             = 'version';
    const PARAM_HOST                = 'host';
    const PARAM_PORT                = 'port';
    const PARAM_LOGIN               = 'login';
    const PARAM_PASSWORD            = 'password';
    const PARAM_PASSWORD_FROM_STDIN = 'password-from-stdin';
    const PARAM_DATABASE            = 'database';
    const PARAM_PREFIX              = 'prefix';
    const PARAM_SCAN                = 'scan';
    const PARAM_CLEAN               = 'clean';
    const PARAM_REPORT_FILE         = 'report-file';
    const PARAM_SIGDB               = 'signature-db';
    const PARAM_PROGRESS            = 'progress';
    const PARAM_FACTORY_CONFIG      = 'factory-config';
    const PARAM_AV_DB               = 'avdb';
    const PARAM_PROCU_DB            = 'procudb';
    const PARAM_SHARED_MEM          = 'shared-mem-progress';
    const PARAM_SHARED_MEM_CREATE   = 'create-shared-mem';
    const PARAM_STATE_FILEPATH      = 'state-file';
    const PARAM_MAX_CLEAN_BATCH     = 'max-clean';
    const PARAM_MAX_RESTORE_BATCH   = 'max-restore';
    const PARAM_RESTORE             = 'restore';
    const PARAM_LOG_FILE            = 'log-file';
    const PARAM_BACKUP_FILEPATH     = 'backup-file';
    const PARAM_LOG_LEVEL           = 'log-level';
    const PARAM_DONT_SEND_UNK_URLS  = 'do-not-send-urls';
    const PARAM_SEARCH_CONFIGS      = 'search-configs';
    const PARAM_SEARCH_DEPTH        = 'search-depth';
    const PARAM_CREDS_FROM_XARGS    = 'creds-from-xargs';
    const PARAM_OVERRIDE_PORT       = 'override_port';
    const PARAM_OVERRIDE_HOST       = 'override_host';
    const PARAM_DO_NOT_SEND_STATS   = 'do-not-send-stats';
    const PARAM_DB_TIMEOUT          = 'db-timeout';
    const PARAM_DETACHED            = 'detached';
    const PARAM_AVD_APP             = 'app-name';
    const PARAM_AVD_PATH            = 'path';
    const PARAM_AVD_PATHS           = 'paths';
    const PARAM_RESCAN              = 'rescan';
    const PARAM_IGNORELIST          = 'ignore-list';

    /**
     * @var array Default config
     */
    protected $defaultConfig = [
        self::PARAM_HELP                => false,
        self::PARAM_VERSION             => false,
        self::PARAM_SCAN                => false,
        self::PARAM_CLEAN               => false,
        self::PARAM_HOST                => '127.0.0.1',
        self::PARAM_PORT                => 3306,
        self::PARAM_LOGIN               => null,
        self::PARAM_PASSWORD            => null,
        self::PARAM_PASSWORD_FROM_STDIN => false,
        self::PARAM_DATABASE            => null,
        self::PARAM_PREFIX              => null,
        self::PARAM_REPORT_FILE         => null,
        self::PARAM_SIGDB               => null,
        self::PARAM_PROGRESS            => null,
        self::PARAM_FACTORY_CONFIG      => [
            MDSDetachedMode::class          => MDSDetachedMode::class,
            MDSDBCredsFromAVD::class        => MDSDBCredsFromAVD::class,
            ImLicense::class                => ImLicense::class,
            MDSSendToCH::class              => MDSSendToCH::class,
            MDSCollectUrlsRequest::class    => MDSCollectUrlsRequest::class,
        ],
        self::PARAM_AV_DB               => null,
        self::PARAM_PROCU_DB            => null,
        self::PARAM_SHARED_MEM          => false,
        self::PARAM_SHARED_MEM_CREATE   => false,
        self::PARAM_STATE_FILEPATH      => null,
        self::PARAM_MAX_CLEAN_BATCH     => 100,
        self::PARAM_MAX_RESTORE_BATCH   => 100,
        self::PARAM_RESTORE             => null,
        self::PARAM_LOG_FILE            => null,
        self::PARAM_LOG_LEVEL           => 'INFO',
        self::PARAM_DONT_SEND_UNK_URLS  => false,
        self::PARAM_SEARCH_CONFIGS      => '',
        self::PARAM_SEARCH_DEPTH        => 3,
        self::PARAM_CREDS_FROM_XARGS    => false,
        self::PARAM_OVERRIDE_PORT       => false,
        self::PARAM_OVERRIDE_HOST       => false,
        self::PARAM_BACKUP_FILEPATH     => '',
        self::PARAM_DO_NOT_SEND_STATS   => false,
        self::PARAM_DB_TIMEOUT          => 15,
        self::PARAM_DETACHED            => false,
        self::PARAM_AVD_APP             => false,
        self::PARAM_AVD_PATH            => false,
        self::PARAM_AVD_PATHS           => false,
        self::PARAM_RESCAN              => false,
        self::PARAM_IGNORELIST          => false,
    ];

    /**
     * Construct
     */
    public function __construct() 
    {
        $this->setDefaultConfig($this->defaultConfig);
    }
}
/*
 * Abstract class for parse cli command
 */
abstract class CliParse
{
    /**
     * @var Config Config for fill
     */
    protected $config = null;
    
    /**
     * @var array List of options. Example of one element: ['short' => 'v', 'long' => 'version,ver', 'needValue' => false]
     */
    protected $opts     = [];
    
    /**
     * @var array Current of options from $argv
     */
    private $options    = [];
    
    /**
     * @var array Arguments left after getopt() processing
     */
    private $freeAgrs   = [];
    
    /**
     * Construct
     *
     * @param array $argv
     * @param Config $config
     * @throws Exception
     */
    public function __construct($argv, Config $config)
    {
        $this->config   = $config;
        $cliLongOpts    = [];
        $cliShortOpts   = [];
        foreach ($this->opts as $params) {
            $postfix = $params['needValue'] ? ':' : '';
            if ($params['long']) {
                $cliLongOpts = array_merge($cliLongOpts, $this->getMultiOpts($params['long'], $params['needValue']));
            }
            if ($params['short']) {
                $cliShortOpts = array_merge($cliShortOpts, $this->getMultiOpts($params['short'], $params['needValue']));
            }
        }
        $this->parseOptions($argv, $cliShortOpts, $cliLongOpts);
        $this->parse();
    }
    
    /**
     * Parse comand line params
     */
    abstract protected function parse();

    /**
     * Checking if the parameter was used in the cli line
     *
     * @param string $paramKey
     * @return bool
     * @throws Exception
     */
    protected function issetParam($paramKey)
    {
        if (!isset($this->opts[$paramKey])) {
            throw new Exception('An invalid option requested.');
        }
        if ($this->getExistingOpt($this->opts[$paramKey]['long'])) {
            return true;
        }
        elseif ($this->getExistingOpt($this->opts[$paramKey]['short'])) {
            return true;
        }
        return false;
    }

    /**
     * Checking if the parameter was used in the cli line
     *
     * @param string $paramKey
     * @return bool
     * @throws Exception
     */
    protected function getParamValue($paramKey, $default = null)
    {
        if (!isset($this->opts[$paramKey])) {
            throw new Exception('An invalid option requested.');
        }
        $existingLongOpt = $this->getExistingOpt($this->opts[$paramKey]['long']);
        if ($existingLongOpt) {
            return $this->options[$existingLongOpt];
        }
        $existingShortOpt = $this->getExistingOpt($this->opts[$paramKey]['short']);
        if ($existingShortOpt) {
            return $this->options[$existingShortOpt];
        }
        return $default;
    }

    /**
     * Return free arguments after using getopt()
     *
     * @return array
     * @throws Exception
     */
    protected function getFreeAgrs()
    {
        return $this->freeAgrs;
    }
    
    /**
     * Parse by getopt() and fill vars: $this->options $this->freeAgrs
     * 
     * @return void
     */
    private function parseOptions($argv, $cliShortOpts, $cliLongOpts)
    {
        if (count($argv) <= 1) {
            return;
        }
        $this->options  = getopt(implode('', $cliShortOpts), $cliLongOpts);
        //$this->freeAgrs = array_slice($argv, $optind); // getopt(,,$optind) only for PHP7.1 and upper
        
        for($i = 1; $i < count($argv); $i++) {
            if (strpos($argv[$i], '-') !== 0) {
                $this->freeAgrs = array_slice($argv, $i);
                break;
            }
        }
    }    

    /**
     * Clean cli parameter
     *
     * @param string $optName Paramenter may be with ":" postfix
     * @return array
     */
    private function getCleanOptName($optName)
    {
        return str_replace(':', '', $optName);
    }
    
    /**
     * Return options with or without ":" postfix
     *
     * @param array $optString String with one or more options separated by ","
     * @param bool $addPostfix True if need add postfix
     * @return array Array list of options
     */
    private function getMultiOpts($optString, $addPostfix = false)
    {
        $opts = explode(',', $optString);
        if ($addPostfix) {
            $opts = array_map(function($value) { 
                return $value . ':';
            }, $opts);
        }
        return $opts;
    }
    
    /**
     * Return existing options from string. 
     *
     * @param string $optsString String with one or more options separated by ","
     * @return string|bool Name of finded options in getopt()
     */
    private function getExistingOpt($optsString)
    {
        $opts = $this->getMultiOpts($optsString);
        foreach ($opts as $opt) {
            if (isset($this->options[$opt])) { 
                return $opt;
            }
        }
        return false;
    }
}
/*
 * Abstract class for MDS which can parse cli command
 */
class MDSCliParse extends CliParse
{
    /**
     * @var array Project options for cli
     */
    protected $opts = [
        MDSConfig::PARAM_HELP                   => ['short' => 'h', 'long' => 'help',                   'needValue' => false],
        MDSConfig::PARAM_VERSION                => ['short' => 'v', 'long' => 'version,ver',            'needValue' => false],
        MDSConfig::PARAM_HOST                   => ['short' => '',  'long' => 'host',                   'needValue' => true],
        MDSConfig::PARAM_PORT                   => ['short' => '',  'long' => 'port',                   'needValue' => true],
        MDSConfig::PARAM_LOGIN                  => ['short' => '',  'long' => 'login',                  'needValue' => true],
        MDSConfig::PARAM_PASSWORD               => ['short' => '',  'long' => 'password',               'needValue' => true],
        MDSConfig::PARAM_PASSWORD_FROM_STDIN    => ['short' => '',  'long' => 'password-from-stdin',    'needValue' => false],
        MDSConfig::PARAM_DATABASE               => ['short' => '',  'long' => 'database',               'needValue' => true],
        MDSConfig::PARAM_PREFIX                 => ['short' => '',  'long' => 'prefix',                 'needValue' => true],
        MDSConfig::PARAM_SCAN                   => ['short' => '',  'long' => 'scan',                   'needValue' => false],
        MDSConfig::PARAM_CLEAN                  => ['short' => '',  'long' => 'clean',                  'needValue' => false],
        MDSConfig::PARAM_REPORT_FILE            => ['short' => '',  'long' => 'report-file',            'needValue' => true],
        MDSConfig::PARAM_SIGDB                  => ['short' => '',  'long' => 'signature-db',           'needValue' => true],
        MDSConfig::PARAM_PROGRESS               => ['short' => '',  'long' => 'progress',               'needValue' => true],
        MDSConfig::PARAM_AV_DB                  => ['short' => '',  'long' => 'avdb',                   'needValue' => true],
        MDSConfig::PARAM_PROCU_DB               => ['short' => '',  'long' => 'procudb',                'needValue' => true],
        MDSConfig::PARAM_SHARED_MEM             => ['short' => '',  'long' => 'shared-mem-progress',    'needValue' => true],
        MDSConfig::PARAM_SHARED_MEM_CREATE      => ['short' => '',  'long' => 'create-shared-mem',      'needValue' => false],
        MDSConfig::PARAM_STATE_FILEPATH         => ['short' => '',  'long' => 'state-file',             'needValue' => true],
        MDSConfig::PARAM_RESTORE                => ['short' => '',  'long' => 'restore',                'needValue' => true],
        MDSConfig::PARAM_LOG_FILE               => ['short' => '',  'long' => 'log-file',               'needValue' => true],
        MDSConfig::PARAM_LOG_LEVEL              => ['short' => '',  'long' => 'log-level',              'needValue' => true],
        MDSConfig::PARAM_DONT_SEND_UNK_URLS     => ['short' => '',  'long' => 'do-not-send-urls',       'needValue' => false],
        MDSConfig::PARAM_SEARCH_CONFIGS         => ['short' => '',  'long' => 'search-configs',         'needValue' => true],
        MDSConfig::PARAM_SEARCH_DEPTH           => ['short' => '',  'long' => 'search-depth',           'needValue' => true],
        MDSConfig::PARAM_CREDS_FROM_XARGS       => ['short' => '',  'long' => 'creds-from-xargs',       'needValue' => false],
        MDSConfig::PARAM_OVERRIDE_PORT          => ['short' => '',  'long' => 'override_port',          'needValue' => true],
        MDSConfig::PARAM_OVERRIDE_HOST          => ['short' => '',  'long' => 'override_host',          'needValue' => true],
        MDSConfig::PARAM_BACKUP_FILEPATH        => ['short' => '',  'long' => 'backup-file',            'needValue' => true],
        MDSConfig::PARAM_DO_NOT_SEND_STATS      => ['short' => '',  'long' => 'do-not-send-stats',      'needValue' => false],
        MDSConfig::PARAM_DB_TIMEOUT             => ['short' => '',  'long' => 'db-timeout',             'needValue' => true],
        MDSConfig::PARAM_DETACHED               => ['short' => '',  'long' => 'detached',               'needValue' => true],
        MDSConfig::PARAM_FACTORY_CONFIG         => ['short' => '',  'long' => 'factory-config',         'needValue' => true],
        MDSConfig::PARAM_AVD_APP                => ['short' => '',  'long' => 'app-name',               'needValue' => true],
        MDSConfig::PARAM_AVD_PATH               => ['short' => '',  'long' => 'path',                   'needValue' => true],
        MDSConfig::PARAM_AVD_PATHS              => ['short' => '',  'long' => 'paths',                  'needValue' => true],
        MDSConfig::PARAM_IGNORELIST             => ['short' => '',  'long' => 'ignore-list',            'needValue' => true],
    ];

    /**
     * Parse comand line params
     * 
     * @return void
     * @throws Exception
     */
    protected function parse()
    {
        foreach ($this->opts as $configName => $params) {
            $default    = $params['needValue'] ? $this->config->get($configName) : null;
            $result     = $this->getParamValue($configName, $default);
            if (!$params['needValue'] && $result === false) { // $result === false because opt without value
                $result = true;
            }
            if ($configName == MDSConfig::PARAM_FACTORY_CONFIG) {
                $file = $result;
                if (!empty($file) && @file_exists($file) && @is_readable($file) && @filesize($file) > 5) {
                    $optionalFactoryConfig = require($file);
                    $result = array_merge($this->config->get(MDSConfig::PARAM_FACTORY_CONFIG), $optionalFactoryConfig);
                }
            }
            $this->config->set($configName, $result);
        }
        
        $factoryConfig = $this->config->get(MDSConfig::PARAM_FACTORY_CONFIG);
        
        if ($this->config->get(MDSConfig::PARAM_HELP)) {
            $this->showHelp();
        }
        elseif ($this->config->get(MDSConfig::PARAM_VERSION)) {
            $this->showVersion();
        }
        elseif (!$this->config->get(MDSConfig::PARAM_SCAN) && !$this->config->get(MDSConfig::PARAM_CLEAN) && !$this->config->get(MDSConfig::PARAM_RESTORE) && !$this->config->get(MDSConfig::PARAM_SEARCH_CONFIGS) && !$this->config->get(MDSConfig::PARAM_CREDS_FROM_XARGS)) {
            $this->showHelp();
        }
        
        // here maybe re-define some of $factoryConfig elements 
        
        $this->config->set(MDSConfig::PARAM_FACTORY_CONFIG, $factoryConfig);
    }
    
    /**
     * Cli show help
     * 
     * @return void
     */
    private function showHelp()
    {
        echo <<<HELP
MDS - an Intelligent Malware Database Scanner for Websites.

Usage: php {$_SERVER['PHP_SELF']} [OPTIONS]

      --host=<host>                     Database host
      --port=<port>                     Database port
      --login=<username>                Database username
      --password=<password>             Database password
      --password-from-stdin             Get database password from stdin
      --database=<db_name>              Database name
      --prefix=<prefix>                 Prefix for table
      --scan                            Do scan
      --clean                           Do clean
      --report-file=<filepath>          Filepath where to put the report
      --signature-db=<filepath>         Filepath with signatures
      --progress=<filepath>             Filepath with progress
      --shared-mem-progress=<shmem_id>  ID of shared memory segment
      --create-shared-mem               MDS create own shared memory segment
      --state=<filepath>                Filepath with state for control task
      --backup-filepath=<filepath>      Backup file
      --avdb=<filepath>                 Filepath with ai-bolit signatures db
      --procudb=<filepath>              Filepath with procu signatures db
      --state-file=<filepath>           Filepath with info about state(content: new|working|done|canceled). You can change it on canceled
      --restore=<filepath>              Filepath to restore csv file
      --log-file=<filepath>             Filepath to log file
      --log-level=<LEVEL>               Log level (types: ERROR|DEBUG|INFO|ALL). You can use multiple by using comma (example: DEBUG,INFO)
      --do-not-send-urls                Do not send unknown urls to server for deeper analysis
      --search-configs                  Search supported CMS configs and print db credentials
      --search-depth=<depth>            Search depth for CMS configs (default: 3)
      --creds-from-xargs                Get db credentials from last free arg (template: host;;port;;user;;pass;;name)
      --do-not-send-stats               Do not send report to Imunify correlation server
      --db-timeout=<timeout>            Timeout for connect/read db in seconds
      --detached=<scan_id>              Run MDS in detached mode
      --path=<path>                     Scan/clean CMS dbs from <path> with help AppVersionDetector
      --paths=<file>                    Scan/clean CMS dbs base64 encoded paths from <file> with help AppVersionDetector
      --app-name=<app-name>             Filter AppVersionDetector dbs for scan with <app-name>. Currently supported only 'wp-core'.

  -h, --help                            Display this help and exit
  -v, --version                         Show version


HELP;
        exit(0);
    }

    /**
     * Cli show version
     * 
     * @return void
     */
    private function showVersion()
    {
        echo "Unknown\n";
        exit(0);
    }
}
/**
 * Class MDSTablesConfig for work with config file in MDS
 */
class MDSTablesConfig
{
    private $raw_config = [];

    /**
     * MDSTablesConfig constructor.
     * @param $file
     * @throws Exception
     */
    public function __construct($file)
    {
        if (empty($file) || !file_exists($file)) {
            throw new MDSException(MDSErrors::MDS_CONFIG_ERROR, $file);
        }

        $this->raw_config = json_decode(file_get_contents($file), true);
    }

    /**
     * Get all applications defined in config
     * @return array
     */
    public function getSupportedApplications()
    {
        return array_keys($this->raw_config['applications']);
    }

    /**
     * Get all tables defined in config for application
     * @param $application
     * @return array
     */
    public function getSupportedTables($application)
    {
        return isset($this->raw_config['applications'][$application]) ? array_keys($this->raw_config['applications'][$application]) : [];
    }

    /**
     * Get all fields defined in config for table in application
     * @param $application
     * @param $table
     * @return array|mixed
     */
    public function getTableFields($application, $table)
    {
        return $this->raw_config['applications'][$application][$table]['fields'] ?? [];
    }

    /**
     * Get key field defined in config for table in application
     * @param $application
     * @param $table
     * @return string
     */
    public function getTableKey($application, $table)
    {
        return $this->raw_config['applications'][$application][$table]['key'] ?? '';
    }

    /**
     * Get array of defined in config fields with key
     * @param $application
     * @param $table
     * @return array
     */
    public function getTableFieldsWithKey($application, $table)
    {
        $fields = $this->getTableFields($application, $table);
        if ($this->getTableKey($application, $table) !== '') {
            $fields[] = $this->getTableKey($application, $table);
        }
        return $fields;
    }

    /**
     * Get satisfied application table by fields and key
     * @param $fields
     * @param $key
     * @return array
     */
    public function getTableSatisfied($fields, $key)
    {
        $res = [];
        foreach($this->getSupportedApplications() as $app) {
            foreach($this->getSupportedTables($app) as $table) {
                $config_fields = $this->getTableFieldsWithKey($app, $table);
                $config_key = $this->getTableKey($app, $table);
                if ($config_key === $key && empty(array_diff($fields, $config_fields))) {
                    $res[] = ['app' => $app, 'table' => $table];
                }
            }
        }
        return $res;
    }

    /**
     * Check application defined in config
     * @param $app
     * @return bool
     */
    public function isApplicationDefined($app)
    {
        return isset($this->raw_config['applications'][$app]);
    }

    /**
     * Check table for application defined in config
     * @param $app
     * @param $table
     * @return bool
     */
    public function isTableDefined($app, $table)
    {
        return isset($this->raw_config['applications'][$app][$table]);
    }

    /**
     * @param $application
     * @param $table
     * @return array
     */
    public function getConfigForTable($application, $table)
    {
        return isset($this->raw_config['applications'][$application][$table]) ? $this->raw_config['applications'][$application][$table] : [];
    }

    /**
     * @param $application
     * @return string
     */
    public function getApplicationDomainQuery($application)
    {
        return isset($this->raw_config['applications'][$application]['domain_name']) ? $this->raw_config['applications'][$application]['domain_name'] : '';
    }
}
/**
 * Class MDSFindTables Find tables that we have in config
 */
class MDSFindTables
{
    private $db;
    private $config;

    public function __construct($db, MDSTablesConfig $config)
    {
        $this->db = $db;
        $this->config = $config;
    }

    public function find($db = null, $prefix = null)
    {
        $result = [];
        foreach ($this->config->getSupportedApplications() as $app)
        {
            foreach ($this->config->getSupportedTables($app) as $table) {
                $query = 'SELECT DISTINCT table_schema as db, table_name as tab '
                        . 'FROM information_schema.columns '
                        . 'WHERE column_name = \'' . $this->config->getTableKey($app, $table) . '\' AND column_key = \'PRI\'';
                if (isset($db)) {
                    $query .= ' AND table_schema = \'' . $db . '\'';
                }
                if (isset($prefix)) {
                    $query .= ' AND table_name LIKE \'' . $prefix . '%\'';
                }
                $fields = $this->config->getTableFields($app, $table);
                foreach($fields as $field) {
                    $query .= ' AND table_name IN (SELECT DISTINCT table_name FROM information_schema.columns WHERE column_name = \'' . $field . '\'';
                }
                $query .= str_repeat(')', count($fields));
                $query .= ';';
                $tables = $this->db->query($query);
                if ($tables->num_rows === 0) {
                    continue;
                }
                foreach($tables as $value) {
                    if (!isset($prefix)) {
                        $prefix = explode('_', $value['tab']);
                        $prefix = $prefix[0] . '_';
                    }
                    $domain_query = str_replace(['%db%', '%prefix%'], [$value['db'], $prefix], $this->config->getApplicationDomainQuery($app));
                    $domain_name_res = $this->db->query($domain_query);
                    
                    $domain_name    = '';
                    $own_url        = '';
                    if ($domain_name_res) {
                        $row = array_values($domain_name_res->fetch_row());
                        if (isset($row[0])) {
                            $own_url = $row[0];
                        }
                    }
                    if ($own_url) {
                        $domain_name = parse_url($own_url, PHP_URL_HOST);
                        $domain_name = preg_replace('~^www\.~ism', '', $domain_name);
                        $domain_name = strtolower($domain_name);
                    }
                    
                    $result[] = [
                        'config_app'    => $app,
                        'config_tab'    => $table,
                        'db'            => $value['db'],
                        'table'         => $value['tab'],
                        'prefix'        => $prefix,
                        'domain_name'   => $domain_name,
                        'config'        => $this->config->getConfigForTable($app, $table),
                    ];
                }
            }
            return $result;
        }
    }
}
/**
 * Class MDSJSONReport need for prepare and wirte JSON report
 */
class MDSJSONReport
{
    const STATUS_DETECTED   = 'detected';
    const STATUS_CLEAN      = 'clean';
    const STATUS_RESTORE    = 'restore';
    
    const STATE_DONE        = 'done';
    const STATE_CANCELED    = 'canceled';

    const OP_SCAN           = 'scan';
    const OP_CLEAN          = 'cleanup';
    const OP_RESTORE        = 'restore';
    
    private $start_time         = '';
    private $report_filename    = '';
    private $unknown_urls_send  = '';
    private $mds_version        = '';
    private $malware_db_version = '';
    private $db_host            = '';
    private $db_name            = '';
    private $db_username        = '';
    private $db_port            = 3306;
    
    private $report = [];
    private $report_url = [];
    private $unknown_urls = [];
    private $urls_counter = 0;
    
    private $table_total_rows = [];

    private $count_tables_scanned   = 0;
    private $running_time           = 0;
    private $errors                 = [];
    private $state                  = self::STATE_DONE;

    private $report_error           = null;
    
    private $uniq_tables_affected   = [];
    private $rows_infected          = 0;
    private $rows_cleaned           = 0;
    private $rows_restored          = 0;
    private $rows_with_errors       = [];
    
    private $count_of_detected_malicious_entries    = 0;
    private $count_of_cleaned_malicious_entries     = 0;
    private $operation = '';
    private $ch = null;

    private $app = null;
    private $app_owner_uid = null;
    private $path = null;
    private $scan_id = null;
    private $save_urls_limit = 5000;

    /**
     * MDSJSONReport constructor.
     * @param string $report_filename
     * @param string $mds_version
     * @param string $malware_db_version
     * @param string $db_host
     * @param string $db_name
     * @param string $db_username
     * @param string $db_port
     */
    public function __construct($start_time, $report_filename, $mds_version, $malware_db_version, $db_host, $db_name, $db_username, $db_port)
    {
        $this->start_time           = $start_time;
        $this->report_filename      = $report_filename;
        $this->mds_version          = $mds_version;
        $this->malware_db_version   = $malware_db_version;
        $this->db_host              = $db_host;
        $this->db_name              = $db_name;
        $this->db_username          = $db_username;
        $this->db_port              = $db_port;

        if (empty($report_filename) || (!file_exists($report_filename) && !is_writable(dirname($report_filename)))) {
            $this->report_error = new MDSException(MDSErrors::MDS_REPORT_ERROR, $report_filename);
        }
    }

    public function setSaveUrlsLimit($limit)
    {
        $this->save_urls_limit = $limit;
    }

    public function setMalwareDbVer($ver)
    {
        $this->malware_db_version = $ver;
    }

    public function setOp($op)
    {
        $this->operation = $op;
    }

    public function setApp($app)
    {
        $this->app = $app;
    }

    public function setAppOwnerUId($app_owner_uid)
    {
        $this->app_owner_uid = $app_owner_uid;
    }

    public function setPath($path)
    {
        $this->path = $path;
    }

    public function setScanId($scan_id)
    {
        $this->scan_id = $scan_id;
    }

    public function setCH($ch)
    {
        $this->ch = $ch;
    }

    public function getUser()
    {
        return $this->db_username;
    }

    public function getHost()
    {
        return $this->db_host;
    }


    public function getDbName()
    {
        return $this->db_name;
    }

    public function getError()
    {
        return $this->report_error;
    }

    /**
     * Set the total number of tables that we scanned
     * @param int $count
     * @return void
     */
    public function setCountTablesScanned($count)
    {
        $this->count_tables_scanned = $count;
    }

    /**
     * Set the total number of tables that we scanned
     * @param int $count
     * @return void
     */
    public function setUnknownUrlsSend($send_urls)
    {
        $this->unknown_urls_send = $send_urls;
    }

    /**
     * Set the total running time of the script
     * @param int $running_time_in_sec
     * @return void
     */
    public function setRunningTime($running_time_in_sec)
    {
        $this->running_time = $running_time_in_sec;
    }

    /**
     * Add total scanned rows for every table
     * @param string $table_name
     * @param int $count
     * @return void
     */
    public function addTotalTableRows($table_name, $count)
    {
        $this->table_total_rows[$table_name] = $count;
    }

    /**
     * Add error code and message
     * @param int $error_code
     * @param string $error_msg
     * @return void
     */
    public function addError($error_code, $error_msg)
    {
        $this->errors[] = [
            'code'      => $error_code,
            'message'   => $error_msg,
        ];
    }
    
    /**
     * Change state
     * @param string $state
     * @return void
     */
    public function setState($state)
    {
        $this->state = $state;
    }

    /**
     * Add errors
     * @param array $errors
     * @return void
     */
    public function addErrors($errors)
    {
        $this->errors = $errors;
    }
    
    /**
     * Add detected info
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param int $row_id
     * @return void
     */
    public function addDetected($signature_id, $snippet, $table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, self::STATUS_DETECTED);
        $this->rows_infected++;
    }

    /**
     * Add detected info
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param int $row_id
     * @return void
     */
    public function addDetectedUrl($signature_id, $snippet, $table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, self::STATUS_DETECTED, true);
        $this->rows_infected++;
    }

    /**
     * @param $url
     */
    public function addUnknownUrl($url)
    {
        if (!isset($this->unknown_urls[$url])) {
            $this->unknown_urls[$url] = '';
            $this->urls_counter++;
        }

        if ($this->unknown_urls_send !== '' && $this->urls_counter >= $this->save_urls_limit) {
            $this->unknown_urls_send->send(array_keys($this->unknown_urls));
            $this->urls_counter = 0;
            $this->unknown_urls = [];
        }
    }

    /**
     * Add detected error info
     * @param string $signature_id
     * @param string $snippet
     * @param string $error_code
     * @return void
     */
    public function addDetectedError($signature_id, $snippet, $table_name, $row_id, $field, $error_code)
    {
        $this->addSignatureError($signature_id, $snippet, $table_name, $row_id, $field, $error_code, self::STATUS_DETECTED);
    }

    /**
     * Add clean info
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param int $row_id
     * @return void
     */
    public function addCleaned($signature_id, $snippet, $table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, self::STATUS_CLEAN);
        $this->rows_cleaned++;
    }

    /**
     * Add clean error info
     * @param string $signature_id
     * @param string $snippet
     * @param string $error_code
     * @return void
     */
    public function addCleanedError($signature_id, $snippet, $table_name, $row_id, $field, $error_code)
    {
        $this->addSignatureError($signature_id, $snippet, $table_name, $row_id, $field, $error_code, self::STATUS_CLEAN);
    }

    /**
     * Add restored info
     * @param string $table_name
     * @param int $row_id
     * @param string $field
     * @return void
     */
    public function addRestored($table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId('', '', $table_name, $row_id, $field, self::STATUS_RESTORE);
        $this->rows_restored++;
    }

    /**
     * Add restored error info
     * @param string $error_code
     * @return void
     */
    public function addRestoredError($error_code, $table_name, $row_id, $field = '')
    {
        $this->addSignatureError('', '', $table_name, $row_id, $field, $error_code, self::STATUS_RESTORE);
    }

    /**
     * Save report
     * @return void
     */
    public function save()
    {
        $report = $this->prepareReport();
        $json = json_encode($report);
        file_put_contents($this->report_filename, $json);

        if ($this->unknown_urls_send !== '' && !empty($this->unknown_urls)) {
            $this->unknown_urls_send->send(array_keys($this->unknown_urls));
        }

        if(isset($this->ch)) {
            $this->ch->prepareData($report);
            $this->ch->send();
        }
    }
    
    // /////////////////////////////////////////////////////////////////////////

    /**
     * Prepare report data for save
     * @return array
     */
    private function prepareReport()
    {

        $report =  [
            'start_time'                            => $this->start_time,
            'scanning_engine_version'               => $this->mds_version,
            'malware_database_version'              => $this->malware_db_version,
            'count_of_tables_scanned'               => $this->count_tables_scanned,
            'count_of_tables_affected'              => count($this->uniq_tables_affected),
            'count_of_rows_infected'                => $this->rows_infected,
            'count_of_rows_cleaned'                 => $this->rows_cleaned,
            'count_of_rows_restored'                => $this->rows_restored,
            'count_of_detected_malicious_entries'   => $this->count_of_detected_malicious_entries,
            'count_of_cleaned_malicious_entries'    => $this->count_of_cleaned_malicious_entries,
            'running_time'                          => $this->running_time,
            'error_list'                            => $this->errors,
            'database_host'                         => $this->db_host,
            'database_port'                         => $this->db_port,
            'database_name'                         => $this->db_name,
            'database_username'                     => $this->db_username,
            'detailed_reports'                      => $this->processReport(),
            'detailed_urls_reports'                 => $this->processReport(true),
            'rows_with_error'                       => $this->rows_with_errors,
            'state'                                 => $this->state,
            'operation'                             => $this->operation,
            'app'                                   => $this->app,
            'app_owner_uid'                         => $this->app_owner_uid,
            'path'                                  => $this->path,
        ];
        if ($this->scan_id) {
            $report['scan_id'] = $this->scan_id;
        }
        return $report;
    }

    /**
     * @param bool $url
     * @return array
     */
    private function processReport($url = false)
    {
        if ($url) {
            $report = &$this->report_url;
        } else {
            $report = &$this->report;
        }

        $reports = [];
        foreach ($report as $signature_id => $signature_params)
        {
            if (isset($signature_params['error'])) {
                $reports[] = [
                    'sigid'     => $signature_id,
                    'snpt'      => $signature_params['snippet'],
                    'status'    => 'error',
                    'errcode'   => $signature_params['error'],
                    'tables'    => [],
                ];
                continue;
            }
            $tables_result = [];
            foreach ($signature_params['tables_info'] as $table_name => $fields) {
                $fields_data = [];
                foreach ($fields as $field => $row_ids) {
                    $fields_data[] = [
                        'field'     => $field,
                        'row_ids'   => $row_ids,
                        'row_inf'   => count($row_ids),
                    ];
                }
                if ($fields_data) {
                    $tables_result[] = [
                        'table'         => $table_name,
                        'total_rows'    => isset($this->table_total_rows[$table_name]) ? $this->table_total_rows[$table_name] : 0,
                        'fields'        => $fields_data,
                    ];
                }
            }
            $reports[] = [
                'sigid'     => $signature_id,
                'snpt'      => $signature_params['snippet'],
                'status'    => $signature_params['status'],
                'tables'    => $tables_result,
                'errcode'   => 0,
            ];
        }
        return $reports;
    }

    /**
     * General method for adding detection and clean information
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param string $row_id
     * @param string $status
     * @return void
     */
    private function addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, $status = self::STATUS_DETECTED, $url = false)
    {
        if ($url) {
            $report = &$this->report_url;
        } else {
            $report = &$this->report;
        }

        if ($this->initReportRow($signature_id, $snippet, $status, $url)) {
            if ($status == self::STATUS_DETECTED) {
                $this->count_of_detected_malicious_entries++;
            }
            elseif ($status == self::STATUS_CLEAN) {
                $this->count_of_cleaned_malicious_entries++;
            }
        }
        if (!isset($report[$signature_id]['tables_info'][$table_name])) {
            $report[$signature_id]['tables_info'][$table_name] = [];
        }
        if (!isset($report[$signature_id]['tables_info'][$table_name][$field])) {
            $report[$signature_id]['tables_info'][$table_name][$field] = [];
        }
        $report[$signature_id]['tables_info'][$table_name][$field][] = $row_id;
        $this->uniq_tables_affected[$table_name] = '';
    }

    /**
     * General method for adding detection and clean error information
     * @param string $signature_id
     * @param string $snippet
     * @param string $error_code
     * @param string $status
     * @return void
     */
    private function addSignatureError($signature_id, $snippet, $table_name, $row_id, $field, $error_code, $status = self::STATUS_DETECTED, $url = false)
    {
        if ($url) {
            $report = &$this->report_url;
        } else {
            $report = &$this->report;
        }

        $this->initReportRow($signature_id, $snippet, $status, $url);
        $report[$signature_id]['error'] = $error_code;
        if (!isset($this->rows_with_errors['tables_info'][$table_name])) {
            $this->rows_with_errors['tables_info'][$table_name] = [];
        }
        if (!isset($this->rows_with_errors['tables_info'][$table_name][$field])) {
            $this->rows_with_errors['tables_info'][$table_name][$field] = [];
        }
        $this->rows_with_errors['tables_info'][$table_name][$field][] = $row_id;
    }

    /**
     * Initiate an array element if not exists
     * @param string $signature_id
     * @param string $snippet
     * @param string $status
     * @return void
     */
    private function initReportRow($signature_id, $snippet, $status = self::STATUS_DETECTED, $url = false)
    {
        if ($url) {
            $report = &$this->report_url;
        } else {
            $report = &$this->report;
        }

        if (isset($report[$signature_id])) {
            return false;
        }
        $report[$signature_id] = [
            'snippet'       => $snippet,
            'total_rows'    => 0,
            'status'        => $status,
            'rows_infected' => 0,
            'tables_info'   => [],
            'error'         => null,
        ];
        return true;
    }
}
/**
 * Class MDSProgress module for tracking progress
 */
class MDSProgress
{
    private $total;
    private $total_table;
    private $num_tables = 1;
    private $current_table;
    private $current_table_num;
    private $current_db;
    private $current_db_num;
    private $last_file_update = 0;
    private $last_update = 0;
    private $progress_file;
    private $shared_mem;
    private $create_shared_mem;
    private $file_write_interval;
    private $update_interval;
    private $start;
    private $progress_string;
    private $tables;
    private $last_table_key;
    private $first_table_key;
    private $print = null;
    private $percent_main;
    private $db_count = 1;
    private $percent_table;

    private $one_db_percent;
    private $one_table_percent;
    private $one_record_percent;

    /**
     * MDSProgress constructor.
     * @param string $file - file for writing progress
     * @param int $update_interval - interval for update progress
     * @param int $file_write_interval - interval for writing to file progress
     * @param int $shared_mem - write to shared memory
     * @param bool $need_create_shmem - need to create shared memory
     * @throws Exception
     */
    public function __construct($file = false, $update_interval = 0, $file_write_interval = 1, $shared_mem = false, $need_create_shmem = false)
    {
        $this->start = time();
        $this->update_interval = $update_interval;
        $this->file_write_interval = $file_write_interval;
        if ($shared_mem) {
            $this->create_shared_mem = $need_create_shmem;
            if ($this->create_shared_mem) {
                @$this->shared_mem = shmop_open((int)$shared_mem, "n", 0666, 5000);
            } else {
                @$this->shared_mem = shmop_open((int)$shared_mem, "w", 0, 0);
            }
            if (empty($this->shared_mem)) {
                if ($need_create_shmem) {
                    throw new MDSException(MDSErrors::MDS_PROGRESS_SHMEM_CRT_ERROR, $shared_mem);
                } else {
                    throw new MDSException(MDSErrors::MDS_PROGRESS_SHMEM_ERROR, $shared_mem);
                }
            }
        }

        if ($file) {
            if (is_writable(dirname($file)) || (file_exists($file) && is_writable($file))) {
                $this->progress_file = $file;
            } else {
                throw new MDSException(MDSErrors::MDS_PROGRESS_FILE_ERROR, $file);
            }
        }
    }

    /**
     * @param $total - total records for scanning
     */
    public function setTotal($total)
    {
        $this->total = $total;
    }

    /**
     * @param $num_dbs - num of tables for scan
     */
    public function setDbCount($num_dbs)
    {
        $this->db_count = $num_dbs;
        $this->one_db_percent = $num_dbs ? 100 / $num_dbs : 0;
    }

    /**
     *
     */
    public function getDbCount()
    {
        return $this->db_count;
    }

    /**
     * @param $tables - array of tables for scan
     */
    public function setTables($tables)
    {
        $this->tables = $tables;
        $this->num_tables = count($tables);
        $this->one_table_percent = $this->one_db_percent / $this->num_tables;
    }

    /**
     * @param $print - print function to printout progress
     */
    public function setPrint($print)
    {
        $this->print = $print;
    }

    /**
     * @param $i - index of currently scanned table
     * @param $table - name of currently scanned table
     */
    public function setCurrentTable($i, $table)
    {
        $new_percent = number_format(($this->current_db_num * $this->one_db_percent) + ($i * $this->one_table_percent), 1);
        $this->progress_string = str_replace(substr($this->progress_string, 0, strpos($this->progress_string, '% of whole scan')), '[' . ($i + 1) . '/' . $this->num_tables . ' tbls of ' . ($this->current_db_num + 1) . '/' . $this->db_count . ' dbs] ' . $new_percent, $this->progress_string);
        $this->current_table_num = $i;
        $this->current_table = $table;
        $this->percent_main = $new_percent;
        if ($this->print !== null && is_callable($this->print)) {
            $this->print->call($this, $this->getProgressAsString());
        }
    }

    /**
     * @param $i - index of currently scanned table
     * @param $table - name of currently scanned table
     */
    public function setCurrentDb($i, $db)
    {
        $new_percent = number_format($i * $this->one_db_percent, 1);
        $this->progress_string = str_replace(substr($this->progress_string, 0, strpos($this->progress_string, '% of whole scan')), '[' . ($this->current_table_num + 1) . '/' . $this->num_tables . ' tbls of ' . ($i + 1) . '/' . $this->db_count . ' dbs] ' . $new_percent, $this->progress_string);
        $this->current_db_num = $i;
        $this->current_db = $db;
        $this->percent_main = $new_percent;
        if ($this->print !== null && is_callable($this->print)) {
            $this->print->call($this, $this->getProgressAsString());
        }
    }

    /**
     * @param $key_start - first key of table
     * @param $key_last - last key of table
     */
    public function setKeysRange($key_start, $key_last)
    {
        $this->first_table_key = $key_start;
        $this->last_table_key = $key_last;
        $this->setTotalTable(($key_last - $key_start) + 1);
    }

    /**
     * @param $total_table - total records for table
     */
    public function setTotalTable($total_table)
    {
        $this->total_table = $total_table;
        $this->one_record_percent = $this->one_table_percent / $this->total_table;
    }

    /**
     * @param $row_id - current record
     * @param $detected - num of detected malicious
     * @param $db - current db
     * @param $table - current table
     */
    public function updateProgress($row_id, $detected, $cleaned, $db, $table)
    {
        if (time() - $this->last_update < $this->update_interval) {
            return;
        }

        $corrected_start_value = $row_id - $this->first_table_key;
        $percent_table = number_format($this->total_table ? $corrected_start_value * 100 / $this->total_table : 0, 1);
        $elapsed_time    = microtime(true) - $this->start;

        $stat            = '';
        $left            = 0;
        $left_time       = 0;
        $elapsed_seconds = 0;

        $percent_main = $this->percent_main;

        $percent_main += number_format($corrected_start_value * $this->one_record_percent, 1);

        if ($elapsed_time >= 1) {
            $elapsed_seconds = round($elapsed_time, 0);
            $fs              = floor($corrected_start_value / $elapsed_seconds);
            $left            = $this->total_table - $corrected_start_value;
            $clean = ($cleaned > 0 ? '/' . $cleaned : '');
            $malware = ($detected > 0 ? '[Mlw:' . $detected . $clean . ']' : '');
            if ($fs > 0) {
                $left_time = ($left / $fs);
                $stat = ' [Avg: ' . round($fs, 2) . ' rec/s' . ($left_time > 0 ? ' Left: ' . AibolitHelpers::seconds2Human($left_time) . ' for current table' : '') . '] ' . $malware;
            }
        }

        $this->progress_string = '[' . ($this->current_table_num + 1) . '/' . $this->num_tables . ' tbls of ' . ($this->current_db_num + 1) . '/' . $this->db_count . ' dbs] ' . $percent_main . '% of whole scan' . '/' . $percent_table . '% [' . $db . '.' . $table . '] ' . $corrected_start_value . ' of ' . $this->total_table . ' rows ' . $stat;

        $data = [
            'self'                  => __FILE__,
            'started'               => $this->start,
            'updated'               => time(),
            'progress_table'        => $percent_table,
            'progress_main'         => $percent_main,
            'time_elapsed'          => $elapsed_seconds,
            'time_left'             => round($left_time),
            'left'                  => $left,
            'total_table'           => $this->total_table,
            'current_index'         => $corrected_start_value,
            'current_db_num'        => $this->current_db_num,
            'current_table_num'     => $this->current_table_num,
            'total_db_count'        => $this->db_count,
            'total_tbl_db_count'    => $this->num_tables,
            'current_row_id'        => $row_id,
            'current'               => $db . '.' . $table . '/' . $row_id,
        ];

        if ($this->progress_file && (time() - $this->last_file_update > $this->file_write_interval)) {
            if (function_exists('json_encode')) {
                file_put_contents($this->progress_file, json_encode($data));
            } else {
                file_put_contents($this->progress_file, serialize($data));
            }

            $this->last_file_update = time();
        }

        if ($this->shared_mem) {
            shmop_write($this->shared_mem, str_repeat("\0", shmop_size($this->shared_mem)), 0);
            if (function_exists('json_encode')) {
                shmop_write($this->shared_mem, json_encode($data), 0);
            } else {
                shmop_write($this->shared_mem, serialize($data), 0);
            }
        }

        if ($this->print !== null && is_callable($this->print)) {
            $this->print->call($this, $this->getProgressAsString());
        }
    }

    /**
     * @return string
     */
    public function getProgressAsString()
    {
        return $this->progress_string;
    }

    public function finalize()
    {
        if ($this->progress_file && file_exists($this->progress_file)) {
            @unlink($this->progress_file);
        }
        if ($this->shared_mem && $this->create_shared_mem) {
            shmop_delete($this->shared_mem);
        }
        if ($this->shared_mem) {
            shmop_close($this->shared_mem);
        }
    }
}
/**
 * Class MDSScan module for scan string with signatures
 */
class MDSScan
{
    /**
     * Scan function
     * @param $content
     * @param $signature_db
     * @return array|bool
     */
    public static function scan($content, $signature_db)
    {
        $checkers['CriticalPHP'] = true;
        $checkers['CriticalJS'] = true;

        $checker_url['UrlChecker'] = false;

        $result = [];
        $resultUrl = [];

        $processResult = function ($checker, $content, $l_Pos, $l_SigId, &$return) use (&$result, $signature_db) {
            $return = null;
            $result = [
                'content' => self::getFragment($content, $l_Pos),
                'pos' => $l_Pos,
                'sigid' => $l_SigId,
            ];
            if (isset($l_SigId) && isset($signature_db->_Mnemo[$l_SigId])) {
                $result['sn'] = $signature_db->_Mnemo[$l_SigId];
            } else {
                $result['sn'] = '';
            }
        };

        $processUrlResult = function ($checker, $content, $l_Pos, $l_SigId, &$return) use (&$resultUrl, $signature_db) {
            $return = null;
            if (isset($l_Pos['black'])) {
                for ($i=0, $iMax = count($l_Pos['black']); $i < $iMax; $i++) {
                    $resultUrl['black'][] = [
                        'content' => self::getFragment($content, $l_Pos['black'][$i]),
                        'pos' => $l_Pos['black'][$i],
                        'sigid' => $l_SigId['black'][$i],
                    ];
                }
            }

            if (isset($l_Pos['unk'])) {
                for ($i=0, $iMax = count($l_Pos['unk']); $i < $iMax; $i++) {
                    $resultUrl['unk'][] = [
                        'content' => self::getFragment($content, $l_Pos['unk'][$i]),
                        'pos' => $l_Pos['unk'][$i],
                        'sigid' => $l_SigId['unk'][$i],
                    ];
                }
            }
        };

        $l_Unwrapped = Normalization::strip_whitespace($content);
        $l_UnicodeContent = Encoding::detectUTFEncoding($content);
        if ($l_UnicodeContent !== false) {
            if (Encoding::iconvSupported()) {
                $l_Unwrapped = Encoding::convertToCp1251($l_UnicodeContent, $l_Unwrapped);
            }
        }
        $l_DeobfObj = new Deobfuscator($l_Unwrapped, $content);
        $l_DeobfType = $l_DeobfObj->getObfuscateType($l_Unwrapped);
        if ($l_DeobfType != '') {
            $l_Unwrapped = $l_DeobfObj->deobfuscate();
        }

        $l_Unwrapped = Normalization::normalize($l_Unwrapped);
        $found = ScanUnit::QCR_ScanContent($checkers, $l_Unwrapped, $content, $signature_db, null, null, $processResult);
        $found_urls = ScanUnit::QCR_ScanContent($checker_url, $l_Unwrapped, $content, $signature_db, null, null, $processUrlResult);
        $ret = false;
        if ($found) {
            $ret['mlw'] = $result;
        }
        if ($found_urls) {
            $ret['url'] = $resultUrl;
        }
        return $ret;
    }

    public static function scanBatch($contents, $signature_db)
    {
        $result = [];
        foreach($contents as $index => $fields) {
            foreach($fields as $field => $content) {
                if ($res = self::scan($content, $signature_db)) {
                    $result[$index][$field] = $res;
                }
            }
        }
        return $result;
    }

    /**
     * Get snippet from string
     * @param $par_Content
     * @param $par_Pos
     * @return string|string[]
     */
    private static function getFragment($par_Content, $par_Pos)
    {
        $l_MaxChars = 120;

        $par_Content = preg_replace('/[\x00-\x1F\x80-\xFF]/', '~', $par_Content);

        $l_MaxLen   = strlen($par_Content);
        $l_RightPos = min($par_Pos + $l_MaxChars, $l_MaxLen);
        $l_MinPos   = max(0, $par_Pos - $l_MaxChars);

        $l_Res = ($l_MinPos > 0 ? '…' : '') . substr($par_Content, $l_MinPos, $par_Pos - $l_MinPos) . '__AI_MARKER__' . substr($par_Content, $par_Pos, $l_RightPos - $par_Pos - 1);

        $l_Res = AibolitHelpers::makeSafeFn(Normalization::normalize($l_Res));

        $l_Res = str_replace('~', ' ', $l_Res);

        $l_Res = preg_replace('~[\s\t]+~', ' ', $l_Res);

        $l_Res = str_replace('' . '?php', '' . '?php ', $l_Res);

        return $l_Res;
    }
}
/**
 * Class MDSPreScanQuery generates PreScan SQL Query to get suspicious rows
 */
class MDSPreScanQuery
{
    private $aliases = [];
    private $limit = 0;
    private $last = 0;
    private $key;
    private $table;
    private $fields;
    private $prescan;

    /**
     * MDSPreScanQuery constructor.
     * @param $prescan
     * @param $fields
     * @param $key
     * @param $table
     * @param $db
     * @param int $limit
     * @param int $last
     */
    public function __construct($prescan, $fields, $key, $table, $db, $limit = 0, $last = 0)
    {
        $this->limit = $limit;
        $this->prescan = $prescan;
        $this->fields = $fields;
        $this->key = $key;
        $this->table = $table;
        $this->last = $last;
        $this->db = $db;
        $this->generateAliases();
    }

    /**
     * @return array
     */
    public function getAliases()
    {
        return $this->aliases;
    }

    /**
     * @param $alias
     * @return bool|string
     */
    public function getFieldByAlias($alias)
    {
        foreach ($this->aliases as $key => $field) {
            if ($field === $alias) {
                return $key;
            }
        }
        return false;
    }

    /**
     * @param $value
     */
    public function setLastKey($value)
    {
        $this->last = $value;
    }

    /**
     * @return int
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function getDB()
    {
        return $this->db;
    }

    /**
     * @return string
     */
    public function getTable()
    {
        return $this->table;
    }

    /**
     * Generate pre scan sql query
     * @return string
     */
    public function generateSqlQuery()
    {
        $res = 'SELECT ';
        $numItems = count($this->aliases);
        $i = 0;
        foreach($this->aliases as $column => $alias) {
            $res .= $column . ' as ' . $alias;
            if(++$i !== $numItems) {
                $res .= ',';
            }
        }
        $res .= ' FROM ' . $this->db . '.' . $this->table;
        $res .= ' WHERE ' . $this->key . ' > ' . $this->last;
        $res .= ' AND (' . $this->generatePreScanClause() . ')';
        $res .= ' ORDER BY ' . $this->key;
        if ($this->limit > 0) {
            $res .= ' LIMIT ' . $this->limit;
        }
        $res .= ';';
        return $res;
    }

    /**
     * generate aliases for fields
     */
    private function generateAliases()
    {
        $alphabet = 'abcdefghijklmnopqrstuvwxyz';
        $fields = $this->fields;
        $fields[] = $this->key;
        $res = [];
        for ($i = 0, $iMax = count($fields); $i < $iMax; $i++) {
            $res[$fields[$i]] = $alphabet[$i];
        }
        $this->aliases = $res;
    }


    /**
     * Generate where clause part for sql qpre scan query
     * @return string
     */
    private function generatePreScanClause()
    {
        $res = '';
        for ($i = 0, $iMax = count($this->fields); $i < $iMax; $i++) {
            $res .= str_replace('$$FF$$', $this->fields[$i], '(' . $this->prescan . ')');
            if ($i !== $iMax - 1) {
                $res .= ' OR ';
            }
        }
        return $res;
    }
}
/**
 * Class MDSScannerTable module for scan whole table
 */
class MDSScannerTable
{
    /**
     * @param mysqli        $connection
     * @param string        $query
     * @param array         $signature_db
     * @param int           $max_clean
     * @param array         $clean_db
     * @param MDSProgress   $progress
     * @param MDSState      $state
     * @param MDSJSONReport $report
     * @param MDSBackup     $backup
     * @param Logger        $log
     * @throws Exception
     */
    public static function scan($connection, $query, $signature_db, $max_clean, $clean_db = null, $progress = null, $state = null, $report = null, $backup = null, $log)
    {
        $total_scanned = 0;
        $detected = 0;
        $cleaned = 0;
        list($min_key, $last_key) = $connection->query('SELECT MIN(' . $query->getKey() .') as start_key, MAX(' . $query->getKey() .') as last_key FROM ' . $query->getDB() . '.' . $query->getTable() . ';')->fetch_array(MYSQLI_NUM);
        if ($progress instanceof MDSProgress) {
            $progress->setKeysRange($min_key, $last_key);
        }
        $res = $connection->query($query->generateSqlQuery());
        if (self::isCanceled($state)) {
            $log->info('Task canceled');
            $report->setState(MDSJSONReport::STATE_CANCELED);
            return;
        }
        while($res && $res->num_rows > 0) {
            if (!isset($clean_db)) {
                foreach ($res as $row) {
                    if (self::isCanceled($state)) {
                        $log->info('Task canceled in progress');
                        $report->setState(MDSJSONReport::STATE_CANCELED);
                        return;
                    }
                    $val = end($row);
                    $key = key($row);
                    array_pop($row);
                    $key = $query->getFieldByAlias($key);
                    foreach($row as $k => $v) {
                        $result = MDSScan::scan($v, $signature_db);
                        if (isset($result['mlw'])) {
                            $log->debug(
                                sprintf(
                                    'DETECTED. Field: "%s", ID: %d, sn: "%s", content: "%s"',
                                    $query->getFieldByAlias($k),
                                    $val,
                                    $result['mlw']['sn'] ?? '',
                                    $result['mlw']['content']
                                )
                            );
                            if ($report !== null) {
                                $report->addDetected($result['mlw']['sn'], $result['mlw']['content'], $query->getTable(), $val, $query->getFieldByAlias($k));
                            }
                            $detected++;
                        }
                        if (isset($result['url']['black'])) {
                            foreach($result['url']['black'] as $url) {
                                if ($report !== null) {
                                    $report->addDetectedUrl($url['sigid'], $url['content'], $query->getTable(), $val, $query->getFieldByAlias($k));
                                }
                            }
                        }
                        if (isset($result['url']['unk'])) {
                            foreach($result['url']['unk'] as $url) {
                                if ($report !== null) {
                                    $report->addUnknownUrl($url['sigid']);
                                }
                            }
                        }
                    }
                    $total_scanned++;
                    if ($progress instanceof MDSProgress) {
                        $progress->updateProgress($val, $detected, 0, $query->getDB(), $query->getTable());
                    }
                    $query->setLastKey($val);
                }
            } else {
                $batch = [];
                $i = $max_clean;
                $forclean = [];
                $forscan = [];
                while (true) {
                    $row = $res->fetch_assoc();
                    if ($i-- && $row) {
                        $batch[end($row)] = $row;
                        continue;
                    } else if (!$row && empty($batch)) {
                        break;
                    }
                    if ($row) {
                        $batch[end($row)] = $row;
                    }
                    foreach ($batch as $index => $row) {
                        array_pop($row);
                        foreach ($row as $k => $v) {
                            $forscan[$index][$query->getFieldByAlias($k)] = $v;
                        }
                    }
                    $last = end($batch);
                    $last_key = end($last);
                    $query->setLastKey($last_key);
                    $scan_res = MDSScan::scanBatch($forscan, $signature_db);
                    foreach ($scan_res as $index => $fields) {
                        if (self::isCanceled($state)) {
                            $report->setState(MDSJSONReport::STATE_CANCELED);
                            return;
                        }
                        foreach ($fields as $field => $result) {
                            if (isset($result['mlw'])) {
                                $log->debug(
                                    sprintf(
                                        'DETECTED. Field: "%s", ID: %d, sn: "%s", content: "%s"',
                                        $field,
                                        $index,
                                        $result['mlw']['sn'] ?? '',
                                        $result['mlw']['content'] ?? ''
                                    )
                                );
                                $detected++;
                                $forclean[$index][$field] = $forscan[$index][$field];
                            }
                            if (isset($result['url']['black'])) {
                                foreach($result['url']['black'] as $url) {
                                    $detected++;
                                    $forclean[$index][$field] = $forscan[$index][$field];
                                }
                            }
                            if (isset($result['url']['unk'])) {
                                foreach($result['url']['unk'] as $url) {
                                    if ($report !== null) {
                                        $report->addUnknownUrl($url['sigid']);
                                    }
                                }
                            }
                        }
                    }
                    if ($backup instanceof MDSBackup) {
                        foreach ($forclean as $index => $fields) {
                            foreach($fields as $field => $result) {
                                $backup->backup($query->getDB(), $query->getTable(), $field, $query->getKey(), $index, $forclean[$index][$field]);
                            }
                        }
                    }
                    $clean_res = MDSCleanup::cleanBatch($forclean, $detected, $cleaned, $clean_db, $connection, $query, $progress);
                    if ($clean_res) {
                        foreach ($clean_res as $index => $fields) {
                            foreach ($fields as $field => $result) {
                                if (!$result) {
                                    $report->addCleanedError('', '', $query->getTable(), $index, $field, MDSErrors::MDS_CLEANUP_ERROR);
                                } else {
                                    foreach ($result as $val) {
                                        $log->debug(
                                            sprintf('CLEANED. Field: "%s", ID: %d, sn: %s', $field, $index,
                                                $val['id'] ?? '')
                                        );
                                        $report->addCleaned($val['id'], $scan_res[$index][$field]['mlw']['content'],
                                            $query->getTable(), $index, $field);
                                    }
                                }
                            }
                        }
                    }
                    $total_scanned += count($batch);
                    if ($progress instanceof MDSProgress) {
                        $progress->updateProgress($last_key, $detected, $cleaned, $query->getDB(), $query->getTable());
                    }
                    $batch = [];
                    $i = $max_clean;
                    $forclean = [];
                    $forscan = [];
                }
            }
            $res = $connection->query($query->generateSqlQuery());
        }

        $log->info(
            sprintf(
                'Scanning table "%s" finished. Scanned: %d, Detected: %d, Cleaned: %d',
                $query->getTable(),
                $total_scanned,
                $detected,
                $cleaned
            )
        );

        if ($report !== null) {
            $report->addTotalTableRows($query->getTable(), $total_scanned);
        }

        if ($res === false) {
            $log->error('Error with db connection ' . $connection->error);
            throw new MDSException(MDSErrors::MDS_DROP_CONNECT_ERROR, $connection->error);
        }
    }

    /**
     * Check on cancel
     * @param MDSState  $state
     * @return bool
     */
    private static function isCanceled($state)
    {
        if (is_null($state)) {
            return false;
        }
        return $state->isCanceled();
    }
}
/**
 * Class MDSScanner module for scan whole user
 */
class MDSScanner
{
    /**
     * @param string                $prescan - prescan string
     * @param string                $database - db name (null to scan all dbs that user have access to)
     * @param string                $prefix - prefix (null to disable filter by prefix)
     * @param MDSFindTables         $mds_find
     * @param mysqli                $connection
     * @param LoadSignaturesForScan $scan_signatures
     * @param int                   $max_clean
     * @param array                 $clean_db
     * @param MDSProgress           $progress
     * @param MDSState              $state
     * @param MDSJSONReport         $report
     * @param MDSBackup             $backup
     * @param bool                  $scan
     * @param bool                  $clean
     * @param Logger $log
     * @throws Exception
     */
    public static function scan($prescan, $database, $prefix, $mds_find, $connection, $scan_signatures, $max_clean = 100, $clean_db = null, $progress = null, $state = null, $report = null, $backup = null, $scan = true, $clean = false, $log = null)
    {

        $start_time = microtime(true);

        $tables = $mds_find->find($database, $prefix);
        if (empty($tables)) {
            $log->error('Not found any supported tables. Nothing to scan.');
            throw new MDSException(MDSErrors::MDS_NO_SUP_TABLES_ERROR, $database, $report->getUser(), $report->getHost());
        }

        if ($progress instanceof MDSProgress) {
            $progress->setTables($tables);
        }

        if (!$scan && !$clean) {
            return;
        }

        $log->info('MDS Scan: started');

        if ($progress instanceof MDSProgress) {
            $progress->setCurrentTable(0, $tables[0]);
        }
        
        foreach($tables as $i => $table) {
            $scan_signatures->setOwnUrl($table['domain_name']);
            $prescan_query = new MDSPreScanQuery($prescan, $table['config']['fields'], $table['config']['key'], $table['table'], $table['db'], 10000);

            $log->debug(sprintf('Scanning table: "%s"', $table['table']));

            MDSScannerTable::scan($connection, $prescan_query, $scan_signatures, $max_clean, $clean_db, $progress, $state, $report, $backup, $log);
            if ($progress instanceof MDSProgress) {
                $progress->setCurrentTable($i, $table);
            }
        }
        
        if ($report !== null) {
            $report->setCountTablesScanned(count($tables));
            $report->setRunningTime(microtime(true) - $start_time);
        }

        $log->info(sprintf('MDS Scan: finished. Time taken: %f second(s)', microtime(true) - $start_time));

        if ($progress instanceof MDSProgress) {
            $progress->finalize();
        }

        if ($backup instanceof MDSBackup) {
            $backup->finish();
        }
    }
}
/**
 * The MDSState class is needed to pass the MDS state of work
 */
class MDSState
{
    private $cache_ttl              = 1; //sec
    private $cache_data             = null;
    private $last_update_time_cache = 0;
    
    const STATE_NEW         = 'new';
    const STATE_WORKING     = 'working';
    const STATE_DONE        = 'done';
    const STATE_CANCELED    = 'canceled';

    private $state_filepath = null;
   
    /**
     * MDSState constructor.
     * @param string $state_filepath
     * @param int $cache_ttl
     */
    public function __construct($state_filepath, $cache_ttl = 1)
    {
        $this->state_filepath   = $state_filepath;
        $this->cache_ttl        = $cache_ttl;
    }
    
    /**
     * Scan or cure process not started
     * @return bool
     */
    public function isNew()
    {
        return $this->getCurrentState() == self::STATE_NEW;
    }
    
    /**
     * The scan or cure process is currently running
     * @return bool
     */
    public function isWorking()
    {
        return $this->getCurrentState() == self::STATE_WORKING;
    }

    /**
     * The scan or cure process is canceled
     * @return bool
     */
    public function isCanceled()
    {
        return $this->getCurrentState() == self::STATE_CANCELED;
    }
    
    /**
     * The scan or cure process is done
     * @return bool
     */
    public function isDone()
    {
        return $this->getCurrentState() == self::STATE_DONE;
    }

    /**
     * Set process to work state
     * @return bool
     */
    public function setWorking()
    {
        return $this->setStateWithoutCheck(self::STATE_WORKING);
    }

    /**
     * Set process to done state
     * @return bool
     */
    public function setDone()
    {
        return $this->setStateWithoutCheck(self::STATE_DONE);
    }

    /**
     * Set process to canceled state
     * @return bool
     */
    public function setCanceled()
    {
        $func = function($data) {
            return ($data == self::STATE_WORKING) ? self::STATE_CANCELED : $data;
        };
        $new_data = $this->editFileWithClosure($this->state_filepath, $func);
        $this->setCache($new_data);
        return $new_data == self::STATE_CANCELED;
    }
    
    // /////////////////////////////////////////////////////////////////////////

    /**
     * Overwrite the file with new data with the condition programmed in the closure
     * @param string $filepath
     * @param function $edit_func
     * @param mixed $default
     * @return mixed
     */
    private function editFileWithClosure($filepath, $edit_func, $default = null)
    {
        $result = $default;
        $fh     = @fopen($filepath, 'c+');
        if (!$fh) {
            return $result;
        }
        if (flock($fh, LOCK_EX)) {
            $data   = trim(stream_get_contents($fh));
            $result = $edit_func($data);
            
            fseek($fh, 0);
            ftruncate($fh, 0);
            fwrite($fh, $result);
        }
        else {
            fclose($fh);
            return $result;
        }
        fclose($fh);
        return $result;
    }

    /**
     * Get file data
     * @param string $filepath
     * @return string|bool
     */
    private function readFile($filepath)
    {
        if (!file_exists($filepath)) {
            $this->setCache(false);
            return false;
        }
        $fh = @fopen($filepath, 'r');
        if (!$fh) {
            $this->setCache(false);
            return false;
        }
        $data = false;
        if (flock($fh, LOCK_SH)) {
            $data = trim(stream_get_contents($fh));
        }
        fclose($fh);
        $this->setCache($data);
        return $data;
    }

    /**
     * Set cache data
     * @param string $cache_data
     * @return void
     */
    private function setCache($cache_data)
    {
        $this->last_update_time_cache = time();
        $this->cache_data = $cache_data;
    }

    /**
     * Set state without checking
     * @param string $state
     * @return bool
     */
    private function setStateWithoutCheck($state)
    {
        $func = function($data) use ($state) {
            return $state;
        };
        $new_data = $this->editFileWithClosure($this->state_filepath, $func, false);
        $this->setCache($new_data);
        return (bool)$new_data;
    }

    /**
     * Get current status
     * @return string
     */
    private function getCurrentState()
    {
        $current_state = $this->cache_data;
        if (is_null($this->cache_data) || $this->last_update_time_cache + $this->cache_ttl < time()) {
            $current_state = $this->readFile($this->state_filepath);
        }
        if (in_array($current_state, [self::STATE_WORKING, self::STATE_DONE, self::STATE_CANCELED])) {
            return $current_state;
        }
        return self::STATE_NEW;
    }

}
/**
 * Class MDSBackup Backup data to csv
 */
class MDSBackup
{
    private $fhandle;
    private $hmemory;

    /**
     * MDSBackup constructor.
     * @param string $file
     */
    public function __construct($file = '')
    {
        if ($file == '') {
            $file = getcwd();
            $file .= '/mds_backup_' . time() . '.csv';
        }
        $this->fhandle = fopen($file, 'a');
        $this->hmemory = fopen('php://memory', 'w+');

        if (!($this->fhandle && $this->hmemory)) {
            throw new MDSException(MDSErrors::MDS_BACKUP_ERROR);
        }
    }

    /**
     * Backup one record to csv
     * @param $db
     * @param $table
     * @param $field
     * @param $id
     * @param $data
     */
    public function backup($db, $table, $field, $key, $id, $data)
    {
        fputcsv($this->hmemory, [$db, $table, $field, $key, $id, base64_encode($data)]);
        $size = fstat($this->hmemory);
        $size = $size['size'];
        if ($size > 32768) {
            $this->flush();
        }
    }

    /**
     * Backup array of records to csv
     * @param $rows
     */
    public function backupBatch($rows)
    {
        foreach($rows as list($db, $table, $field, $key, $id, $data)) {
             $this->backup($db, $table, $field, $key, $id, $data);
        }
    }

    /**
     * Flush to disk and close handles
     */
    public function finish()
    {
        $this->flush();
        fclose($this->hmemory);
        fclose($this->fhandle);
    }

    /**
     * Flush to disk
     */
    private function flush()
    {
        rewind($this->hmemory);
        stream_copy_to_stream($this->hmemory, $this->fhandle);
        fflush($this->fhandle);
        rewind($this->hmemory);
        ftruncate($this->hmemory, 0);
    }
}
class MDSCleanup
{
    public static function clean($content, $clean_db, $connection, $query, $field, $key, $report = null)
    {
        $old_content = $content;
        $clean_result = CleanUnit::CleanContent($content, $clean_db, true);
        if ($clean_result) {
            $query_str = 'UPDATE ' . $query->getDb() . '.' . $query->getTable() . ' SET ' . $field . '=\'' . $connection->real_escape_string($content) . '\'';
            $query_str .= ' WHERE ' . $query->getKey() . '=' . $key . ' AND ' . $field . '=\'' . $connection->real_escape_string($old_content) . '\';';
            if ($connection->query($query_str) && $connection->affected_rows === 1 && $old_content !== $content) {
                return $clean_result;
            }
        }
        return false;
    }

    public static function cleanBatch($content_for_clean, $detected, &$cleaned, $clean_db, $connection, $query, $progress = null)
    {
        $res = [];
        if (!empty($content_for_clean)) {
            @$connection->begin_transaction(MYSQLI_TRANS_START_READ_WRITE);
            foreach ($content_for_clean as $index => $fields) {
                foreach($fields as $field => $result) {
                    $clean = self::clean($result, $clean_db, $connection, $query, $field, $index);
                    if ($clean) {
                        $res[$index][$field] = $clean;
                        $cleaned++;
                    } else {
                        $res[$index][$field] = false;
                    }
                    if ($progress instanceof MDSProgress) {
                        $progress->updateProgress($index, $detected, $cleaned, $query->getDB(), $query->getTable());
                    }
                }
            }
            @$connection->commit();
        }
        return $res;
    }
}
/**
 * Class MDSRestore Restore data from csv backup
 */
class MDSRestore
{
    private $fhandle;
    private $connection;
    private $progress;
    private $report;
    private $current_row = 0;
    private $start_time = 0;
    private $state = null;
    private $log = null;

    /**
     * MDSRestore constructor.
     * @param string        $file
     * @param mysqli        $connection
     * @param MDSProgress   $progress
     * @param MDSJSONReport $report
     * @param MDSState      $state
     */
    public function __construct($file, $connection, $progress = null, $report = null, MDSState $state = null, $log = null)
    {
        if (!$this->fhandle = fopen($file, 'r')) {
            throw new MDSException(MDSErrors::MDS_RESTORE_BACKUP_ERROR, $file);
        }
        $this->connection = $connection;
        $this->progress = $progress;
        $this->report = $report;
        $this->state = $state;
        $this->log = $log;

        $file = new \SplFileObject($file, 'r');
        $file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        $file->seek(PHP_INT_MAX);

        if ($progress instanceof MDSProgress) {
            $progress->setTotal($file->key());
            $progress->setKeysRange(0, $file->key());
            $progress->setTotalTable($file->key());
            $progress->setCurrentTable(0, '');
        }

        $this->start_time = microtime(true);
    }

    /**
     * Write to db one record
     * @param $db
     * @param $table
     * @param $field
     * @param $key
     * @param $id
     * @param $data
     * @return bool
     */
    public function writeToDb($db, $table, $field, $key, $id, $data)
    {
        $ret = false;
        $data = base64_decode($data);
        $query_str = 'UPDATE ' . $db . '.' . $table . ' SET ' . $field . '=\'' . $this->connection->real_escape_string($data) . '\'';
        $query_str .= ' WHERE ' . $key . '=' . $id .';';
        if ($this->connection->query($query_str) && $this->connection->affected_rows === 1) {
            $ret = true;
        }
        if ($this->progress instanceof MDSProgress) {
            $this->progress->updateProgress(++$this->current_row, 0, 0, $db, $table);
        }
        if (isset($this->report)) {
            if ($ret === true) {
                $this->report->addRestored($table, $id, $field);
            } else {
                $this->report->addRestoredError(MDSErrors::MDS_RESTORE_UPDATE_ERROR, $table, $id, $field);
            }

        }
        return $ret;
    }

    /**
     * Write to db array of records
     * @param $rows
     */
    public function writeToDbBatch($rows)
    {
        foreach($rows as list($db, $table, $field, $key, $id, $data)) {
            $this->writeToDb($db, $table, $field, $key, $id, $data);
        }
    }

    public function restore($count)
    {
        $batch = $count;
        $for_restore = [];
        while (true) {
            if ($this->isCanceled()) {
                $this->log->info('Task canceled in progress');
                $this->report->setState(MDSJSONReport::STATE_CANCELED);
                break;
            }
            $row = fgetcsv($this->fhandle);
            if ($batch-- && $row) {
                $for_restore[] = $row;
                continue;
            } else {
                if (!$row && empty($for_restore)) {
                    break;
                }
            }
            if ($row) {
                $for_restore[] = $row;
            }
            $this->writeToDbBatch($for_restore);
            $for_restore = [];
            $batch = $count;
        }
    }

    /**
     * Close file handle and save report
     */
    public function finish()
    {
        fclose($this->fhandle);
        if (isset($this->report)) {
            $this->report->setCountTablesScanned(1);
            $this->report->setRunningTime(microtime(true) - $this->start_time);
        }
    }
    
    /**
     * Check on cancel
     * @return bool
     */
    private function isCanceled()
    {
        if (is_null($this->state)) {
            return false;
        }
        return $this->state->isCanceled();
    }
    
}
/**
 * Class MDSUrls store urls data
 */
class MDSUrls
{
    private $optimized_db;
    private $urls;

    /**
     * MDSUrls constructor.
     * @param $file
     * @throws Exception
     */
    public function __construct($file)
    {
        if (empty($file) || !file_exists($file)) {
            throw new MDSException(MDSErrors::MDS_DB_URLS_ERROR, $file);
        }

        $db = new \SplFileObject($file, 'r');
        $db->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        foreach ($db as $url) {
            $url = explode('-', $url, 2);
            $this->urls[$url[0]] = strpos($url[1],'//') === 0 ? substr_replace($url[1],'//(www\.)?',0,2) : $url[1];
        }
        unset($db);

        $this->optimized_db = $this->urls;
        $this->optSig($this->optimized_db);
    }

    /**
     * Signature optimization (glue)
     * @param $sigs
     */
    private function optSig(&$sigs)
    {
        $sigs = array_unique($sigs);

        // Add SigId
        foreach ($sigs as $index => &$s) {
            $s .= '(?<X' . $index . '>)';
        }
        unset($s);

        $fix = [
            '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e'  => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
            'http://.+?/.+?\.php\?a'                    => 'http://[^?\s]++(?<=\.php)\?a',
            '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*'             => '.+?',
            '[\'"]{0,1}.+?[\'"]{0,1}'                   => '.+?'
        ];

        $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);
        
        $fix = [
            '~^\\\\[d]\+&@~'                            => '&@(?<=\d..)',
            '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~'  => ''
        ];

        $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);

        $this->optSigCheck($sigs);

        $tmp = [];
        foreach ($sigs as $i => $s) {
            if (!preg_match('~^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$~', $s)) {
                unset($sigs[$i]);
                $tmp[] = $s;
            }
        }
        
        usort($sigs, 'strcasecmp');
        $txt = implode("\n", $sigs);

        for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
            $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', [$this, 'optMergePrefixes'], $txt);
        }

        $sigs = array_merge(explode("\n", $txt), $tmp);
        
        $this->optSigCheck($sigs);
    }

    /**
     * @param $m
     * @return string
     */
    private function optMergePrefixes($m)
    {
        $limit = 8000;

        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $len = $prefix_len;
        $r   = [];

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {

            if (strlen($line) > $limit) {
                $r[] = $line;
                continue;
            }

            $s = substr($line, $prefix_len);
            $len += strlen($s);
            if ($len > $limit) {
                if (count($suffixes) == 1) {
                    $r[] = $prefix . $suffixes[0];
                } else {
                    $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
                }
                $suffixes = [];
                $len      = $prefix_len + strlen($s);
            }
            $suffixes[] = $s;
        }

        if (!empty($suffixes)) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
        }

        return implode("\n", $r);
    }

    /*
     * Checking errors in pattern
     */
    private function optSigCheck(&$sigs)
    {
        $result = true;

        foreach ($sigs as $k => $sig) {
            if (trim($sig) == "") {
                unset($sigs[$k]);
                $result = false;
            }

            if (@preg_match('~' . $sig . '~smiS', '') === false) {
                $error = error_get_last();
                unset($sigs[$k]);
                $result = false;
            }
        }

        return $result;
    }

    /**
     * Return optimized db
     * @return mixed
     */
    public function getDb()
    {
        return $this->optimized_db;
    }

    public function getSig($l_Found)
    {
        foreach ($l_Found as $key => &$v) {
            if (is_string($key) && $v[1] !== -1 && strlen($key) > 1) {
                return 'CMW-URL-' . substr($key, 1);
            }
        }
        return null;
    }

    public function getSigUrl($id)
    {
        if (strpos($id, 'CMW-URL-') !== false) {
            $id = (int)str_replace('CMW-URL-', '', $id);
        }
        return $this->urls[$id];
    }

}
class MDSErrors
{
    const MDS_CONNECT_ERROR             = 1;
    const MDS_BACKUP_ERROR              = 2;
    const MDS_PROGRESS_FILE_ERROR       = 3;
    const MDS_PROGRESS_SHMEM_ERROR      = 4;
    const MDS_PROGRESS_SHMEM_CRT_ERROR  = 5;
    const MDS_RESTORE_BACKUP_ERROR      = 6;
    const MDS_NO_SUP_TABLES_ERROR       = 7;
    const MDS_CONFIG_ERROR              = 8;
    const MDS_DB_URLS_ERROR             = 9;
    const MDS_NO_DATABASE               = 10;
    const MDS_PRESCAN_CONFIG_ERROR      = 11;
    const MDS_REPORT_ERROR              = 12;

    const MDS_DROP_CONNECT_ERROR        = 13;

    const MDS_AVD_DB_NOTFOUND           = 14;
    const MDS_AVD_DB_INVALID            = 15;
    const MDS_INVALID_CMS_CONFIG        = 16;
    const MDS_CMS_CONFIG_NOTSUP         = 17;
    const MDS_MULTIPLE_DBS              = 18;
    const MDS_NO_SCANNED                = 19;

    const MDS_CLEANUP_ERROR             = 101;
    const MDS_RESTORE_UPDATE_ERROR      = 102;

    const MESSAGES = [
        self::MDS_CONNECT_ERROR               => 'Can\'t connect to database: %s',
        self::MDS_BACKUP_ERROR                => 'Can\'t create backup file in %s',
        self::MDS_PROGRESS_FILE_ERROR         => 'Can\'t create progress file in %s',
        self::MDS_PROGRESS_SHMEM_ERROR        => 'Can\'t use progress shared memory with key %s',
        self::MDS_PROGRESS_SHMEM_CRT_ERROR    => 'Can\'t create progress shared memory with key %s',
        self::MDS_RESTORE_BACKUP_ERROR        => 'Can\'t open backup file for restore in %s',
        self::MDS_NO_SUP_TABLES_ERROR         => 'Not found any supported tables in db %s in %s@%s',
        self::MDS_CONFIG_ERROR                => 'Can\'t open configuration file in %s',
        self::MDS_DB_URLS_ERROR               => 'Can\'t open urls db file %s',
        self::MDS_DROP_CONNECT_ERROR          => 'Lost connection to database: %s',
        self::MDS_NO_DATABASE                 => 'No database selected. Please, provide database name.',
        self::MDS_PRESCAN_CONFIG_ERROR        => 'Can\'t load prescan config from %s',
        self::MDS_REPORT_ERROR                => 'Can\'t write report to %s',
        self::MDS_CLEANUP_ERROR               => 'Error in cleanup during update table record.',
        self::MDS_RESTORE_UPDATE_ERROR        => 'Error in restore during update table record.',
        self::MDS_AVD_DB_NOTFOUND             => 'Failed loading DB from "%s": DB file not found.',
        self::MDS_AVD_DB_INVALID              => 'Failed loading DB from "%s": invalid DB format.',
        self::MDS_INVALID_CMS_CONFIG          => 'Failed loading CMS config %s',
        self::MDS_CMS_CONFIG_NOTSUP           => 'Can\'t parse config for CMS: %s',
        self::MDS_MULTIPLE_DBS                => 'For multiple DBs we support only scan, please select one db for work.',
        self::MDS_NO_SCANNED                  => 'No database to process.',
    ];

    public static function getErrorMessage($errcode, ...$args) {
        return vsprintf(self::MESSAGES[$errcode] ?? '', ...$args);
    }

}
class MDSException extends Exception
{
    private $_errcode = 0;
    private $_errmsg = '';

    public function __construct($errcode, ...$args)
    {
        $this->_errcode = $errcode;
        $this->_errmsg = MDSErrors::getErrorMessage($errcode, $args);
        parent::__construct($this->_errmsg);
    }

    public function getErrCode()
    {
        return $this->_errcode;
    }

    public function getErrMsg()
    {
        return $this->_errmsg;
    }
}
class MDSDBCredsFromConfig
{
    private $finder;
    private $creds = [];

    public function __construct($finder, $path)
    {
        $res = [];
        $this->finder = $finder;
        foreach ($this->finder->find($path) as $file_config) {
            $config = @file_get_contents($file_config, false, null, 0, 50000);
            if (preg_match('~define\(\s*\'DB_NAME\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
                $res['db_name'] = $matches[1];
            }
            if (preg_match('~define\(\s*\'DB_USER\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
                $res['db_user'] = $matches[1];
            }
            if (preg_match('~define\(\s*\'DB_PASSWORD\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
                $res['db_pass'] = $matches[1];
            }
            if (preg_match('~define\(\s*\'DB_HOST\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
                $host = explode(':', $matches[1]);
                $res['db_host'] = $host[0];
                $res['db_port'] = isset($host[1]) ? (int)$host[1] : 3306;
            }
            if (preg_match('~table_prefix\s*=\s*\'([^\']+)\';~msi', $config,$matches)) {
                $res['db_prefix'] = $matches[1];
            }

            if (isset($res['db_name']) && isset($res['db_user']) && isset($res['db_pass'])
                && isset($res['db_host']) && isset($res['db_port']) && isset($res['db_prefix'])
            ) {
                $this->creds[] = $res;
            }
        }
        $this->creds = array_unique($this->creds, SORT_REGULAR);
    }

    public function getCreds()
    {
        return $this->creds;
    }

    public function printCreds()
    {
        echo 'Found following db credentials: ' . PHP_EOL;
        foreach ($this->creds as $db_cred) {
            echo '--------------------------------------------------------' . PHP_EOL;
            echo 'Host:   ' . $db_cred['db_host']   . PHP_EOL;
            echo 'Port:   ' . $db_cred['db_port']   . PHP_EOL;
            echo 'User:   ' . $db_cred['db_user']   . PHP_EOL;
            echo 'Pass:   ' . $db_cred['db_pass']   . PHP_EOL;
            echo 'Name:   ' . $db_cred['db_name']   . PHP_EOL;
            echo 'Prefix: ' . $db_cred['db_prefix'] . PHP_EOL;
        }
    }

    public function printForXArgs()
    {
        foreach ($this->creds as $db_cred) {
            echo  $db_cred['db_host'] . ';;' . $db_cred['db_port'] . ';;' . $db_cred['db_user'] . ';;' . $db_cred['db_pass'] . ';;' . $db_cred['db_name'] . ';;' . $db_cred['db_prefix'] . PHP_EOL;
        }
    }

}
class MDSCMSConfigFilter
{
    private $followSymlink = true;

    public function __construct()
    {

    }

    private function fileExistsAndNotNull($path)
    {
        return (is_file($path) && file_exists($path) && (filesize($path) > 2048));
    }

    public function needToScan($file, $stat = false, $only_dir = false)
    {
        if (is_dir($file)) {
            return true;
        }
        if ($this->fileExistsAndNotNull($file) && basename($file) === 'wp-config.php') {
            return true;
        }
        return false;
    }

    public function isFollowSymlink()
    {
        return $this->followSymlink;
    }

}

class MDSCHRequest
{

    const API_URL = 'https://api.imunify360.com/api/send-message';
    const DEBUG_API_URL = 'http://127.0.0.1:8888';

    private $timeout = 10;
    private $debug = false;

    /**
     * MDSCHRequest constructor.
     * @param int $timeout
     */
    public function __construct($timeout = 10, $debug = false)
    {
        $this->timeout = $timeout;
        $this->debug = $debug;
    }

    /**
     * @param $data
     * @return bool|array
     */
    public function request($data)
    {
        $result = '';
        $json_data = json_encode($data);

        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->getApiUrl());
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
            $result = curl_exec($ch);
            curl_close($ch);
        } catch (Exception $e) {
            fwrite(STDERR, 'Warning: [MDS] Curl: ' . $e->getMessage() . PHP_EOL);
            return false;
        }
        return @json_decode($result, true);
    }

    private function getApiUrl()
    {
        return $this->debug ? self::DEBUG_API_URL : self::API_URL;
    }
}
class MDSSendToCH
{
    private $request = null;
    private $report = null;
    private $lic = null;

    public function __construct($request, $lic)
    {
        $this->request = $request;
        $this->lic = $lic;
    }

    public function prepareData($report)
    {
        $this->report = $report;
        $this->array_walk_recursive_delete($this->report, function($value, $key, $userdata) {
            if ($key === 'row_ids' || $key === 'rows_with_error') {
                return true;
            }
            return false;
        });
        $this->report = ['items' => [$this->report]];
    }

    public function send()
    {
        $license = $this->lic->getLicData();
        $data = [
            'method' => 'MDS_SCAN_LIST',
            'license' => $license,
            'payload' => $this->report,
            'server_id' => $license['id'],
        ];
        $res = $this->request->request($data);
        if ($res['status'] === 'ok') {
            return true;
        } else {
            fwrite(STDERR, 'Warning: [MDS] Invalid response: ' . json_encode($res) . PHP_EOL);
            return false;
        }
    }

    /**
     * Remove any elements where the callback returns true
     *
     * @param  array    $array    the array to walk
     * @param  callable $callback callback takes ($value, $key, $userdata)
     * @param  mixed    $userdata additional data passed to the callback.
     * @return array
     */
    private function array_walk_recursive_delete(array &$array, callable $callback, $userdata = null)
    {
        foreach ($array as $key => &$value) {
            if (is_array($value)) {
                $value = $this->array_walk_recursive_delete($value, $callback, $userdata);
            }
            if ($callback($value, $key, $userdata)) {
                unset($array[$key]);
            }
        }
        return $array;
    }
}

class MDSDetachedMode
{
    protected $workdir;
    protected $scan_id;
    protected $pid_file;
    protected $done_file;
    protected $sock_file;

    public function __construct($scan_id, $basedir = '/var/imunify360/aibolit/run', $sock_file = '/var/run/defence360agent/generic_sensor.sock.2')
    {
        $this->scan_id  = $scan_id;
        $this->setWorkDir($basedir, $scan_id);
        $this->pid_file     = $this->workdir . '/pid';
        $this->done_file    = $this->workdir . '/done';
        $this->setSocketFile($sock_file);
        $this->savePid();
        $this->checkWorkDir($this->workdir);
    }

    public function getWorkDir()
    {
        return $this->workdir;
    }

    protected function checkWorkDir($workdir)
    {
        if (!file_exists($workdir) && !mkdir($workdir) && !is_dir($workdir)) {
            die('Error! Cannot create workdir ' . $workdir . ' for detached scan.');
        } elseif (file_exists($workdir) && !is_writable($workdir)) {
            die('Error! Workdir ' . $workdir . ' is not writable.');
        } 
    }

    protected function savePid()
    {
        file_put_contents($this->pid_file, strval(getmypid()));
    }

    public function complete()
    {
        @touch($this->done_file);
        $complete = [
            'method'        => 'MALWARE_SCAN_COMPLETE',
            'scan_id'       => $this->scan_id,
            'resource_type' => 'db',
        ];
        $json_complete = json_encode($complete) . "\n";
        $socket = @fsockopen('unix://' . $this->sock_file);
        if (is_resource($socket)) {
            stream_set_blocking($socket, false);
            fwrite($socket, $json_complete);
            fclose($socket);
        }
    }

    protected function setWorkDir($dir, $scan_id)
    {
        $this->workdir = $dir . '/' . $scan_id;
    }

    protected function setSocketFile($sock)
    {
        $this->sock_file = $sock;
    }
}

class MDSDBCredsFromAVD
{
    protected $dbh;
    
    protected $avd_path_prev    = '/var/imunify360/components_versions.sqlite3';
    protected $avd_path         = '/var/lib/cloudlinux-app-version-detector/components_versions.sqlite3';
    protected $found_apps       = 0;
    private $path_field         = 'real_path';

    public function __construct()
    {
        $path = file_exists($this->avd_path) ? $this->avd_path : (file_exists($this->avd_path_prev) ? $this->avd_path_prev : '');

        if ($path === '') {
            throw new MDSException(MDSErrors::MDS_AVD_DB_NOTFOUND, $this->avd_path);
        }

        $this->openAppDB($path);
        if (!$this->haveTable('apps')) {
            throw new MDSException(MDSErrors::MDS_AVD_DB_INVALID, $this->avd_path);
        }
        if (!$this->haveColumn('apps', $this->path_field)) {
            $this->path_field = 'path';
        }
    }

    public function getCredsFromApps($paths, $apps = null, $recursive = false)
    {
        foreach($this->getApps($paths, $apps, $recursive) as $row) {
            $config = MDSCMSAddonFactory::getCMSConfigInstance($row['title'], $row[$this->path_field]);
            $res = $config->parseConfig();
            $res['app_owner_uid'] = $row['app_uid'] ?? null;
            yield $res;
        }
        $this->dbh = null;
    }

    public function getAppsCount()
    {
        return $this->found_apps;
    }

    public function countApps($paths, $apps = null, $recursive = false)
    {
        list($sql, $params) = $this->generateAppDBQuery($recursive, $apps, $paths);
        $count_sql = 'SELECT COUNT(*) as count FROM (' . $sql . ');';
        $result = $this->execQueryToAppDB($count_sql, $params);
        $this->found_apps = (int)$result->fetchArray(SQLITE3_NUM)[0];
    }

    ////////////////////////////////////////////////////////////////////////////
    
    private function getApps($paths, $apps, $recursive)
    {
        list($sql, $params) = $this->generateAppDBQuery($recursive, $apps, $paths);
        $res = $this->execQueryToAppDB($sql, $params);
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            yield $row;
        }
    }

    private function openAppDB($db)
    {
        $this->dbh = new \SQLite3($db);
    }
    
    private function haveColumn($table_name, $column_name)
    {
        $sql    = 'PRAGMA table_info("' . $table_name . '")';
        $stmt   = $this->dbh->prepare($sql);
        $result = $stmt->execute();
        while ($row = $result->fetchArray(SQLITE3_ASSOC))
        {
            if ($row['name'] == $column_name) {
                return true;
            }
        }
        return false;
    }    
    
    private function haveTable($table_name)
    {
        $sql = 'PRAGMA table_info("' . $table_name . '")';
        $stmt   = $this->dbh->prepare($sql);
        $result = $stmt->execute();
        return (bool)$result->fetchArray();
    }    

    /**
     * @param string $query
     * @param array  $params
     *
     * @return SQLite3Result
     */
    private function execQueryToAppDB(string $query, array $params)
    {
        $stmt  = $this->dbh->prepare($query);
        foreach ($params as $param_name => $param_value)
        {
            $stmt->bindValue($param_name, $param_value);
        }
        return $stmt->execute();
    }

    /**
     * @param $recursive
     * @param $apps
     * @param $paths
     *
     * @return array
     */
    private function generateAppDBQuery($recursive, $apps, $paths): array
    {
        $params = [];
        
        $sql = 'SELECT *'
            . ' FROM apps'
            . ' WHERE (';
        for ($i = 0, $iMax = count($paths); $i < $iMax; $i++) {
            $sql .= $this->path_field . ' ';
            $sql .= $recursive ? 'LIKE ' : '= ';
            $sql .= ':path' . $i;
            $params[':path' . $i] = $recursive ? $paths[$i] . '%' : $paths[$i];
            if ($i !== $iMax - 1) {
                $sql .= ' OR ';
            }
        }

        $sql .= ')';
        
        $sql .= isset($apps) ? ' AND title IN (' : '';
        for ($i = 0, $iMax = count($apps); $i < $iMax; $i++) {
            $sql .= ':app' . $i;
            $params[':app' . $i] = $apps[$i];
            if ($i !== $iMax - 1) {
                $sql .= ', ';
            }
        }
        $sql .= isset($apps) ? ')' : '';
        $sql .= ' GROUP BY ' . $this->path_field . ', title';

        return [$sql, $params];
    }

}

class MDSCMSAddonFactory
{
    public static function getCMSConfigInstance($app, $path)
    {
        $class = 'MDS' . ucfirst(str_replace('_', '', $app)) . 'Config';

        if (!class_exists($class)) {
            throw new MDSException(MDSErrors::MDS_CMS_CONFIG_NOTSUP, $app);
        }
        return new $class($path);
    }
}

class MDSCMSAddon
{
    protected const CONFIG_FILE = '';
    protected const MIN_SIZE = '1000';

    protected $app;
    protected $path;

    public function __construct($path)
    {
        if (!file_exists($path . '/' . static::CONFIG_FILE)
            || !is_readable($path . '/' . static::CONFIG_FILE)
            || (filesize($path . '/' . static::CONFIG_FILE) < static::MIN_SIZE)
        ) {
            throw new MDSException(MDSErrors::MDS_INVALID_CMS_CONFIG, $path . '/' . static::CONFIG_FILE);
        }

        $this->path = $path;
    }

    public function parseConfig()
    {

    }

}
class MDSAVDPathFilter
{
    private $ignoreList = [];

    public function __construct($filepath)
    {
        if (!file_exists($filepath) || !is_file($filepath) || !is_readable($filepath)) {
            return;
        }

        $content = file_get_contents($filepath);
        $list = explode("\n", $content);
        foreach ($list as $base64_filepath) {
            if ($base64_filepath !== '') {
                $this->ignoreList[$base64_filepath] = '';
            }
        }
    }

    public function needToScan($file)
    {
        $tree = $this->getTree($file);
        if ($this->pathRelatesTo($tree, $this->ignoreList, true)) {
            return false;
        }
        return true;
    }

    private function getTree($file)
    {
        $tree = [];
        $path = $file;
        while ($path !== '.' && $path !== '/') {
            $path = dirname($path, 1);
            $tree[] = $path;
        }
        $tree[] = $file;
        return $tree;
    }

    private function pathRelatesTo($tree, $pathes, $base64 = false)
    {
        foreach ($tree as $path) {
            if ($base64) {
                $path = base64_encode($path);
            }
            if (isset($pathes[$path])) {
                return true;
            }
        }
        return false;
    }
}

class MDSCollectUrlsRequest
{

    const API_URL = 'https://api.imunify360.com/api/mds/check-urls';
    const DEBUG_API_URL = 'http://127.0.0.1:8888';

    private $timeout = 10;
    private $debug = false;

    /**
     * MDSCollectUrlsRequest constructor.
     * @param int $timeout
     */
    public function __construct($timeout = 10, $debug = false)
    {
        $this->timeout = $timeout;
        $this->debug = $debug;
    }

    /**
     * @param $data
     * @return bool|array
     */
    public function request($data)
    {
        $result = '';
        $json_data = json_encode($data);

        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->getApiUrl());
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
            $result = curl_exec($ch);
            curl_close($ch);
        } catch (Exception $e) {
            fwrite(STDERR, 'Warning: [MDS] Curl: ' . $e->getMessage() . PHP_EOL);
            return false;
        }
        return @json_decode($result, true);
    }

    private function getApiUrl()
    {
        return $this->debug ? self::DEBUG_API_URL : self::API_URL;
    }
}
class MDSSendUrls
{
    private $request = null;

    public function __construct($request)
    {
        $this->request = $request;
    }

    public function send($urls)
    {
        $data = [
            'urls'      => $urls,
            'source'    => 'MDS',
        ];
        $res = $this->request->request($data);
        if ($res['status'] === 'ok') {
            return true;
        } else {
            fwrite(STDERR, 'Warning: [MDS] Invalid response: ' . json_encode($res) . PHP_EOL);
            return false;
        }
    }
}

class MDSWpcoreConfig extends MDSCMSAddon
{
    protected const CONFIG_FILE = 'wp-config.php';

    public function parseConfig()
    {
        $res = [];
        $config = @file_get_contents($this->path . '/' . self::CONFIG_FILE, false, null, 0, 50000);
        if (preg_match('~define\(\s*\'DB_NAME\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
            $res['db_name'] = $matches[1];
        }
        if (preg_match('~define\(\s*\'DB_USER\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
            $res['db_user'] = $matches[1];
        }
        if (preg_match('~define\(\s*\'DB_PASSWORD\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
            $res['db_pass'] = $matches[1];
        }
        if (preg_match('~table_prefix\s*=\s*\'([^\']+)\';~msi', $config,$matches)) {
            $res['db_prefix'] = $matches[1];
        }
        if (preg_match('~define\(\s*\'DB_HOST\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
            $host = explode(':', $matches[1]);
            $res['db_host'] = $host[0];
            $res['db_port'] = isset($host[1]) ? (int)$host[1] : 3306;
        }

        if (isset($res['db_name']) && isset($res['db_user']) && isset($res['db_pass']) && isset($res['db_host'])
            && isset($res['db_port']) && isset($res['db_prefix'])
        ) {
            $res['db_app'] = 'wp_core';
            $res['db_path'] = $this->path;
            return $res;
        } else {
            return false;
        }
    }
}
class LoadSignaturesForClean
{
    private $sig_db             = [];
    private $sig_db_meta_info   = [];
    private $sig_db_location    = 'internal';
    private $scan_db            = null;

    private $deMapper           = '';

    public function __construct($signature, $avdb)
    {

        $this->sig_db_meta_info = [
            'build-date'    => 'n/a',
            'version'       => 'n/a',
            'release-type'  => 'n/a',
        ];

        if ($signature) {
            $db_raw                 = explode("\n", trim(base64_decode(trim($signature))));
            $this->sig_db_location  = 'external';
        } elseif (file_exists($avdb)) {
            $db_raw                 = explode("\n", trim(@gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($avdb))))))));
            $this->sig_db_location  = 'external';
            echo "Loaded External DB\n";
        } else {
            InternalCleanSignatures::init();
            $db_raw = explode("\n", base64_decode(strrev(str_rot13(gzinflate(base64_decode(InternalCleanSignatures::$db))))));
        }
        
        foreach ($db_raw as $line) {
            $line = trim($line);
            if ($line == '') {
                continue;
            }

            $parsed = preg_split("/\t+/", $line);

            if ($parsed[0] == 'System-Data') {
                $meta_info                              = json_decode($parsed[3], true);
                $this->sig_db_meta_info['build-date']   = $meta_info['build-date'];
                $this->sig_db_meta_info['version']      = $meta_info['version'];
                $this->sig_db_meta_info['release-type'] = $meta_info['release-type'];
            } else {
                $db_item['id']          = $parsed[0];
                $db_item['mask_type']   = $parsed[1];

                $db_item['mask_type']   = str_replace('*.', '.*\.', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_ANY', '.*', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_PHP', '\.(suspected|vir|txt|phtml|pht|php\d*|php\..*)$', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_HTML', '\.(htm|html|tpl|inc)$', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_JS', '\.(js)$', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_SS', '.*', $db_item['mask_type']);

                $db_item['sig_type']    = (int)$parsed[2];
                $db_item['sig_match']   = str_replace('~', '\~', trim($parsed[3]));
                $db_item['sig_match']   = str_replace('@<v>@', '\$[a-zA-Z0-9_]+', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<id>@', '[a-zA-Z0-9_]+', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<d>@', '\d+', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<qq>@', '[\'"]', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<q>@', '[\'"]{0,1}', $db_item['sig_match']);
                $db_item['sig_replace'] = trim(@$parsed[4]);

                if ($db_item['sig_match'] == '') {
                    throw new Exception($line);
                }

                $this->sig_db[] = $db_item;
            }
        }
        $this->deMapper = @unserialize(@base64_decode($this->deMapper));
    }
    
    public function getDBLocation()
    {
        return $this->sig_db_location;
    }

    public function getDB()
    {
        return $this->sig_db;
    }
    
    public function getDBMetaInfo()
    {
        return $this->sig_db_meta_info;
    }

    public function getDeMapper()
    {
        return is_array($this->deMapper) ? $this->deMapper : false;
    }

    public function getScanDB()
    {
        return $this->scan_db;
    }

    public function setScanDB($db)
    {
        $this->scan_db = $db;
    }
}

class InternalCleanSignatures
{
    public static $db;

    public static function init()
    {
        $i000101010010110010 = '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'; //This variable will be filled by the building script.
        self::$db = $i000101010010110010;
    }
}
class ImLicense
{
    const VERIFY_FIELDS = ['id', 'status', 'group', 'limit', 'token_created_utc', 'token_expire_utc'];
    private $is_valid = false;
    private $raw_lic = [];
    private $valid_sign = '';
    private $pub_key = '';
    private $lic_path = '';
    private $pub_key_path = '';

    public function __construct($lic_path, $pub_key)
    {
        $this->lic_path = $lic_path;
        $this->pub_key_path = $pub_key;

        if (file_exists($lic_path) && filesize($lic_path) > 0 && is_readable($lic_path)) {
            $this->raw_lic = json_decode(file_get_contents($lic_path), true);
        }

        if (file_exists($pub_key) && filesize($pub_key) > 0 && is_readable($pub_key)) {
            $this->pub_key = file_get_contents($pub_key);
        }
        if ($this->isAllFieldsPresent()) {
            $this->findValidSignature();
        }
    }

    public function isValid()
    {
        return $this->is_valid;
    }

    public function getLicData()
    {
        if (!$this->is_valid || $this->valid_sign === '') {
            return false;
        }
        if (is_array($this->raw_lic) && $this->isAllFieldsPresent()) {
            return [
                'id'                => $this->raw_lic['id'],
                'status'            => $this->raw_lic['status'],
                'limit'             => $this->raw_lic['limit'],
                'token_created_utc' => $this->raw_lic['token_created_utc'],
                'token_expire_utc'  => $this->raw_lic['token_expire_utc'],
                'sign'              => $this->valid_sign,
            ];
        }
        return false;
    }

    private function isAllFieldsPresent()
    {
        if (!isset($this->raw_lic['signatures'])) {
            return false;
        }
        if ($this->pub_key === '') {
            return false;
        }
        foreach (self::VERIFY_FIELDS as $field) {
            if (!isset($this->raw_lic[$field])) {
                return false;
            }
        }
        return true;
    }

    private function findValidSignature()
    {
        foreach ($this->raw_lic['signatures'] as $sign) {
            $signature = base64_decode($sign);
            $content = '';
            foreach (self::VERIFY_FIELDS as $field) {
                $content .= $this->raw_lic[$field];
            }
            if (openssl_verify($content, $signature, $this->pub_key, OPENSSL_ALGO_SHA512)) {
                $this->valid_sign = $sign;
                $this->is_valid = true;
                return true;
            }
        }
        return false;
    }
}

class LoadSignaturesForScan
{
    private $sig_db             = [];
    private $sig_db_meta_info   = [];
    private $sig_db_location    = 'internal';

    private $mode;
    private $debug;

    public $_DBShe;
    public $X_DBShe;
    public $_FlexDBShe;
    public $X_FlexDBShe;
    public $XX_FlexDBShe;
    public $_ExceptFlex;
    public $_AdwareSig;
    public $_PhishingSig;
    public $_JSVirSig;
    public $X_JSVirSig;
    public $_SusDB;
    public $_SusDBPrio;
    public $_DeMapper;
    public $_Mnemo;

    public $whiteUrls;
    public $blackUrls;
    public $ownUrl = null;

    private $count;
    private $count_susp;
    private $result = 0;
    private $last_error = '';

    const SIGN_INTERNAL = 1;
    const SIGN_EXTERNAL = 2;
    const SIGN_IMPORT = 3;
    const SIGN_ERROR = 9;

    public function __construct($avdb_file, $mode, $debug)
    {
        $this->mode = $mode;
        $this->debug = $debug;
        $this->sig_db_meta_info = [
            'build-date'    => 'n/a',
            'version'       => 'n/a',
            'release-type'  => 'n/a',
        ];

        if ($avdb_file && file_exists($avdb_file)) {
            $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($avdb_file)))))));
            $this->sig_db_location  = 'external';

            $this->_DBShe       = explode("\n", base64_decode($avdb[0]));
            $this->X_DBShe      = explode("\n", base64_decode($avdb[1]));
            $this->_FlexDBShe   = explode("\n", base64_decode($avdb[2]));
            $this->X_FlexDBShe  = explode("\n", base64_decode($avdb[3]));
            $this->XX_FlexDBShe = explode("\n", base64_decode($avdb[4]));
            $this->_ExceptFlex  = explode("\n", base64_decode($avdb[5]));
            $this->_AdwareSig   = explode("\n", base64_decode($avdb[6]));
            $this->_PhishingSig = explode("\n", base64_decode($avdb[7]));
            $this->_JSVirSig    = explode("\n", base64_decode($avdb[8]));
            $this->X_JSVirSig   = explode("\n", base64_decode($avdb[9]));
            $this->_SusDB       = explode("\n", base64_decode($avdb[10]));
            $this->_SusDBPrio   = explode("\n", base64_decode($avdb[11]));
            $this->_DeMapper    = array_combine(explode("\n", base64_decode($avdb[12])), explode("\n", base64_decode($avdb[13])));
            $this->_Mnemo       = @array_flip(@array_combine(explode("\n", base64_decode($avdb[14])), explode("\n", base64_decode($avdb[15]))));

            // get meta information
            $avdb_meta_info = json_decode(base64_decode($avdb[16]), true);

            $this->sig_db_meta_info['build-date'] = $avdb_meta_info ? $avdb_meta_info['build-date'] : 'n/a';
            $this->sig_db_meta_info['version'] = $avdb_meta_info ? $avdb_meta_info['version'] : 'n/a';
            $this->sig_db_meta_info['release-type'] = $avdb_meta_info ? $avdb_meta_info['release-type'] : 'n/a';

            if (count($this->_DBShe) <= 1) {
                $this->_DBShe = [];
            }

            if (count($this->X_DBShe) <= 1) {
                $this->X_DBShe = [];
            }

            if (count($this->_FlexDBShe) <= 1) {
                $this->_FlexDBShe = [];
            }

            if (count($this->X_FlexDBShe) <= 1) {
                $this->X_FlexDBShe = [];
            }

            if (count($this->XX_FlexDBShe) <= 1) {
                $this->XX_FlexDBShe = [];
            }

            if (count($this->_ExceptFlex) <= 1) {
                $this->_ExceptFlex = [];
            }

            if (count($this->_AdwareSig) <= 1) {
                $this->_AdwareSig = [];
            }

            if (count($this->_PhishingSig) <= 1) {
                $this->_PhishingSig = [];
            }

            if (count($this->X_JSVirSig) <= 1) {
                $this->X_JSVirSig = [];
            }

            if (count($this->_JSVirSig) <= 1) {
                $this->_JSVirSig = [];
            }

            if (count($this->_SusDB) <= 1) {
                $this->_SusDB = [];
            }

            if (count($this->_SusDBPrio) <= 1) {
                $this->_SusDBPrio = [];
            }

            $this->result = self::SIGN_EXTERNAL;
        } else {
            InternalSignatures::init();
            $this->_DBShe       = InternalSignatures::$_DBShe;
            $this->X_DBShe      = InternalSignatures::$X_DBShe;
            $this->_FlexDBShe   = InternalSignatures::$_FlexDBShe;
            $this->X_FlexDBShe  = InternalSignatures::$X_FlexDBShe;
            $this->XX_FlexDBShe = InternalSignatures::$XX_FlexDBShe;
            $this->_ExceptFlex  = InternalSignatures::$_ExceptFlex;
            $this->_AdwareSig   = InternalSignatures::$_AdwareSig;
            $this->_PhishingSig = InternalSignatures::$_PhishingSig;
            $this->_JSVirSig    = InternalSignatures::$_JSVirSig;
            $this->X_JSVirSig   = InternalSignatures::$X_JSVirSig;
            $this->_SusDB       = InternalSignatures::$_SusDB;
            $this->_SusDBPrio   = InternalSignatures::$_SusDBPrio;
            $this->_DeMapper    = InternalSignatures::$_DeMapper;
            $this->_Mnemo       = InternalSignatures::$_Mnemo;

            // get meta information
            $avdb_meta_info = InternalSignatures::$db_meta_info;

            $this->sig_db_meta_info['build-date'] = $avdb_meta_info ? $avdb_meta_info['build-date'] : 'n/a';
            $this->sig_db_meta_info['version'] = $avdb_meta_info ? $avdb_meta_info['version'] : 'n/a';
            $this->sig_db_meta_info['release-type'] = $avdb_meta_info ? $avdb_meta_info['release-type'] : 'n/a';

            $this->result = self::SIGN_INTERNAL;
        }

        // use only basic signature subset
        if ($mode < 2) {
            $this->X_FlexDBShe  = [];
            $this->XX_FlexDBShe = [];
            $this->X_JSVirSig   = [];
        }

        // Load custom signatures
        if (file_exists(__DIR__ . '/ai-bolit.sig')) {
            try {
                $s_file = new SplFileObject(__DIR__ . '/ai-bolit.sig');
                $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
                foreach ($s_file as $line) {
                    $this->_FlexDBShe[] = preg_replace('#\G(?:[^~\\\\]+|\\\\.)*+\K~#', '\\~', $line); // escaping ~
                }

                $this->result = self::SIGN_IMPORT;
                $s_file = null; // file handler is closed
            }
            catch (Exception $e) {
                $this->result = self::SIGN_ERROR;
                $this->last_error = $e->getMessage();
            }
        }

        $this->count = count($this->_JSVirSig) + count($this->X_JSVirSig) + count($this->_DBShe) + count($this->X_DBShe) + count($this->_FlexDBShe) + count($this->X_FlexDBShe) + count($this->XX_FlexDBShe);
        $this->count_susp = $this->count + count($this->_SusDB);

        if (!$debug) {
            $this->OptimizeSignatures();
        }

        $this->_DBShe  = array_map('strtolower', $this->_DBShe);
        $this->X_DBShe = array_map('strtolower', $this->X_DBShe);
    }

    private function OptimizeSignatures()
    {
        ($this->mode == 2) && ($this->_FlexDBShe = array_merge($this->_FlexDBShe, $this->X_FlexDBShe, $this->XX_FlexDBShe));
        ($this->mode == 1) && ($this->_FlexDBShe = array_merge($this->_FlexDBShe, $this->X_FlexDBShe));
        $this->X_FlexDBShe = $this->XX_FlexDBShe = [];

        ($this->mode == 2) && ($this->_JSVirSig = array_merge($this->_JSVirSig, $this->X_JSVirSig));
        $this->X_JSVirSig = [];

        $count = count($this->_FlexDBShe);

        for ($i = 0; $i < $count; $i++) {
            if ($this->_FlexDBShe[$i] == '[a-zA-Z0-9_]+?\(\s*[a-zA-Z0-9_]+?=\s*\)')
                $this->_FlexDBShe[$i] = '\((?<=[a-zA-Z0-9_].)\s*[a-zA-Z0-9_]++=\s*\)';
            if ($this->_FlexDBShe[$i] == '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e')
                $this->_FlexDBShe[$i] = '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e';
            if ($this->_FlexDBShe[$i] == '$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.')
                $this->_FlexDBShe[$i] = '\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.';

            $this->_FlexDBShe[$i] = str_replace('http://.+?/.+?\.php\?a', 'http://[^?\s]++(?<=\.php)\?a', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = preg_replace('~\[a-zA-Z0-9_\]\+\K\?~', '+', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = preg_replace('~^\\\\[d]\+&@~', '&@(?<=\d..)', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = str_replace('\s*[\'"]{0,1}.+?[\'"]{0,1}\s*', '.+?', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = str_replace('[\'"]{0,1}.+?[\'"]{0,1}', '.+?', $this->_FlexDBShe[$i]);

            $this->_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $this->_FlexDBShe[$i]);
        }

        $this->optSig($this->_FlexDBShe);

        $this->optSig($this->_JSVirSig);
        $this->optSig($this->_AdwareSig);
        $this->optSig($this->_PhishingSig);
        $this->optSig($this->_SusDB);
        //optSig($g_SusDBPrio);
        //optSig($g_ExceptFlex);

        // convert exception rules
        $cnt = count($this->_ExceptFlex);
        for ($i = 0; $i < $cnt; $i++) {
            $this->_ExceptFlex[$i] = trim(Normalization::normalize($this->_ExceptFlex[$i]));
            if ($this->_ExceptFlex[$i] == '')
                unset($this->_ExceptFlex[$i]);
        }

        $this->_ExceptFlex = array_values($this->_ExceptFlex);
    }

    private function optSig(&$sigs)
    {
        $sigs = array_unique($sigs);

        // Add SigId
        foreach ($sigs as &$s) {
            $s .= '(?<X' . AibolitHelpers::myCheckSum($s) . '>)';
        }
        unset($s);

        $fix = [
            '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e' => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
            'http://.+?/.+?\.php\?a' => 'http://[^?\s]++(?<=\.php)\?a',
            '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*' => '.+?',
            '[\'"]{0,1}.+?[\'"]{0,1}' => '.+?'
        ];

        $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);

        $fix = [
            '~^\\\\[d]\+&@~' => '&@(?<=\d..)',
            '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~' => ''
        ];

        $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);

        $this->optSigCheck($sigs);

        $tmp = [];
        foreach ($sigs as $i => $s) {
            if (!preg_match('~^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$~', $s)) {
                unset($sigs[$i]);
                $tmp[] = $s;
            }
        }

        usort($sigs, 'strcasecmp');
        $txt = implode("\n", $sigs);

        for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
            $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', [$this, 'optMergePrefixes'], $txt);
        }

        $sigs = array_merge(explode("\n", $txt), $tmp);

        $this->optSigCheck($sigs);
    }

    private function optMergePrefixes($m)
    {
        $limit = 8000;

        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $len = $prefix_len;
        $r   = [];

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {

            if (strlen($line) > $limit) {
                $r[] = $line;
                continue;
            }

            $s = substr($line, $prefix_len);
            $len += strlen($s);
            if ($len > $limit) {
                if (count($suffixes) == 1) {
                    $r[] = $prefix . $suffixes[0];
                } else {
                    $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
                }
                $suffixes = [];
                $len      = $prefix_len + strlen($s);
            }
            $suffixes[] = $s;
        }

        if (!empty($suffixes)) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
        }

        return implode("\n", $r);
    }

    private function optMergePrefixes_Old($m)
    {
        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {
            $suffixes[] = substr($line, $prefix_len);
        }

        return $prefix . '(?:' . implode('|', $suffixes) . ')';
    }

    /*
     * Checking errors in pattern
     */
    private function optSigCheck(&$sigs)
    {
        $result = true;

        foreach ($sigs as $k => $sig) {
            if (trim($sig) == "") {
                if ($this->debug) {
                    echo ("************>>>>> EMPTY\n     pattern: " . $sig . "\n");
                }
                unset($sigs[$k]);
                $result = false;
            }

            if (@preg_match('~' . $sig . '~smiS', '') === false) {
                $error = error_get_last();
                if ($this->debug) {
                    echo ("************>>>>> " . $error['message'] . "\n     pattern: " . $sig . "\n");
                }
                unset($sigs[$k]);
                $result = false;
            }
        }

        return $result;
    }

    public static function getSigId($l_Found)
    {
        foreach ($l_Found as $key => &$v) {
            if (is_string($key) && $v[1] != -1 && strlen($key) == 9) {
                return substr($key, 1);
            }
        }

        return null;
    }

    public function setOwnUrl($url)
    {
        if (isset($this->blackUrls)) {
            foreach ($this->blackUrls->getDb() as $black) {
                if (preg_match('~' . $black . '~msi', $url)) {
                    $this->ownUrl = null;
                    return;
                }
            }
        }
        $this->ownUrl = $url;
    }

    public function getOwnUrl()
    {
        return $this->ownUrl;
    }

    public function getDBLocation()
    {
        return $this->sig_db_location;
    }

    public function getDB()
    {
        return $this->sig_db;
    }

    public function getDBMetaInfo()
    {
        return $this->sig_db_meta_info;
    }

    public function getDBMetaInfoVersion()
    {
        return $this->sig_db_meta_info['version'];
    }

    public function getDBCount()
    {
        return $this->count;
    }

    public function getDBCountWithSuspicious()
    {
        return $this->count_susp;
    }

    public function getResult()
    {
        return $this->result;
    }

    public function getLastError()
    {
        return $this->last_error;
    }
}

class InternalSignatures
{
    public static $_DBShe;
    public static $X_DBShe;
    public static $_FlexDBShe;
    public static $X_FlexDBShe;
    public static $XX_FlexDBShe;
    public static $_ExceptFlex;
    public static $_AdwareSig;
    public static $_PhishingSig;
    public static $_JSVirSig;
    public static $X_JSVirSig;
    public static $_SusDB;
    public static $_SusDBPrio;
    public static $_DeMapper;
    public static $_Mnemo;
    public static $db_meta_info;

    public static function init()
    {
        //BEGIN_SIG 25/02/2021 11:42:32
self::$_DBShe = unserialize(gzinflate(/*1614242552*/base64_decode("S7QysKquBQA=")));
self::$X_DBShe = unserialize(gzinflate(/*1614242552*/base64_decode("S7QysKquBQA=")));
self::$_FlexDBShe = unserialize(gzinflate(/*1614242552*/base64_decode("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")));
self::$X_FlexDBShe = unserialize(gzinflate(/*1614242552*/base64_decode("S7QysKquBQA=")));
self::$XX_FlexDBShe = unserialize(gzinflate(/*1614242552*/base64_decode("S7QysKquBQA=")));
self::$_ExceptFlex = unserialize(gzinflate(/*1614242552*/base64_decode("S7QysKquBQA=")));
self::$_AdwareSig = unserialize(gzinflate(/*1614242552*/base64_decode("S7QysKquBQA=")));
self::$_PhishingSig = unserialize(gzinflate(/*1614242552*/base64_decode("S7QysKquBQA=")));
self::$_JSVirSig = unserialize(gzinflate(/*1614242552*/base64_decode("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")));
self::$X_JSVirSig = unserialize(gzinflate(/*1614242552*/base64_decode("S7QysKquBQA=")));
self::$_SusDB = unserialize(gzinflate(/*1614242552*/base64_decode("ZY5BboMwEEXvwiLFDYoxiZRgB1jkGB6QjIFiRRRi06LK8t1rZ1NFXczoz2j++yPokVpFU2boJaMRtPGACv4W1YOep9sYFAMC++dO6Nvr4vExd30QwEM3X61Z9XOuIYZuD4hFTFHi6YR4/DVWgxZTj2B8N1r6XvgKBox5g2ubJqfU4U2scoQDdPaSkMxBde9/CtjsMXO7uKJiWhiq7lvBG++0JE9InrtA4U0ZGH4qrxhIGcIzH34+hWwjtVpW9HcE7esT47oupqIYy1l9juq7h4OcJ/yf6n4B")));
self::$_SusDBPrio = unserialize(gzinflate(/*1614242552*/base64_decode("S7QysKquBQA=")));
self::$_Mnemo = unserialize(gzinflate(/*1614242552*/base64_decode("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")));
self::$_DeMapper = unserialize(base64_decode("YTo1OntzOjEwOiJ3aXphcmQucGhwIjtzOjM3OiJjbGFzcyBXZWxjb21lU3RlcCBleHRlbmRzIENXaXphcmRTdGVwIjtzOjE3OiJ1cGRhdGVfY2xpZW50LnBocCI7czozNzoieyBDVXBkYXRlQ2xpZW50OjpBZGRNZXNzYWdlMkxvZygiZXhlYyI7czoxMToiaW5jbHVkZS5waHAiO3M6NDg6IkdMT0JBTFNbIlVTRVIiXS0+SXNBdXRob3JpemVkKCkgJiYgJGFyQXV0aFJlc3VsdCI7czo5OiJzdGFydC5waHAiO3M6NjA6IkJYX1JPT1QuJy9tb2R1bGVzL21haW4vY2xhc3Nlcy9nZW5lcmFsL3VwZGF0ZV9kYl91cGRhdGVyLnBocCI7czoxMDoiaGVscGVyLnBocCI7czo1ODoiSlBsdWdpbkhlbHBlcjo6Z2V0UGx1Z2luKCJzeXN0ZW0iLCJvbmVjbGlja2NoZWNrb3V0X3ZtMyIpOyI7fQ=="));
self::$db_meta_info = unserialize(base64_decode("YTozOntzOjEwOiJidWlsZC1kYXRlIjtzOjEwOiIxNjE0MTY2NjkyIjtzOjc6InZlcnNpb24iO3M6MTM6IjIwMjEwMjI0LTQ4ODAiO3M6MTI6InJlbGVhc2UtdHlwZSI7czoxMDoicHJvZHVjdGlvbiI7fQ=="));

//END_SIG
    }
}

class AibolitHelpers
{
    /**
     * Format bytes to human readable
     *
     * @param int $bytes
     *
     * @return string
     */
    public static function bytes2Human($bytes)
    {
        if ($bytes < 1024) {
            return $bytes . ' b';
        } elseif (($kb = $bytes / 1024) < 1024) {
            return number_format($kb, 2) . ' Kb';
        } elseif (($mb = $kb / 1024) < 1024) {
            return number_format($mb, 2) . ' Mb';
        } elseif (($gb = $mb / 1024) < 1024) {
            return number_format($gb, 2) . ' Gb';
        } else {
            return number_format($gb / 1024, 2) . 'Tb';
        }
    }

    /**
     * Seconds to human readable
     * @param int $seconds
     * @return string
     */
    public static function seconds2Human($seconds)
    {
        $r        = '';
        $_seconds = floor($seconds);
        $ms       = $seconds - $_seconds;
        $seconds  = $_seconds;
        if ($hours = floor($seconds / 3600)) {
            $r .= $hours . ' h ';
            $seconds %= 3600;
        }

        if ($minutes = floor($seconds / 60)) {
            $r .= $minutes . ' m ';
            $seconds %= 60;
        }

        if ($minutes < 3) {
            $r .= ' ' . (string)($seconds + ($ms > 0 ? round($ms) : 0)) . ' s';
        }

        return $r;
    }

    /**
     * Get bytes from shorthand byte values (1M, 1G...)
     * @param int|string $val
     * @return int
     */
    public static function getBytes($val)
    {
        $val  = trim($val);
        $last = strtolower($val[strlen($val) - 1]);
        switch ($last) {
            case 't':
                $val *= 1024;
            case 'g':
                $val *= 1024;
            case 'm':
                $val *= 1024;
            case 'k':
                $val *= 1024;
        }
        return intval($val);
    }

    /**
     * Convert dangerous chars to html entities
     *
     * @param        $par_Str
     * @param string $addPrefix
     * @param string $noPrefix
     * @param bool   $replace_path
     *
     * @return string
     */
    public static function makeSafeFn($par_Str, $addPrefix = '', $noPrefix = '', $replace_path = false)
    {
        if ($replace_path) {
            $lines = explode("\n", $par_Str);
            array_walk($lines, static function(&$n) use ($addPrefix, $noPrefix) {
                $n = $addPrefix . str_replace($noPrefix, '', $n);
            });

            $par_Str = implode("\n", $lines);
        }

        return htmlspecialchars($par_Str, ENT_SUBSTITUTE | ENT_QUOTES);
    }


    public static function myCheckSum($str)
    {
        return hash('crc32b', $str);
    }

}

class Finder
{
    const MAX_ALLOWED_PHP_HTML_IN_DIR = 600;

    private $sym_links              = [];
    private $skipped_folders        = [];
    private $doorways               = [];
    private $big_files              = [];
    private $big_elf_files          = [];

    private $collect_skipped        = false;
    private $collect_symLinks       = false;
    private $collect_doorways       = false;
    private $collect_bigfiles       = false;
    private $collect_bigelffiles    = false;

    private $total_dir_counter      = 0;
    private $total_files_counter    = 0;
    private $checked_hashes         = [];

    private $initial_dir            = '';
    private $initial_level          = null;
    private $level_limit            = null;

    private $filter;

    public function __construct($filter = null, $level_limit = null)
    {
        $this->filter = $filter;
        $this->level_limit = $level_limit;
    }

    private function linkResolve($path)
    {
        return realpath($path);
    }

    private function resolve($path, $follow_symlinks)
    {
        if (!$follow_symlinks || !is_link($path)) {
            return $path;
        }
        return $this->linkResolve($path);
    }

    private function isPathCheckedAlready($path)
    {
        $root_hash = crc32($path);
        if (isset($this->checked_hashes[$root_hash])) {
            return true;
        }
        $this->checked_hashes[$root_hash] = '';
        return false;
    }

    private function walk($path, $follow_symlinks)
    {
        $level = substr_count($path, '/');
        if (isset($this->level_limit) && (($level - $this->initial_level + 1) > $this->level_limit)) {
            return;
        }
        $l_DirCounter          = 0;
        $l_DoorwayFilesCounter = 0;

        if ($follow_symlinks && $this->isPathCheckedAlready($path)) {
            return;
        }

        # will not iterate dir, if it should be ignored
        if (!$this->filter->needToScan($path, false, true)) {
            if ($this->collect_skipped) {
                $this->skipped_folders[] = $path;
            }
            return;
        }
        $dirh = @opendir($path);
        if ($dirh === false) {
            return;
        }

        while (($entry = readdir($dirh)) !== false) {
            if ($entry == '.' || $entry == '..') {
                continue;
            }
            $entry = $path . DIRECTORY_SEPARATOR . $entry;
            if (is_link($entry)) {

                if ($this->collect_symLinks) {
                    $this->sym_links[] = $entry;
                }

                if (!$follow_symlinks) {
                    continue;
                }
                $real_path = $this->resolve($entry, true);
            } else {
                $real_path = $entry;
            }
            if (is_dir($entry)) {
                $l_DirCounter++;
                if ($this->collect_doorways && $l_DirCounter > self::MAX_ALLOWED_PHP_HTML_IN_DIR) {
                    $this->doorways[]  = $path;
                    $l_DirCounter = -655360;
                }
                $this->total_dir_counter++;
                yield from $this->walk($real_path, $follow_symlinks);
            } else if (is_file($entry)) {
                $stat = stat($entry);
                if (!$stat) {
                    continue;
                }
                if ($this->collect_doorways && is_callable([$this->filter, 'checkShortExt']) && $this->filter->checkShortExt($entry)) {
                    $l_DoorwayFilesCounter++;
                    if ($l_DoorwayFilesCounter > self::MAX_ALLOWED_PHP_HTML_IN_DIR) {
                        $this->doorways[]           = $path;
                        $l_DoorwayFilesCounter = -655360;
                    }
                }
                if ($follow_symlinks && $this->isPathCheckedAlready($real_path)) {
                    continue;
                }
                if ($this->collect_bigfiles && is_callable([$this->filter, 'checkIsBig']) && $this->filter->checkIsBig($real_path)) {
                    $this->big_files[] = $real_path;
                }
                if ($this->collect_bigelffiles
                    && is_callable([$this->filter, 'checkIsBig']) && $this->filter->checkIsBig($real_path)
                    && is_callable([$this->filter, 'checkIsElf']) && $this->filter->checkIsElf($real_path)
                ) {
                    $this->big_elf_files[] = $real_path;
                }
                $need_to_scan = $this->filter->needToScan($real_path, $stat);
                if ($need_to_scan) {
                    $this->total_files_counter++;
                    yield $real_path;
                }
            }
        }
        closedir($dirh);
    }

    private function expandPath($path, $follow_symlinks)
    {
        if ($path) {
            if (is_dir($path)) {
                yield from $this->walk($path, $follow_symlinks);
            } else {
                if ($this->collect_bigfiles && is_callable([$this->filter, 'checkIsBig']) && $this->filter->checkIsBig($path)) {
                    $this->big_files[] = $path;
                    if ($this->collect_bigelffiles && is_callable([$this->filter, 'checkIsElf']) && $this->filter->checkIsElf($path)) {
                        $this->big_elf_files[] = $path;
                    }
                }
                $need_to_scan = $this->filter->needToScan($path);
                if ($need_to_scan) {
                    yield $path;
                }
            }
        }
    }

    public function find($target)
    {
        if ($target === '/') {
            $target = '/*';
        }
        if (is_string($target) && substr($target, -1) == DIRECTORY_SEPARATOR) {
            $target = substr($target, 0, -1);
        }

        if (is_callable([$this->filter, 'getGenerated']) && !$this->filter->getGenerated()
            && is_callable([$this->filter, 'generateCheckers'])
        ) {
            $this->filter->generateCheckers();
        }

        # We shouldn't use iglob for list of paths,
        # cause they cannot contain * or regexp
        # but can contain invalid sequence e.g. [9-0]
        $paths = is_array($target) ? $target : new GlobIterator($target, FilesystemIterator::CURRENT_AS_PATHNAME);
        foreach ($paths as $path) {
            $this->initial_dir = realpath($path);
            $this->initial_level = substr_count($this->initial_dir, '/');
            $path = $this->linkResolve($path);
            yield from $this->expandPath($path, $this->filter->isFollowSymlink());
        }
    }

    private function convertTemplatesToRegexp($templates)
    {
        return '~(' . str_replace([',', '.', '*'], ['|', '\\.', '.*'], $templates) . ')~i';
    }

    public function setLevelLimit($level)
    {
        $this->level_limit = $level;
    }

    public function getSymlinks()
    {
        return $this->sym_links;
    }

    public function getBigFiles()
    {
        return $this->big_files;
    }

    public function getBigElfFiles()
    {
        return $this->big_elf_files;
    }

    public function setCollectDoorways($flag)
    {
        $this->collect_doorways = $flag;
    }

    public function setCollectBigElfs($flag)
    {
        $this->collect_bigelffiles = $flag;
    }

    public function setCollectSymlinks($flag)
    {
        $this->collect_symLinks = $flag;
    }

    public function setCollectSkipped($flag)
    {
        $this->collect_skipped = $flag;
    }

    public function setCollectBigFiles($flag)
    {
        $this->collect_bigfiles = $flag;
    }

    public function getDoorways()
    {
        return $this->doorways;
    }

    public function skippedDirs()
    {
        return $this->skipped_folders;
    }

    public function getTotalDirs()
    {
        return $this->total_dir_counter;
    }

    public function getTotalFiles()
    {
        return $this->total_files_counter;
    }

    public function getFilter()
    {
        return $this->filter;
    }
}
class StringToStreamWrapper {

    const WRAPPER_NAME = 'var';

    private static $_content;
    private $_position;

    /**
     * Prepare a new memory stream with the specified content
     * @return string
     */
    public static function prepare($content)
    {
        if (!in_array(self::WRAPPER_NAME, stream_get_wrappers())) {
            stream_wrapper_register(self::WRAPPER_NAME, get_class());
        }
        self::$_content = $content;
    }

    public function stream_open($path, $mode, $options, &$opened_path)
    {
        $this->_position = 0;
        return true;
    }

    public function stream_read($count)
    {
        $ret = substr(self::$_content, $this->_position, $count);
        $this->_position += strlen($ret);
        return $ret;
    }

    public function stream_stat()
    {
        return [];
    }

    public function stream_eof()
    {
        return $this->_position >= strlen(self::$_content);
    }

    public function stream_set_option($option , $arg1, $arg2 )
    {
        return true;
    }
}

class Normalization
{
    const MAX_ITERATION = 10;

    private static $confusables = "YToxNTY1OntzOjM6IuKAqCI7czoxOiIgIjtzOjM6IuKAqSI7czoxOiIgIjtzOjM6IuGagCI7czoxOiIgIjtzOjM6IuKAgCI7czoxOiIgIjtzOjM6IuKAgSI7czoxOiIgIjtzOjM6IuKAgiI7czoxOiIgIjtzOjM6IuKAgyI7czoxOiIgIjtzOjM6IuKAhCI7czoxOiIgIjtzOjM6IuKAhSI7czoxOiIgIjtzOjM6IuKAhiI7czoxOiIgIjtzOjM6IuKAiCI7czoxOiIgIjtzOjM6IuKAiSI7czoxOiIgIjtzOjM6IuKAiiI7czoxOiIgIjtzOjM6IuKBnyI7czoxOiIgIjtzOjI6IsKgIjtzOjE6IiAiO3M6Mzoi4oCHIjtzOjE6IiAiO3M6Mzoi4oCvIjtzOjE6IiAiO3M6Mjoiw4IiO3M6MToiICI7czoyOiLfuiI7czoxOiJfIjtzOjM6Iu+5jSI7czoxOiJfIjtzOjM6Iu+5jiI7czoxOiJfIjtzOjM6Iu+5jyI7czoxOiJfIjtzOjM6IuKAkCI7czoxOiItIjtzOjM6IuKAkSI7czoxOiItIjtzOjM6IuKAkiI7czoxOiItIjtzOjM6IuKAkyI7czoxOiItIjtzOjM6Iu+5mCI7czoxOiItIjtzOjI6ItuUIjtzOjE6Ii0iO3M6Mzoi4oGDIjtzOjE6Ii0iO3M6Mjoiy5ciO3M6MToiLSI7czozOiLiiJIiO3M6MToiLSI7czozOiLinpYiO3M6MToiLSI7czozOiLisroiO3M6MToiLSI7czoyOiLYjSI7czoxOiIsIjtzOjI6ItmrIjtzOjE6IiwiO3M6Mzoi4oCaIjtzOjE6IiwiO3M6MjoiwrgiO3M6MToiLCI7czozOiLqk7kiO3M6MToiLCI7czoyOiLNviI7czoxOiI7IjtzOjM6IuCkgyI7czoxOiI6IjtzOjM6IuCqgyI7czoxOiI6IjtzOjM6Iu+8miI7czoxOiI6IjtzOjI6ItaJIjtzOjE6IjoiO3M6Mjoi3IMiO3M6MToiOiI7czoyOiLchCI7czoxOiI6IjtzOjM6IuGbrCI7czoxOiI6IjtzOjM6Iu+4sCI7czoxOiI6IjtzOjM6IuGggyI7czoxOiI6IjtzOjM6IuGgiSI7czoxOiI6IjtzOjM6IuKBmiI7czoxOiI6IjtzOjI6IteDIjtzOjE6IjoiO3M6Mjoiy7giO3M6MToiOiI7czozOiLqnokiO3M6MToiOiI7czozOiLiiLYiO3M6MToiOiI7czoyOiLLkCI7czoxOiI6IjtzOjM6IuqTvSI7czoxOiI6IjtzOjM6Iu+8gSI7czoxOiIhIjtzOjI6IseDIjtzOjE6IiEiO3M6Mzoi4rWRIjtzOjE6IiEiO3M6MjoiypQiO3M6MToiPyI7czoyOiLJgSI7czoxOiI/IjtzOjM6IuClvSI7czoxOiI/IjtzOjM6IuGOriI7czoxOiI/IjtzOjM6IuqbqyI7czoxOiI/IjtzOjQ6IvCdha0iO3M6MToiLiI7czozOiLigKQiO3M6MToiLiI7czoyOiLcgSI7czoxOiIuIjtzOjI6ItyCIjtzOjE6Ii4iO3M6Mzoi6piOIjtzOjE6Ii4iO3M6NDoi8JCpkCI7czoxOiIuIjtzOjI6ItmgIjtzOjE6Ii4iO3M6Mjoi27AiO3M6MToiLiI7czozOiLqk7giO3M6MToiLiI7czozOiLjg7siO3M6MToityI7czozOiLvvaUiO3M6MToityI7czozOiLhm6siO3M6MToityI7czoyOiLOhyI7czoxOiK3IjtzOjM6IuK4sSI7czoxOiK3IjtzOjQ6IvCQhIEiO3M6MToityI7czozOiLigKIiO3M6MToityI7czozOiLigKciO3M6MToityI7czozOiLiiJkiO3M6MToityI7czozOiLii4UiO3M6MToityI7czozOiLqno8iO3M6MToityI7czozOiLhkKciO3M6MToityI7czoyOiLVnSI7czoxOiInIjtzOjM6Iu+8hyI7czoxOiInIjtzOjM6IuKAmCI7czoxOiInIjtzOjM6IuKAmSI7czoxOiInIjtzOjM6IuKAmyI7czoxOiInIjtzOjM6IuKAsiI7czoxOiInIjtzOjM6IuKAtSI7czoxOiInIjtzOjI6ItWaIjtzOjE6IiciO3M6Mjoi17MiO3M6MToiJyI7czoxOiJgIjtzOjE6IiciO3M6Mzoi4b+vIjtzOjE6IiciO3M6Mzoi772AIjtzOjE6IiciO3M6MjoiwrQiO3M6MToiJyI7czoyOiLOhCI7czoxOiInIjtzOjM6IuG/vSI7czoxOiInIjtzOjM6IuG+vSI7czoxOiInIjtzOjM6IuG+vyI7czoxOiInIjtzOjM6IuG/viI7czoxOiInIjtzOjI6Isq5IjtzOjE6IiciO3M6MjoizbQiO3M6MToiJyI7czoyOiLLiCI7czoxOiInIjtzOjI6IsuKIjtzOjE6IiciO3M6Mjoiy4siO3M6MToiJyI7czoyOiLLtCI7czoxOiInIjtzOjI6Isq7IjtzOjE6IiciO3M6Mjoiyr0iO3M6MToiJyI7czoyOiLKvCI7czoxOiInIjtzOjI6Isq+IjtzOjE6IiciO3M6Mzoi6p6MIjtzOjE6IiciO3M6Mjoi15kiO3M6MToiJyI7czoyOiLftCI7czoxOiInIjtzOjI6It+1IjtzOjE6IiciO3M6Mzoi4ZGKIjtzOjE6IiciO3M6Mzoi4ZuMIjtzOjE6IiciO3M6NDoi8Ja9kSI7czoxOiInIjtzOjQ6IvCWvZIiO3M6MToiJyI7czozOiLvvLsiO3M6MToiKCI7czozOiLinagiO3M6MToiKCI7czozOiLinbIiO3M6MToiKCI7czozOiLjgJQiO3M6MToiKCI7czozOiLvtL4iO3M6MToiKCI7czozOiLvvL0iO3M6MToiKSI7czozOiLinakiO3M6MToiKSI7czozOiLinbMiO3M6MToiKSI7czozOiLjgJUiO3M6MToiKSI7czozOiLvtL8iO3M6MToiKSI7czozOiLinbQiO3M6MToieyI7czo0OiLwnYSUIjtzOjE6InsiO3M6Mzoi4p21IjtzOjE6In0iO3M6Mzoi4ri/IjtzOjE6IrYiO3M6Mzoi4oGOIjtzOjE6IioiO3M6Mjoi2a0iO3M6MToiKiI7czozOiLiiJciO3M6MToiKiI7czo0OiLwkIyfIjtzOjE6IioiO3M6Mzoi4Zy1IjtzOjE6Ii8iO3M6Mzoi4oGBIjtzOjE6Ii8iO3M6Mzoi4oiVIjtzOjE6Ii8iO3M6Mzoi4oGEIjtzOjE6Ii8iO3M6Mzoi4pWxIjtzOjE6Ii8iO3M6Mzoi4p+LIjtzOjE6Ii8iO3M6Mzoi4qe4IjtzOjE6Ii8iO3M6NDoi8J2IuiI7czoxOiIvIjtzOjM6IuOHkyI7czoxOiIvIjtzOjM6IuOAsyI7czoxOiIvIjtzOjM6IuKzhiI7czoxOiIvIjtzOjM6IuODjiI7czoxOiIvIjtzOjM6IuS4vyI7czoxOiIvIjtzOjM6IuK8gyI7czoxOiIvIjtzOjM6Iu+8vCI7czoxOiJcIjtzOjM6Iu+5qCI7czoxOiJcIjtzOjM6IuKIliI7czoxOiJcIjtzOjM6IuKfjSI7czoxOiJcIjtzOjM6IuKntSI7czoxOiJcIjtzOjM6IuKnuSI7czoxOiJcIjtzOjQ6IvCdiI8iO3M6MToiXCI7czo0OiLwnYi7IjtzOjE6IlwiO3M6Mzoi44eUIjtzOjE6IlwiO3M6Mzoi5Li2IjtzOjE6IlwiO3M6Mzoi4ryCIjtzOjE6IlwiO3M6Mzoi6p24IjtzOjE6IiYiO3M6Mjoiy4QiO3M6MToiXiI7czoyOiLLhiI7czoxOiJeIjtzOjM6IuK4sCI7czoxOiKwIjtzOjI6IsuaIjtzOjE6IrAiO3M6Mzoi4oiYIjtzOjE6IrAiO3M6Mzoi4peLIjtzOjE6IrAiO3M6Mzoi4pemIjtzOjE6IrAiO3M6Mzoi4pK4IjtzOjE6IqkiO3M6Mzoi4pOHIjtzOjE6Iq4iO3M6Mzoi4ZutIjtzOjE6IisiO3M6Mzoi4p6VIjtzOjE6IisiO3M6NDoi8JCKmyI7czoxOiIrIjtzOjM6IuKelyI7czoxOiL3IjtzOjM6IuKAuSI7czoxOiI8IjtzOjM6IuKdriI7czoxOiI8IjtzOjI6IsuCIjtzOjE6IjwiO3M6NDoi8J2ItiI7czoxOiI8IjtzOjM6IuGQuCI7czoxOiI8IjtzOjM6IuGasiI7czoxOiI8IjtzOjM6IuGQgCI7czoxOiI9IjtzOjM6IuK5gCI7czoxOiI9IjtzOjM6IuOCoCI7czoxOiI9IjtzOjM6IuqTvyI7czoxOiI9IjtzOjM6IuKAuiI7czoxOiI+IjtzOjM6IuKdryI7czoxOiI+IjtzOjI6IsuDIjtzOjE6Ij4iO3M6NDoi8J2ItyI7czoxOiI+IjtzOjM6IuGQsyI7czoxOiI+IjtzOjQ6IvCWvL8iO3M6MToiPiI7czozOiLigZMiO3M6MToifiI7czoyOiLLnCI7czoxOiJ+IjtzOjM6IuG/gCI7czoxOiJ+IjtzOjM6IuKIvCI7czoxOiJ+IjtzOjM6IuKCpCI7czoxOiKjIjtzOjQ6IvCdn5AiO3M6MToiMiI7czo0OiLwnZ+aIjtzOjE6IjIiO3M6NDoi8J2fpCI7czoxOiIyIjtzOjQ6IvCdn64iO3M6MToiMiI7czo0OiLwnZ+4IjtzOjE6IjIiO3M6Mzoi6p2aIjtzOjE6IjIiO3M6MjoixqciO3M6MToiMiI7czoyOiLPqCI7czoxOiIyIjtzOjM6IuqZhCI7czoxOiIyIjtzOjM6IuGSvyI7czoxOiIyIjtzOjM6IuqbryI7czoxOiIyIjtzOjQ6IvCdiIYiO3M6MToiMyI7czo0OiLwnZ+RIjtzOjE6IjMiO3M6NDoi8J2fmyI7czoxOiIzIjtzOjQ6IvCdn6UiO3M6MToiMyI7czo0OiLwnZ+vIjtzOjE6IjMiO3M6NDoi8J2fuSI7czoxOiIzIjtzOjM6IuqeqyI7czoxOiIzIjtzOjI6IsicIjtzOjE6IjMiO3M6MjoixrciO3M6MToiMyI7czozOiLqnaoiO3M6MToiMyI7czozOiLis4wiO3M6MToiMyI7czoyOiLQlyI7czoxOiIzIjtzOjI6ItOgIjtzOjE6IjMiO3M6NDoi8Ja8uyI7czoxOiIzIjtzOjQ6IvCRo4oiO3M6MToiMyI7czo0OiLwnZ+SIjtzOjE6IjQiO3M6NDoi8J2fnCI7czoxOiI0IjtzOjQ6IvCdn6YiO3M6MToiNCI7czo0OiLwnZ+wIjtzOjE6IjQiO3M6NDoi8J2fuiI7czoxOiI0IjtzOjM6IuGPjiI7czoxOiI0IjtzOjQ6IvCRoq8iO3M6MToiNCI7czo0OiLwnZ+TIjtzOjE6IjUiO3M6NDoi8J2fnSI7czoxOiI1IjtzOjQ6IvCdn6ciO3M6MToiNSI7czo0OiLwnZ+xIjtzOjE6IjUiO3M6NDoi8J2fuyI7czoxOiI1IjtzOjI6Isa8IjtzOjE6IjUiO3M6NDoi8JGiuyI7czoxOiI1IjtzOjQ6IvCdn5QiO3M6MToiNiI7czo0OiLwnZ+eIjtzOjE6IjYiO3M6NDoi8J2fqCI7czoxOiI2IjtzOjQ6IvCdn7IiO3M6MToiNiI7czo0OiLwnZ+8IjtzOjE6IjYiO3M6Mzoi4rOSIjtzOjE6IjYiO3M6Mjoi0LEiO3M6MToiNiI7czozOiLhj64iO3M6MToiNiI7czo0OiLwkaOVIjtzOjE6IjYiO3M6NDoi8J2IkiI7czoxOiI3IjtzOjQ6IvCdn5UiO3M6MToiNyI7czo0OiLwnZ+fIjtzOjE6IjciO3M6NDoi8J2fqSI7czoxOiI3IjtzOjQ6IvCdn7MiO3M6MToiNyI7czo0OiLwnZ+9IjtzOjE6IjciO3M6NDoi8JCTkiI7czoxOiI3IjtzOjQ6IvCRo4YiO3M6MToiNyI7czozOiLgrIMiO3M6MToiOCI7czozOiLgp6oiO3M6MToiOCI7czozOiLgqaoiO3M6MToiOCI7czo0OiLwnqOLIjtzOjE6IjgiO3M6NDoi8J2fliI7czoxOiI4IjtzOjQ6IvCdn6AiO3M6MToiOCI7czo0OiLwnZ+qIjtzOjE6IjgiO3M6NDoi8J2ftCI7czoxOiI4IjtzOjQ6IvCdn74iO3M6MToiOCI7czoyOiLIoyI7czoxOiI4IjtzOjI6IsiiIjtzOjE6IjgiO3M6NDoi8JCMmiI7czoxOiI4IjtzOjM6IuCppyI7czoxOiI5IjtzOjM6IuCtqCI7czoxOiI5IjtzOjM6IuCnrSI7czoxOiI5IjtzOjM6IuC1rSI7czoxOiI5IjtzOjQ6IvCdn5ciO3M6MToiOSI7czo0OiLwnZ+hIjtzOjE6IjkiO3M6NDoi8J2fqyI7czoxOiI5IjtzOjQ6IvCdn7UiO3M6MToiOSI7czo0OiLwnZ+/IjtzOjE6IjkiO3M6Mzoi6p2uIjtzOjE6IjkiO3M6Mzoi4rOKIjtzOjE6IjkiO3M6NDoi8JGjjCI7czoxOiI5IjtzOjQ6IvCRoqwiO3M6MToiOSI7czo0OiLwkaOWIjtzOjE6IjkiO3M6Mzoi4o26IjtzOjE6ImEiO3M6Mzoi772BIjtzOjE6ImEiO3M6NDoi8J2QmiI7czoxOiJhIjtzOjQ6IvCdkY4iO3M6MToiYSI7czo0OiLwnZKCIjtzOjE6ImEiO3M6NDoi8J2StiI7czoxOiJhIjtzOjQ6IvCdk6oiO3M6MToiYSI7czo0OiLwnZSeIjtzOjE6ImEiO3M6NDoi8J2VkiI7czoxOiJhIjtzOjQ6IvCdloYiO3M6MToiYSI7czo0OiLwnZa6IjtzOjE6ImEiO3M6NDoi8J2XriI7czoxOiJhIjtzOjQ6IvCdmKIiO3M6MToiYSI7czo0OiLwnZmWIjtzOjE6ImEiO3M6NDoi8J2aiiI7czoxOiJhIjtzOjI6IsmRIjtzOjE6ImEiO3M6MjoizrEiO3M6MToiYSI7czo0OiLwnZuCIjtzOjE6ImEiO3M6NDoi8J2bvCI7czoxOiJhIjtzOjQ6IvCdnLYiO3M6MToiYSI7czo0OiLwnZ2wIjtzOjE6ImEiO3M6NDoi8J2eqiI7czoxOiJhIjtzOjI6ItCwIjtzOjE6ImEiO3M6Mzoi77yhIjtzOjE6IkEiO3M6NDoi8J2QgCI7czoxOiJBIjtzOjQ6IvCdkLQiO3M6MToiQSI7czo0OiLwnZGoIjtzOjE6IkEiO3M6NDoi8J2SnCI7czoxOiJBIjtzOjQ6IvCdk5AiO3M6MToiQSI7czo0OiLwnZSEIjtzOjE6IkEiO3M6NDoi8J2UuCI7czoxOiJBIjtzOjQ6IvCdlawiO3M6MToiQSI7czo0OiLwnZagIjtzOjE6IkEiO3M6NDoi8J2XlCI7czoxOiJBIjtzOjQ6IvCdmIgiO3M6MToiQSI7czo0OiLwnZi8IjtzOjE6IkEiO3M6NDoi8J2ZsCI7czoxOiJBIjtzOjI6Is6RIjtzOjE6IkEiO3M6NDoi8J2aqCI7czoxOiJBIjtzOjQ6IvCdm6IiO3M6MToiQSI7czo0OiLwnZycIjtzOjE6IkEiO3M6NDoi8J2dliI7czoxOiJBIjtzOjQ6IvCdnpAiO3M6MToiQSI7czoyOiLQkCI7czoxOiJBIjtzOjM6IuGOqiI7czoxOiJBIjtzOjM6IuGXhSI7czoxOiJBIjtzOjM6IuqTriI7czoxOiJBIjtzOjQ6IvCWvYAiO3M6MToiQSI7czo0OiLwkIqgIjtzOjE6IkEiO3M6MjoiyKciO3M6MToi5SI7czoyOiLIpiI7czoxOiLFIjtzOjQ6IvCdkJsiO3M6MToiYiI7czo0OiLwnZGPIjtzOjE6ImIiO3M6NDoi8J2SgyI7czoxOiJiIjtzOjQ6IvCdkrciO3M6MToiYiI7czo0OiLwnZOrIjtzOjE6ImIiO3M6NDoi8J2UnyI7czoxOiJiIjtzOjQ6IvCdlZMiO3M6MToiYiI7czo0OiLwnZaHIjtzOjE6ImIiO3M6NDoi8J2WuyI7czoxOiJiIjtzOjQ6IvCdl68iO3M6MToiYiI7czo0OiLwnZijIjtzOjE6ImIiO3M6NDoi8J2ZlyI7czoxOiJiIjtzOjQ6IvCdmosiO3M6MToiYiI7czoyOiLGhCI7czoxOiJiIjtzOjI6ItCsIjtzOjE6ImIiO3M6Mzoi4Y+PIjtzOjE6ImIiO3M6Mzoi4ZGyIjtzOjE6ImIiO3M6Mzoi4ZavIjtzOjE6ImIiO3M6Mzoi77yiIjtzOjE6IkIiO3M6Mzoi4oSsIjtzOjE6IkIiO3M6NDoi8J2QgSI7czoxOiJCIjtzOjQ6IvCdkLUiO3M6MToiQiI7czo0OiLwnZGpIjtzOjE6IkIiO3M6NDoi8J2TkSI7czoxOiJCIjtzOjQ6IvCdlIUiO3M6MToiQiI7czo0OiLwnZS5IjtzOjE6IkIiO3M6NDoi8J2VrSI7czoxOiJCIjtzOjQ6IvCdlqEiO3M6MToiQiI7czo0OiLwnZeVIjtzOjE6IkIiO3M6NDoi8J2YiSI7czoxOiJCIjtzOjQ6IvCdmL0iO3M6MToiQiI7czo0OiLwnZmxIjtzOjE6IkIiO3M6Mzoi6p60IjtzOjE6IkIiO3M6MjoizpIiO3M6MToiQiI7czo0OiLwnZqpIjtzOjE6IkIiO3M6NDoi8J2boyI7czoxOiJCIjtzOjQ6IvCdnJ0iO3M6MToiQiI7czo0OiLwnZ2XIjtzOjE6IkIiO3M6NDoi8J2ekSI7czoxOiJCIjtzOjI6ItCSIjtzOjE6IkIiO3M6Mzoi4Y+0IjtzOjE6IkIiO3M6Mzoi4Ze3IjtzOjE6IkIiO3M6Mzoi6pOQIjtzOjE6IkIiO3M6NDoi8JCKgiI7czoxOiJCIjtzOjQ6IvCQiqEiO3M6MToiQiI7czo0OiLwkIyBIjtzOjE6IkIiO3M6Mzoi772DIjtzOjE6ImMiO3M6Mzoi4oW9IjtzOjE6ImMiO3M6NDoi8J2QnCI7czoxOiJjIjtzOjQ6IvCdkZAiO3M6MToiYyI7czo0OiLwnZKEIjtzOjE6ImMiO3M6NDoi8J2SuCI7czoxOiJjIjtzOjQ6IvCdk6wiO3M6MToiYyI7czo0OiLwnZSgIjtzOjE6ImMiO3M6NDoi8J2VlCI7czoxOiJjIjtzOjQ6IvCdlogiO3M6MToiYyI7czo0OiLwnZa8IjtzOjE6ImMiO3M6NDoi8J2XsCI7czoxOiJjIjtzOjQ6IvCdmKQiO3M6MToiYyI7czo0OiLwnZmYIjtzOjE6ImMiO3M6NDoi8J2ajCI7czoxOiJjIjtzOjM6IuG0hCI7czoxOiJjIjtzOjI6Is+yIjtzOjE6ImMiO3M6Mzoi4rKlIjtzOjE6ImMiO3M6Mjoi0YEiO3M6MToiYyI7czozOiLqrq8iO3M6MToiYyI7czo0OiLwkJC9IjtzOjE6ImMiO3M6NDoi8J+djCI7czoxOiJDIjtzOjQ6IvCRo7IiO3M6MToiQyI7czo0OiLwkaOpIjtzOjE6IkMiO3M6Mzoi77yjIjtzOjE6IkMiO3M6Mzoi4oWtIjtzOjE6IkMiO3M6Mzoi4oSCIjtzOjE6IkMiO3M6Mzoi4oStIjtzOjE6IkMiO3M6NDoi8J2QgiI7czoxOiJDIjtzOjQ6IvCdkLYiO3M6MToiQyI7czo0OiLwnZGqIjtzOjE6IkMiO3M6NDoi8J2SniI7czoxOiJDIjtzOjQ6IvCdk5IiO3M6MToiQyI7czo0OiLwnZWuIjtzOjE6IkMiO3M6NDoi8J2WoiI7czoxOiJDIjtzOjQ6IvCdl5YiO3M6MToiQyI7czo0OiLwnZiKIjtzOjE6IkMiO3M6NDoi8J2YviI7czoxOiJDIjtzOjQ6IvCdmbIiO3M6MToiQyI7czoyOiLPuSI7czoxOiJDIjtzOjM6IuKypCI7czoxOiJDIjtzOjI6ItChIjtzOjE6IkMiO3M6Mzoi4Y+fIjtzOjE6IkMiO3M6Mzoi6pOaIjtzOjE6IkMiO3M6NDoi8JCKoiI7czoxOiJDIjtzOjQ6IvCQjIIiO3M6MToiQyI7czo0OiLwkJCVIjtzOjE6IkMiO3M6NDoi8JCUnCI7czoxOiJDIjtzOjM6IuKFviI7czoxOiJkIjtzOjM6IuKFhiI7czoxOiJkIjtzOjQ6IvCdkJ0iO3M6MToiZCI7czo0OiLwnZGRIjtzOjE6ImQiO3M6NDoi8J2ShSI7czoxOiJkIjtzOjQ6IvCdkrkiO3M6MToiZCI7czo0OiLwnZOtIjtzOjE6ImQiO3M6NDoi8J2UoSI7czoxOiJkIjtzOjQ6IvCdlZUiO3M6MToiZCI7czo0OiLwnZaJIjtzOjE6ImQiO3M6NDoi8J2WvSI7czoxOiJkIjtzOjQ6IvCdl7EiO3M6MToiZCI7czo0OiLwnZilIjtzOjE6ImQiO3M6NDoi8J2ZmSI7czoxOiJkIjtzOjQ6IvCdmo0iO3M6MToiZCI7czoyOiLUgSI7czoxOiJkIjtzOjM6IuGPpyI7czoxOiJkIjtzOjM6IuGRryI7czoxOiJkIjtzOjM6IuqTkiI7czoxOiJkIjtzOjM6IuKFriI7czoxOiJEIjtzOjM6IuKFhSI7czoxOiJEIjtzOjQ6IvCdkIMiO3M6MToiRCI7czo0OiLwnZC3IjtzOjE6IkQiO3M6NDoi8J2RqyI7czoxOiJEIjtzOjQ6IvCdkp8iO3M6MToiRCI7czo0OiLwnZOTIjtzOjE6IkQiO3M6NDoi8J2UhyI7czoxOiJEIjtzOjQ6IvCdlLsiO3M6MToiRCI7czo0OiLwnZWvIjtzOjE6IkQiO3M6NDoi8J2WoyI7czoxOiJEIjtzOjQ6IvCdl5ciO3M6MToiRCI7czo0OiLwnZiLIjtzOjE6IkQiO3M6NDoi8J2YvyI7czoxOiJEIjtzOjQ6IvCdmbMiO3M6MToiRCI7czozOiLhjqAiO3M6MToiRCI7czozOiLhl54iO3M6MToiRCI7czozOiLhl6oiO3M6MToiRCI7czozOiLqk5MiO3M6MToiRCI7czozOiLihK4iO3M6MToiZSI7czozOiLvvYUiO3M6MToiZSI7czozOiLihK8iO3M6MToiZSI7czozOiLihYciO3M6MToiZSI7czo0OiLwnZCeIjtzOjE6ImUiO3M6NDoi8J2RkiI7czoxOiJlIjtzOjQ6IvCdkoYiO3M6MToiZSI7czo0OiLwnZOuIjtzOjE6ImUiO3M6NDoi8J2UoiI7czoxOiJlIjtzOjQ6IvCdlZYiO3M6MToiZSI7czo0OiLwnZaKIjtzOjE6ImUiO3M6NDoi8J2WviI7czoxOiJlIjtzOjQ6IvCdl7IiO3M6MToiZSI7czo0OiLwnZimIjtzOjE6ImUiO3M6NDoi8J2ZmiI7czoxOiJlIjtzOjQ6IvCdmo4iO3M6MToiZSI7czozOiLqrLIiO3M6MToiZSI7czoyOiLQtSI7czoxOiJlIjtzOjI6ItK9IjtzOjE6ImUiO3M6Mjoiw6kiO3M6MToiZSI7czozOiLii78iO3M6MToiRSI7czozOiLvvKUiO3M6MToiRSI7czozOiLihLAiO3M6MToiRSI7czo0OiLwnZCEIjtzOjE6IkUiO3M6NDoi8J2QuCI7czoxOiJFIjtzOjQ6IvCdkawiO3M6MToiRSI7czo0OiLwnZOUIjtzOjE6IkUiO3M6NDoi8J2UiCI7czoxOiJFIjtzOjQ6IvCdlLwiO3M6MToiRSI7czo0OiLwnZWwIjtzOjE6IkUiO3M6NDoi8J2WpCI7czoxOiJFIjtzOjQ6IvCdl5giO3M6MToiRSI7czo0OiLwnZiMIjtzOjE6IkUiO3M6NDoi8J2ZgCI7czoxOiJFIjtzOjQ6IvCdmbQiO3M6MToiRSI7czoyOiLOlSI7czoxOiJFIjtzOjQ6IvCdmqwiO3M6MToiRSI7czo0OiLwnZumIjtzOjE6IkUiO3M6NDoi8J2coCI7czoxOiJFIjtzOjQ6IvCdnZoiO3M6MToiRSI7czo0OiLwnZ6UIjtzOjE6IkUiO3M6Mjoi0JUiO3M6MToiRSI7czozOiLitLkiO3M6MToiRSI7czozOiLhjqwiO3M6MToiRSI7czozOiLqk7AiO3M6MToiRSI7czo0OiLwkaKmIjtzOjE6IkUiO3M6NDoi8JGiriI7czoxOiJFIjtzOjQ6IvCQioYiO3M6MToiRSI7czo0OiLwnZCfIjtzOjE6ImYiO3M6NDoi8J2RkyI7czoxOiJmIjtzOjQ6IvCdkociO3M6MToiZiI7czo0OiLwnZK7IjtzOjE6ImYiO3M6NDoi8J2TryI7czoxOiJmIjtzOjQ6IvCdlKMiO3M6MToiZiI7czo0OiLwnZWXIjtzOjE6ImYiO3M6NDoi8J2WiyI7czoxOiJmIjtzOjQ6IvCdlr8iO3M6MToiZiI7czo0OiLwnZezIjtzOjE6ImYiO3M6NDoi8J2YpyI7czoxOiJmIjtzOjQ6IvCdmZsiO3M6MToiZiI7czo0OiLwnZqPIjtzOjE6ImYiO3M6Mzoi6qy1IjtzOjE6ImYiO3M6Mzoi6p6ZIjtzOjE6ImYiO3M6Mjoixb8iO3M6MToiZiI7czozOiLhup0iO3M6MToiZiI7czoyOiLWhCI7czoxOiJmIjtzOjQ6IvCdiJMiO3M6MToiRiI7czozOiLihLEiO3M6MToiRiI7czo0OiLwnZCFIjtzOjE6IkYiO3M6NDoi8J2QuSI7czoxOiJGIjtzOjQ6IvCdka0iO3M6MToiRiI7czo0OiLwnZOVIjtzOjE6IkYiO3M6NDoi8J2UiSI7czoxOiJGIjtzOjQ6IvCdlL0iO3M6MToiRiI7czo0OiLwnZWxIjtzOjE6IkYiO3M6NDoi8J2WpSI7czoxOiJGIjtzOjQ6IvCdl5kiO3M6MToiRiI7czo0OiLwnZiNIjtzOjE6IkYiO3M6NDoi8J2ZgSI7czoxOiJGIjtzOjQ6IvCdmbUiO3M6MToiRiI7czozOiLqnpgiO3M6MToiRiI7czoyOiLPnCI7czoxOiJGIjtzOjQ6IvCdn4oiO3M6MToiRiI7czozOiLhlrQiO3M6MToiRiI7czozOiLqk50iO3M6MToiRiI7czo0OiLwkaOCIjtzOjE6IkYiO3M6NDoi8JGioiI7czoxOiJGIjtzOjQ6IvCQiociO3M6MToiRiI7czo0OiLwkIqlIjtzOjE6IkYiO3M6NDoi8JCUpSI7czoxOiJGIjtzOjM6Iu+9hyI7czoxOiJnIjtzOjM6IuKEiiI7czoxOiJnIjtzOjQ6IvCdkKAiO3M6MToiZyI7czo0OiLwnZGUIjtzOjE6ImciO3M6NDoi8J2SiCI7czoxOiJnIjtzOjQ6IvCdk7AiO3M6MToiZyI7czo0OiLwnZSkIjtzOjE6ImciO3M6NDoi8J2VmCI7czoxOiJnIjtzOjQ6IvCdlowiO3M6MToiZyI7czo0OiLwnZeAIjtzOjE6ImciO3M6NDoi8J2XtCI7czoxOiJnIjtzOjQ6IvCdmKgiO3M6MToiZyI7czo0OiLwnZmcIjtzOjE6ImciO3M6NDoi8J2akCI7czoxOiJnIjtzOjI6IsmhIjtzOjE6ImciO3M6Mzoi4baDIjtzOjE6ImciO3M6Mjoixo0iO3M6MToiZyI7czoyOiLWgSI7czoxOiJnIjtzOjQ6IvCdkIYiO3M6MToiRyI7czo0OiLwnZC6IjtzOjE6IkciO3M6NDoi8J2RriI7czoxOiJHIjtzOjQ6IvCdkqIiO3M6MToiRyI7czo0OiLwnZOWIjtzOjE6IkciO3M6NDoi8J2UiiI7czoxOiJHIjtzOjQ6IvCdlL4iO3M6MToiRyI7czo0OiLwnZWyIjtzOjE6IkciO3M6NDoi8J2WpiI7czoxOiJHIjtzOjQ6IvCdl5oiO3M6MToiRyI7czo0OiLwnZiOIjtzOjE6IkciO3M6NDoi8J2ZgiI7czoxOiJHIjtzOjQ6IvCdmbYiO3M6MToiRyI7czoyOiLUjCI7czoxOiJHIjtzOjM6IuGPgCI7czoxOiJHIjtzOjM6IuGPsyI7czoxOiJHIjtzOjM6IuqTliI7czoxOiJHIjtzOjM6Iu+9iCI7czoxOiJoIjtzOjM6IuKEjiI7czoxOiJoIjtzOjQ6IvCdkKEiO3M6MToiaCI7czo0OiLwnZKJIjtzOjE6ImgiO3M6NDoi8J2SvSI7czoxOiJoIjtzOjQ6IvCdk7EiO3M6MToiaCI7czo0OiLwnZSlIjtzOjE6ImgiO3M6NDoi8J2VmSI7czoxOiJoIjtzOjQ6IvCdlo0iO3M6MToiaCI7czo0OiLwnZeBIjtzOjE6ImgiO3M6NDoi8J2XtSI7czoxOiJoIjtzOjQ6IvCdmKkiO3M6MToiaCI7czo0OiLwnZmdIjtzOjE6ImgiO3M6NDoi8J2akSI7czoxOiJoIjtzOjI6ItK7IjtzOjE6ImgiO3M6Mjoi1bAiO3M6MToiaCI7czozOiLhj4IiO3M6MToiaCI7czozOiLvvKgiO3M6MToiSCI7czozOiLihIsiO3M6MToiSCI7czozOiLihIwiO3M6MToiSCI7czozOiLihI0iO3M6MToiSCI7czo0OiLwnZCHIjtzOjE6IkgiO3M6NDoi8J2QuyI7czoxOiJIIjtzOjQ6IvCdka8iO3M6MToiSCI7czo0OiLwnZOXIjtzOjE6IkgiO3M6NDoi8J2VsyI7czoxOiJIIjtzOjQ6IvCdlqciO3M6MToiSCI7czo0OiLwnZebIjtzOjE6IkgiO3M6NDoi8J2YjyI7czoxOiJIIjtzOjQ6IvCdmYMiO3M6MToiSCI7czo0OiLwnZm3IjtzOjE6IkgiO3M6MjoizpciO3M6MToiSCI7czo0OiLwnZquIjtzOjE6IkgiO3M6NDoi8J2bqCI7czoxOiJIIjtzOjQ6IvCdnKIiO3M6MToiSCI7czo0OiLwnZ2cIjtzOjE6IkgiO3M6NDoi8J2eliI7czoxOiJIIjtzOjM6IuKyjiI7czoxOiJIIjtzOjI6ItCdIjtzOjE6IkgiO3M6Mzoi4Y67IjtzOjE6IkgiO3M6Mzoi4ZW8IjtzOjE6IkgiO3M6Mzoi6pOnIjtzOjE6IkgiO3M6NDoi8JCLjyI7czoxOiJIIjtzOjI6IsubIjtzOjE6ImkiO3M6Mzoi4o2zIjtzOjE6ImkiO3M6Mzoi772JIjtzOjE6ImkiO3M6Mzoi4oWwIjtzOjE6ImkiO3M6Mzoi4oS5IjtzOjE6ImkiO3M6Mzoi4oWIIjtzOjE6ImkiO3M6NDoi8J2QoiI7czoxOiJpIjtzOjQ6IvCdkZYiO3M6MToiaSI7czo0OiLwnZKKIjtzOjE6ImkiO3M6NDoi8J2SviI7czoxOiJpIjtzOjQ6IvCdk7IiO3M6MToiaSI7czo0OiLwnZSmIjtzOjE6ImkiO3M6NDoi8J2VmiI7czoxOiJpIjtzOjQ6IvCdlo4iO3M6MToiaSI7czo0OiLwnZeCIjtzOjE6ImkiO3M6NDoi8J2XtiI7czoxOiJpIjtzOjQ6IvCdmKoiO3M6MToiaSI7czo0OiLwnZmeIjtzOjE6ImkiO3M6NDoi8J2akiI7czoxOiJpIjtzOjI6IsSxIjtzOjE6ImkiO3M6NDoi8J2apCI7czoxOiJpIjtzOjI6IsmqIjtzOjE6ImkiO3M6MjoiyakiO3M6MToiaSI7czoyOiLOuSI7czoxOiJpIjtzOjM6IuG+viI7czoxOiJpIjtzOjI6Is26IjtzOjE6ImkiO3M6NDoi8J2biiI7czoxOiJpIjtzOjQ6IvCdnIQiO3M6MToiaSI7czo0OiLwnZy+IjtzOjE6ImkiO3M6NDoi8J2duCI7czoxOiJpIjtzOjQ6IvCdnrIiO3M6MToiaSI7czoyOiLRliI7czoxOiJpIjtzOjM6IuqZhyI7czoxOiJpIjtzOjI6ItOPIjtzOjE6ImkiO3M6Mzoi6q21IjtzOjE6ImkiO3M6Mzoi4Y6lIjtzOjE6ImkiO3M6NDoi8JGjgyI7czoxOiJpIjtzOjI6IsOtIjtzOjE6ImkiO3M6Mzoi772KIjtzOjE6ImoiO3M6Mzoi4oWJIjtzOjE6ImoiO3M6NDoi8J2QoyI7czoxOiJqIjtzOjQ6IvCdkZciO3M6MToiaiI7czo0OiLwnZKLIjtzOjE6ImoiO3M6NDoi8J2SvyI7czoxOiJqIjtzOjQ6IvCdk7MiO3M6MToiaiI7czo0OiLwnZSnIjtzOjE6ImoiO3M6NDoi8J2VmyI7czoxOiJqIjtzOjQ6IvCdlo8iO3M6MToiaiI7czo0OiLwnZeDIjtzOjE6ImoiO3M6NDoi8J2XtyI7czoxOiJqIjtzOjQ6IvCdmKsiO3M6MToiaiI7czo0OiLwnZmfIjtzOjE6ImoiO3M6NDoi8J2akyI7czoxOiJqIjtzOjI6Is+zIjtzOjE6ImoiO3M6Mjoi0ZgiO3M6MToiaiI7czozOiLvvKoiO3M6MToiSiI7czo0OiLwnZCJIjtzOjE6IkoiO3M6NDoi8J2QvSI7czoxOiJKIjtzOjQ6IvCdkbEiO3M6MToiSiI7czo0OiLwnZKlIjtzOjE6IkoiO3M6NDoi8J2TmSI7czoxOiJKIjtzOjQ6IvCdlI0iO3M6MToiSiI7czo0OiLwnZWBIjtzOjE6IkoiO3M6NDoi8J2VtSI7czoxOiJKIjtzOjQ6IvCdlqkiO3M6MToiSiI7czo0OiLwnZedIjtzOjE6IkoiO3M6NDoi8J2YkSI7czoxOiJKIjtzOjQ6IvCdmYUiO3M6MToiSiI7czo0OiLwnZm5IjtzOjE6IkoiO3M6Mzoi6p6yIjtzOjE6IkoiO3M6Mjoizb8iO3M6MToiSiI7czoyOiLQiCI7czoxOiJKIjtzOjM6IuGOqyI7czoxOiJKIjtzOjM6IuGSjSI7czoxOiJKIjtzOjM6IuqTmSI7czoxOiJKIjtzOjQ6IvCdkKQiO3M6MToiayI7czo0OiLwnZGYIjtzOjE6ImsiO3M6NDoi8J2SjCI7czoxOiJrIjtzOjQ6IvCdk4AiO3M6MToiayI7czo0OiLwnZO0IjtzOjE6ImsiO3M6NDoi8J2UqCI7czoxOiJrIjtzOjQ6IvCdlZwiO3M6MToiayI7czo0OiLwnZaQIjtzOjE6ImsiO3M6NDoi8J2XhCI7czoxOiJrIjtzOjQ6IvCdl7giO3M6MToiayI7czo0OiLwnZisIjtzOjE6ImsiO3M6NDoi8J2ZoCI7czoxOiJrIjtzOjQ6IvCdmpQiO3M6MToiayI7czozOiLihKoiO3M6MToiSyI7czozOiLvvKsiO3M6MToiSyI7czo0OiLwnZCKIjtzOjE6IksiO3M6NDoi8J2QviI7czoxOiJLIjtzOjQ6IvCdkbIiO3M6MToiSyI7czo0OiLwnZKmIjtzOjE6IksiO3M6NDoi8J2TmiI7czoxOiJLIjtzOjQ6IvCdlI4iO3M6MToiSyI7czo0OiLwnZWCIjtzOjE6IksiO3M6NDoi8J2VtiI7czoxOiJLIjtzOjQ6IvCdlqoiO3M6MToiSyI7czo0OiLwnZeeIjtzOjE6IksiO3M6NDoi8J2YkiI7czoxOiJLIjtzOjQ6IvCdmYYiO3M6MToiSyI7czo0OiLwnZm6IjtzOjE6IksiO3M6MjoizpoiO3M6MToiSyI7czo0OiLwnZqxIjtzOjE6IksiO3M6NDoi8J2bqyI7czoxOiJLIjtzOjQ6IvCdnKUiO3M6MToiSyI7czo0OiLwnZ2fIjtzOjE6IksiO3M6NDoi8J2emSI7czoxOiJLIjtzOjM6IuKylCI7czoxOiJLIjtzOjI6ItCaIjtzOjE6IksiO3M6Mzoi4Y+mIjtzOjE6IksiO3M6Mzoi4ZuVIjtzOjE6IksiO3M6Mzoi6pOXIjtzOjE6IksiO3M6NDoi8JCUmCI7czoxOiJLIjtzOjI6IteAIjtzOjE6ImwiO3M6Mzoi4oijIjtzOjE6ImwiO3M6Mzoi4o+9IjtzOjE6ImwiO3M6Mzoi77+oIjtzOjE6ImwiO2k6MTtzOjE6ImwiO3M6Mjoi2aEiO3M6MToibCI7czoyOiLbsSI7czoxOiJsIjtzOjQ6IvCQjKAiO3M6MToibCI7czo0OiLwnqOHIjtzOjE6ImwiO3M6NDoi8J2fjyI7czoxOiJsIjtzOjQ6IvCdn5kiO3M6MToibCI7czo0OiLwnZ+jIjtzOjE6ImwiO3M6NDoi8J2frSI7czoxOiJsIjtzOjQ6IvCdn7ciO3M6MToibCI7czozOiLvvKkiO3M6MToibCI7czozOiLihaAiO3M6MToibCI7czozOiLihJAiO3M6MToibCI7czozOiLihJEiO3M6MToibCI7czo0OiLwnZCIIjtzOjE6ImwiO3M6NDoi8J2QvCI7czoxOiJsIjtzOjQ6IvCdkbAiO3M6MToibCI7czo0OiLwnZOYIjtzOjE6ImwiO3M6NDoi8J2VgCI7czoxOiJsIjtzOjQ6IvCdlbQiO3M6MToibCI7czo0OiLwnZaoIjtzOjE6ImwiO3M6NDoi8J2XnCI7czoxOiJsIjtzOjQ6IvCdmJAiO3M6MToibCI7czo0OiLwnZmEIjtzOjE6ImwiO3M6NDoi8J2ZuCI7czoxOiJsIjtzOjI6IsaWIjtzOjE6ImwiO3M6Mzoi772MIjtzOjE6ImwiO3M6Mzoi4oW8IjtzOjE6ImwiO3M6Mzoi4oSTIjtzOjE6ImwiO3M6NDoi8J2QpSI7czoxOiJsIjtzOjQ6IvCdkZkiO3M6MToibCI7czo0OiLwnZKNIjtzOjE6ImwiO3M6NDoi8J2TgSI7czoxOiJsIjtzOjQ6IvCdk7UiO3M6MToibCI7czo0OiLwnZSpIjtzOjE6ImwiO3M6NDoi8J2VnSI7czoxOiJsIjtzOjQ6IvCdlpEiO3M6MToibCI7czo0OiLwnZeFIjtzOjE6ImwiO3M6NDoi8J2XuSI7czoxOiJsIjtzOjQ6IvCdmK0iO3M6MToibCI7czo0OiLwnZmhIjtzOjE6ImwiO3M6NDoi8J2alSI7czoxOiJsIjtzOjI6IseAIjtzOjE6ImwiO3M6MjoizpkiO3M6MToibCI7czo0OiLwnZqwIjtzOjE6ImwiO3M6NDoi8J2bqiI7czoxOiJsIjtzOjQ6IvCdnKQiO3M6MToibCI7czo0OiLwnZ2eIjtzOjE6ImwiO3M6NDoi8J2emCI7czoxOiJsIjtzOjM6IuKykiI7czoxOiJsIjtzOjI6ItCGIjtzOjE6ImwiO3M6Mjoi04AiO3M6MToibCI7czoyOiLXlSI7czoxOiJsIjtzOjI6ItefIjtzOjE6ImwiO3M6Mjoi2KciO3M6MToibCI7czo0OiLwnriAIjtzOjE6ImwiO3M6NDoi8J66gCI7czoxOiJsIjtzOjM6Iu+6jiI7czoxOiJsIjtzOjM6Iu+6jSI7czoxOiJsIjtzOjI6It+KIjtzOjE6ImwiO3M6Mzoi4rWPIjtzOjE6ImwiO3M6Mzoi4ZuBIjtzOjE6ImwiO3M6Mzoi6pOyIjtzOjE6ImwiO3M6NDoi8Ja8qCI7czoxOiJsIjtzOjQ6IvCQiooiO3M6MToibCI7czo0OiLwkIyJIjtzOjE6ImwiO3M6NDoi8J2IqiI7czoxOiJMIjtzOjM6IuKFrCI7czoxOiJMIjtzOjM6IuKEkiI7czoxOiJMIjtzOjQ6IvCdkIsiO3M6MToiTCI7czo0OiLwnZC/IjtzOjE6IkwiO3M6NDoi8J2RsyI7czoxOiJMIjtzOjQ6IvCdk5siO3M6MToiTCI7czo0OiLwnZSPIjtzOjE6IkwiO3M6NDoi8J2VgyI7czoxOiJMIjtzOjQ6IvCdlbciO3M6MToiTCI7czo0OiLwnZarIjtzOjE6IkwiO3M6NDoi8J2XnyI7czoxOiJMIjtzOjQ6IvCdmJMiO3M6MToiTCI7czo0OiLwnZmHIjtzOjE6IkwiO3M6NDoi8J2ZuyI7czoxOiJMIjtzOjM6IuKzkCI7czoxOiJMIjtzOjM6IuGPniI7czoxOiJMIjtzOjM6IuGSqiI7czoxOiJMIjtzOjM6IuqToSI7czoxOiJMIjtzOjQ6IvCWvJYiO3M6MToiTCI7czo0OiLwkaKjIjtzOjE6IkwiO3M6NDoi8JGisiI7czoxOiJMIjtzOjQ6IvCQkJsiO3M6MToiTCI7czo0OiLwkJSmIjtzOjE6IkwiO3M6Mzoi77ytIjtzOjE6Ik0iO3M6Mzoi4oWvIjtzOjE6Ik0iO3M6Mzoi4oSzIjtzOjE6Ik0iO3M6NDoi8J2QjCI7czoxOiJNIjtzOjQ6IvCdkYAiO3M6MToiTSI7czo0OiLwnZG0IjtzOjE6Ik0iO3M6NDoi8J2TnCI7czoxOiJNIjtzOjQ6IvCdlJAiO3M6MToiTSI7czo0OiLwnZWEIjtzOjE6Ik0iO3M6NDoi8J2VuCI7czoxOiJNIjtzOjQ6IvCdlqwiO3M6MToiTSI7czo0OiLwnZegIjtzOjE6Ik0iO3M6NDoi8J2YlCI7czoxOiJNIjtzOjQ6IvCdmYgiO3M6MToiTSI7czo0OiLwnZm8IjtzOjE6Ik0iO3M6MjoizpwiO3M6MToiTSI7czo0OiLwnZqzIjtzOjE6Ik0iO3M6NDoi8J2brSI7czoxOiJNIjtzOjQ6IvCdnKciO3M6MToiTSI7czo0OiLwnZ2hIjtzOjE6Ik0iO3M6NDoi8J2emyI7czoxOiJNIjtzOjI6Is+6IjtzOjE6Ik0iO3M6Mzoi4rKYIjtzOjE6Ik0iO3M6Mjoi0JwiO3M6MToiTSI7czozOiLhjrciO3M6MToiTSI7czozOiLhl7AiO3M6MToiTSI7czozOiLhm5YiO3M6MToiTSI7czozOiLqk58iO3M6MToiTSI7czo0OiLwkIqwIjtzOjE6Ik0iO3M6NDoi8JCMkSI7czoxOiJNIjtzOjQ6IvCdkKciO3M6MToibiI7czo0OiLwnZGbIjtzOjE6Im4iO3M6NDoi8J2SjyI7czoxOiJuIjtzOjQ6IvCdk4MiO3M6MToibiI7czo0OiLwnZO3IjtzOjE6Im4iO3M6NDoi8J2UqyI7czoxOiJuIjtzOjQ6IvCdlZ8iO3M6MToibiI7czo0OiLwnZaTIjtzOjE6Im4iO3M6NDoi8J2XhyI7czoxOiJuIjtzOjQ6IvCdl7siO3M6MToibiI7czo0OiLwnZivIjtzOjE6Im4iO3M6NDoi8J2ZoyI7czoxOiJuIjtzOjQ6IvCdmpciO3M6MToibiI7czoyOiLVuCI7czoxOiJuIjtzOjI6ItW8IjtzOjE6Im4iO3M6MjoiybQiO3M6MToibiI7czozOiLvvK4iO3M6MToiTiI7czozOiLihJUiO3M6MToiTiI7czo0OiLwnZCNIjtzOjE6Ik4iO3M6NDoi8J2RgSI7czoxOiJOIjtzOjQ6IvCdkbUiO3M6MToiTiI7czo0OiLwnZKpIjtzOjE6Ik4iO3M6NDoi8J2TnSI7czoxOiJOIjtzOjQ6IvCdlJEiO3M6MToiTiI7czo0OiLwnZW5IjtzOjE6Ik4iO3M6NDoi8J2WrSI7czoxOiJOIjtzOjQ6IvCdl6EiO3M6MToiTiI7czo0OiLwnZiVIjtzOjE6Ik4iO3M6NDoi8J2ZiSI7czoxOiJOIjtzOjQ6IvCdmb0iO3M6MToiTiI7czoyOiLOnSI7czoxOiJOIjtzOjQ6IvCdmrQiO3M6MToiTiI7czo0OiLwnZuuIjtzOjE6Ik4iO3M6NDoi8J2cqCI7czoxOiJOIjtzOjQ6IvCdnaIiO3M6MToiTiI7czo0OiLwnZ6cIjtzOjE6Ik4iO3M6Mzoi4rKaIjtzOjE6Ik4iO3M6Mzoi6pOgIjtzOjE6Ik4iO3M6NDoi8JCUkyI7czoxOiJOIjtzOjM6IuCwgiI7czoxOiJvIjtzOjM6IuCygiI7czoxOiJvIjtzOjM6IuC0giI7czoxOiJvIjtzOjM6IuC2giI7czoxOiJvIjtzOjM6IuClpiI7czoxOiJvIjtzOjM6IuCppiI7czoxOiJvIjtzOjM6IuCrpiI7czoxOiJvIjtzOjM6IuCvpiI7czoxOiJvIjtzOjM6IuCxpiI7czoxOiJvIjtzOjM6IuCzpiI7czoxOiJvIjtzOjM6IuC1piI7czoxOiJvIjtzOjM6IuC5kCI7czoxOiJvIjtzOjM6IuC7kCI7czoxOiJvIjtzOjM6IuGBgCI7czoxOiJvIjtzOjI6ItmlIjtzOjE6Im8iO3M6Mjoi27UiO3M6MToibyI7czozOiLvvY8iO3M6MToibyI7czozOiLihLQiO3M6MToibyI7czo0OiLwnZCoIjtzOjE6Im8iO3M6NDoi8J2RnCI7czoxOiJvIjtzOjQ6IvCdkpAiO3M6MToibyI7czo0OiLwnZO4IjtzOjE6Im8iO3M6NDoi8J2UrCI7czoxOiJvIjtzOjQ6IvCdlaAiO3M6MToibyI7czo0OiLwnZaUIjtzOjE6Im8iO3M6NDoi8J2XiCI7czoxOiJvIjtzOjQ6IvCdl7wiO3M6MToibyI7czo0OiLwnZiwIjtzOjE6Im8iO3M6NDoi8J2ZpCI7czoxOiJvIjtzOjQ6IvCdmpgiO3M6MToibyI7czozOiLhtI8iO3M6MToibyI7czozOiLhtJEiO3M6MToibyI7czozOiLqrL0iO3M6MToibyI7czoyOiLOvyI7czoxOiJvIjtzOjQ6IvCdm5AiO3M6MToibyI7czo0OiLwnZyKIjtzOjE6Im8iO3M6NDoi8J2dhCI7czoxOiJvIjtzOjQ6IvCdnb4iO3M6MToibyI7czo0OiLwnZ64IjtzOjE6Im8iO3M6Mjoiz4MiO3M6MToibyI7czo0OiLwnZuUIjtzOjE6Im8iO3M6NDoi8J2cjiI7czoxOiJvIjtzOjQ6IvCdnYgiO3M6MToibyI7czo0OiLwnZ6CIjtzOjE6Im8iO3M6NDoi8J2evCI7czoxOiJvIjtzOjM6IuKynyI7czoxOiJvIjtzOjI6ItC+IjtzOjE6Im8iO3M6Mzoi4YO/IjtzOjE6Im8iO3M6Mjoi1oUiO3M6MToibyI7czoyOiLXoSI7czoxOiJvIjtzOjI6ItmHIjtzOjE6Im8iO3M6NDoi8J64pCI7czoxOiJvIjtzOjQ6IvCeuaQiO3M6MToibyI7czo0OiLwnrqEIjtzOjE6Im8iO3M6Mzoi77urIjtzOjE6Im8iO3M6Mzoi77usIjtzOjE6Im8iO3M6Mzoi77uqIjtzOjE6Im8iO3M6Mzoi77upIjtzOjE6Im8iO3M6Mjoi2r4iO3M6MToibyI7czozOiLvrqwiO3M6MToibyI7czozOiLvrq0iO3M6MToibyI7czozOiLvrqsiO3M6MToibyI7czozOiLvrqoiO3M6MToibyI7czoyOiLbgSI7czoxOiJvIjtzOjM6Iu+uqCI7czoxOiJvIjtzOjM6Iu+uqSI7czoxOiJvIjtzOjM6Iu+upyI7czoxOiJvIjtzOjM6Iu+upiI7czoxOiJvIjtzOjI6ItuVIjtzOjE6Im8iO3M6Mzoi4LSgIjtzOjE6Im8iO3M6Mzoi4YCdIjtzOjE6Im8iO3M6NDoi8JCTqiI7czoxOiJvIjtzOjQ6IvCRo4giO3M6MToibyI7czo0OiLwkaOXIjtzOjE6Im8iO3M6NDoi8JCQrCI7czoxOiJvIjtpOjA7czoxOiJPIjtzOjI6It+AIjtzOjE6Ik8iO3M6Mzoi4KemIjtzOjE6Ik8iO3M6Mzoi4K2mIjtzOjE6Ik8iO3M6Mzoi44CHIjtzOjE6Ik8iO3M6NDoi8JGTkCI7czoxOiJPIjtzOjQ6IvCRo6AiO3M6MToiTyI7czo0OiLwnZ+OIjtzOjE6Ik8iO3M6NDoi8J2fmCI7czoxOiJPIjtzOjQ6IvCdn6IiO3M6MToiTyI7czo0OiLwnZ+sIjtzOjE6Ik8iO3M6NDoi8J2ftiI7czoxOiJPIjtzOjM6Iu+8ryI7czoxOiJPIjtzOjQ6IvCdkI4iO3M6MToiTyI7czo0OiLwnZGCIjtzOjE6Ik8iO3M6NDoi8J2RtiI7czoxOiJPIjtzOjQ6IvCdkqoiO3M6MToiTyI7czo0OiLwnZOeIjtzOjE6Ik8iO3M6NDoi8J2UkiI7czoxOiJPIjtzOjQ6IvCdlYYiO3M6MToiTyI7czo0OiLwnZW6IjtzOjE6Ik8iO3M6NDoi8J2WriI7czoxOiJPIjtzOjQ6IvCdl6IiO3M6MToiTyI7czo0OiLwnZiWIjtzOjE6Ik8iO3M6NDoi8J2ZiiI7czoxOiJPIjtzOjQ6IvCdmb4iO3M6MToiTyI7czoyOiLOnyI7czoxOiJPIjtzOjQ6IvCdmrYiO3M6MToiTyI7czo0OiLwnZuwIjtzOjE6Ik8iO3M6NDoi8J2cqiI7czoxOiJPIjtzOjQ6IvCdnaQiO3M6MToiTyI7czo0OiLwnZ6eIjtzOjE6Ik8iO3M6Mzoi4rKeIjtzOjE6Ik8iO3M6Mjoi0J4iO3M6MToiTyI7czoyOiLVlSI7czoxOiJPIjtzOjM6IuK1lCI7czoxOiJPIjtzOjM6IuGLkCI7czoxOiJPIjtzOjM6IuCsoCI7czoxOiJPIjtzOjQ6IvCQk4IiO3M6MToiTyI7czozOiLqk7MiO3M6MToiTyI7czo0OiLwkaK1IjtzOjE6Ik8iO3M6NDoi8JCKkiI7czoxOiJPIjtzOjQ6IvCQiqsiO3M6MToiTyI7czo0OiLwkJCEIjtzOjE6Ik8iO3M6NDoi8JCUliI7czoxOiJPIjtzOjM6IuKBsCI7czoxOiK6IjtzOjM6IuG1kiI7czoxOiK6IjtzOjI6IsWQIjtzOjE6ItYiO3M6Mzoi4o20IjtzOjE6InAiO3M6Mzoi772QIjtzOjE6InAiO3M6NDoi8J2QqSI7czoxOiJwIjtzOjQ6IvCdkZ0iO3M6MToicCI7czo0OiLwnZKRIjtzOjE6InAiO3M6NDoi8J2ThSI7czoxOiJwIjtzOjQ6IvCdk7kiO3M6MToicCI7czo0OiLwnZStIjtzOjE6InAiO3M6NDoi8J2VoSI7czoxOiJwIjtzOjQ6IvCdlpUiO3M6MToicCI7czo0OiLwnZeJIjtzOjE6InAiO3M6NDoi8J2XvSI7czoxOiJwIjtzOjQ6IvCdmLEiO3M6MToicCI7czo0OiLwnZmlIjtzOjE6InAiO3M6NDoi8J2amSI7czoxOiJwIjtzOjI6Is+BIjtzOjE6InAiO3M6Mjoiz7EiO3M6MToicCI7czo0OiLwnZuSIjtzOjE6InAiO3M6NDoi8J2boCI7czoxOiJwIjtzOjQ6IvCdnIwiO3M6MToicCI7czo0OiLwnZyaIjtzOjE6InAiO3M6NDoi8J2dhiI7czoxOiJwIjtzOjQ6IvCdnZQiO3M6MToicCI7czo0OiLwnZ6AIjtzOjE6InAiO3M6NDoi8J2ejiI7czoxOiJwIjtzOjQ6IvCdnroiO3M6MToicCI7czo0OiLwnZ+IIjtzOjE6InAiO3M6Mzoi4rKjIjtzOjE6InAiO3M6Mjoi0YAiO3M6MToicCI7czozOiLvvLAiO3M6MToiUCI7czozOiLihJkiO3M6MToiUCI7czo0OiLwnZCPIjtzOjE6IlAiO3M6NDoi8J2RgyI7czoxOiJQIjtzOjQ6IvCdkbciO3M6MToiUCI7czo0OiLwnZKrIjtzOjE6IlAiO3M6NDoi8J2TnyI7czoxOiJQIjtzOjQ6IvCdlJMiO3M6MToiUCI7czo0OiLwnZW7IjtzOjE6IlAiO3M6NDoi8J2WryI7czoxOiJQIjtzOjQ6IvCdl6MiO3M6MToiUCI7czo0OiLwnZiXIjtzOjE6IlAiO3M6NDoi8J2ZiyI7czoxOiJQIjtzOjQ6IvCdmb8iO3M6MToiUCI7czoyOiLOoSI7czoxOiJQIjtzOjQ6IvCdmrgiO3M6MToiUCI7czo0OiLwnZuyIjtzOjE6IlAiO3M6NDoi8J2crCI7czoxOiJQIjtzOjQ6IvCdnaYiO3M6MToiUCI7czo0OiLwnZ6gIjtzOjE6IlAiO3M6Mzoi4rKiIjtzOjE6IlAiO3M6Mjoi0KAiO3M6MToiUCI7czozOiLhj6IiO3M6MToiUCI7czozOiLhka0iO3M6MToiUCI7czozOiLqk5EiO3M6MToiUCI7czo0OiLwkIqVIjtzOjE6IlAiO3M6NDoi8J2QqiI7czoxOiJxIjtzOjQ6IvCdkZ4iO3M6MToicSI7czo0OiLwnZKSIjtzOjE6InEiO3M6NDoi8J2ThiI7czoxOiJxIjtzOjQ6IvCdk7oiO3M6MToicSI7czo0OiLwnZSuIjtzOjE6InEiO3M6NDoi8J2VoiI7czoxOiJxIjtzOjQ6IvCdlpYiO3M6MToicSI7czo0OiLwnZeKIjtzOjE6InEiO3M6NDoi8J2XviI7czoxOiJxIjtzOjQ6IvCdmLIiO3M6MToicSI7czo0OiLwnZmmIjtzOjE6InEiO3M6NDoi8J2amiI7czoxOiJxIjtzOjI6ItSbIjtzOjE6InEiO3M6Mjoi1aMiO3M6MToicSI7czoyOiLVpiI7czoxOiJxIjtzOjM6IuKEmiI7czoxOiJRIjtzOjQ6IvCdkJAiO3M6MToiUSI7czo0OiLwnZGEIjtzOjE6IlEiO3M6NDoi8J2RuCI7czoxOiJRIjtzOjQ6IvCdkqwiO3M6MToiUSI7czo0OiLwnZOgIjtzOjE6IlEiO3M6NDoi8J2UlCI7czoxOiJRIjtzOjQ6IvCdlbwiO3M6MToiUSI7czo0OiLwnZawIjtzOjE6IlEiO3M6NDoi8J2XpCI7czoxOiJRIjtzOjQ6IvCdmJgiO3M6MToiUSI7czo0OiLwnZmMIjtzOjE6IlEiO3M6NDoi8J2agCI7czoxOiJRIjtzOjM6IuK1lSI7czoxOiJRIjtzOjQ6IvCdkKsiO3M6MToiciI7czo0OiLwnZGfIjtzOjE6InIiO3M6NDoi8J2SkyI7czoxOiJyIjtzOjQ6IvCdk4ciO3M6MToiciI7czo0OiLwnZO7IjtzOjE6InIiO3M6NDoi8J2UryI7czoxOiJyIjtzOjQ6IvCdlaMiO3M6MToiciI7czo0OiLwnZaXIjtzOjE6InIiO3M6NDoi8J2XiyI7czoxOiJyIjtzOjQ6IvCdl78iO3M6MToiciI7czo0OiLwnZizIjtzOjE6InIiO3M6NDoi8J2ZpyI7czoxOiJyIjtzOjQ6IvCdmpsiO3M6MToiciI7czozOiLqrYciO3M6MToiciI7czozOiLqrYgiO3M6MToiciI7czozOiLhtKYiO3M6MToiciI7czozOiLisoUiO3M6MToiciI7czoyOiLQsyI7czoxOiJyIjtzOjM6IuqugSI7czoxOiJyIjtzOjI6IsqAIjtzOjE6InIiO3M6NDoi8J2IliI7czoxOiJSIjtzOjM6IuKEmyI7czoxOiJSIjtzOjM6IuKEnCI7czoxOiJSIjtzOjM6IuKEnSI7czoxOiJSIjtzOjQ6IvCdkJEiO3M6MToiUiI7czo0OiLwnZGFIjtzOjE6IlIiO3M6NDoi8J2RuSI7czoxOiJSIjtzOjQ6IvCdk6EiO3M6MToiUiI7czo0OiLwnZW9IjtzOjE6IlIiO3M6NDoi8J2WsSI7czoxOiJSIjtzOjQ6IvCdl6UiO3M6MToiUiI7czo0OiLwnZiZIjtzOjE6IlIiO3M6NDoi8J2ZjSI7czoxOiJSIjtzOjQ6IvCdmoEiO3M6MToiUiI7czoyOiLGpiI7czoxOiJSIjtzOjM6IuGOoSI7czoxOiJSIjtzOjM6IuGPkiI7czoxOiJSIjtzOjQ6IvCQkrQiO3M6MToiUiI7czozOiLhlociO3M6MToiUiI7czozOiLqk6MiO3M6MToiUiI7czo0OiLwlry1IjtzOjE6IlIiO3M6Mzoi772TIjtzOjE6InMiO3M6NDoi8J2QrCI7czoxOiJzIjtzOjQ6IvCdkaAiO3M6MToicyI7czo0OiLwnZKUIjtzOjE6InMiO3M6NDoi8J2TiCI7czoxOiJzIjtzOjQ6IvCdk7wiO3M6MToicyI7czo0OiLwnZSwIjtzOjE6InMiO3M6NDoi8J2VpCI7czoxOiJzIjtzOjQ6IvCdlpgiO3M6MToicyI7czo0OiLwnZeMIjtzOjE6InMiO3M6NDoi8J2YgCI7czoxOiJzIjtzOjQ6IvCdmLQiO3M6MToicyI7czo0OiLwnZmoIjtzOjE6InMiO3M6NDoi8J2anCI7czoxOiJzIjtzOjM6IuqcsSI7czoxOiJzIjtzOjI6Isa9IjtzOjE6InMiO3M6Mjoi0ZUiO3M6MToicyI7czozOiLqrqoiO3M6MToicyI7czo0OiLwkaOBIjtzOjE6InMiO3M6NDoi8JCRiCI7czoxOiJzIjtzOjM6Iu+8syI7czoxOiJTIjtzOjQ6IvCdkJIiO3M6MToiUyI7czo0OiLwnZGGIjtzOjE6IlMiO3M6NDoi8J2RuiI7czoxOiJTIjtzOjQ6IvCdkq4iO3M6MToiUyI7czo0OiLwnZOiIjtzOjE6IlMiO3M6NDoi8J2UliI7czoxOiJTIjtzOjQ6IvCdlYoiO3M6MToiUyI7czo0OiLwnZW+IjtzOjE6IlMiO3M6NDoi8J2WsiI7czoxOiJTIjtzOjQ6IvCdl6YiO3M6MToiUyI7czo0OiLwnZiaIjtzOjE6IlMiO3M6NDoi8J2ZjiI7czoxOiJTIjtzOjQ6IvCdmoIiO3M6MToiUyI7czoyOiLQhSI7czoxOiJTIjtzOjI6ItWPIjtzOjE6IlMiO3M6Mzoi4Y+VIjtzOjE6IlMiO3M6Mzoi4Y+aIjtzOjE6IlMiO3M6Mzoi6pOiIjtzOjE6IlMiO3M6NDoi8Ja8uiI7czoxOiJTIjtzOjQ6IvCQipYiO3M6MToiUyI7czo0OiLwkJCgIjtzOjE6IlMiO3M6Mzoi6p61IjtzOjE6It8iO3M6MjoizrIiO3M6MToi3yI7czoyOiLPkCI7czoxOiLfIjtzOjQ6IvCdm4MiO3M6MToi3yI7czo0OiLwnZu9IjtzOjE6It8iO3M6NDoi8J2ctyI7czoxOiLfIjtzOjQ6IvCdnbEiO3M6MToi3yI7czo0OiLwnZ6rIjtzOjE6It8iO3M6Mzoi4Y+wIjtzOjE6It8iO3M6NDoi8J2QrSI7czoxOiJ0IjtzOjQ6IvCdkaEiO3M6MToidCI7czo0OiLwnZKVIjtzOjE6InQiO3M6NDoi8J2TiSI7czoxOiJ0IjtzOjQ6IvCdk70iO3M6MToidCI7czo0OiLwnZSxIjtzOjE6InQiO3M6NDoi8J2VpSI7czoxOiJ0IjtzOjQ6IvCdlpkiO3M6MToidCI7czo0OiLwnZeNIjtzOjE6InQiO3M6NDoi8J2YgSI7czoxOiJ0IjtzOjQ6IvCdmLUiO3M6MToidCI7czo0OiLwnZmpIjtzOjE6InQiO3M6NDoi8J2anSI7czoxOiJ0IjtzOjM6IuG0myI7czoxOiJ0IjtzOjM6IuKKpCI7czoxOiJUIjtzOjM6IuKfmSI7czoxOiJUIjtzOjQ6IvCfnagiO3M6MToiVCI7czozOiLvvLQiO3M6MToiVCI7czo0OiLwnZCTIjtzOjE6IlQiO3M6NDoi8J2RhyI7czoxOiJUIjtzOjQ6IvCdkbsiO3M6MToiVCI7czo0OiLwnZKvIjtzOjE6IlQiO3M6NDoi8J2ToyI7czoxOiJUIjtzOjQ6IvCdlJciO3M6MToiVCI7czo0OiLwnZWLIjtzOjE6IlQiO3M6NDoi8J2VvyI7czoxOiJUIjtzOjQ6IvCdlrMiO3M6MToiVCI7czo0OiLwnZenIjtzOjE6IlQiO3M6NDoi8J2YmyI7czoxOiJUIjtzOjQ6IvCdmY8iO3M6MToiVCI7czo0OiLwnZqDIjtzOjE6IlQiO3M6MjoizqQiO3M6MToiVCI7czo0OiLwnZq7IjtzOjE6IlQiO3M6NDoi8J2btSI7czoxOiJUIjtzOjQ6IvCdnK8iO3M6MToiVCI7czo0OiLwnZ2pIjtzOjE6IlQiO3M6NDoi8J2eoyI7czoxOiJUIjtzOjM6IuKypiI7czoxOiJUIjtzOjI6ItCiIjtzOjE6IlQiO3M6Mzoi4Y6iIjtzOjE6IlQiO3M6Mzoi6pOUIjtzOjE6IlQiO3M6NDoi8Ja8iiI7czoxOiJUIjtzOjQ6IvCRorwiO3M6MToiVCI7czo0OiLwkIqXIjtzOjE6IlQiO3M6NDoi8JCKsSI7czoxOiJUIjtzOjQ6IvCQjJUiO3M6MToiVCI7czo0OiLwnZCuIjtzOjE6InUiO3M6NDoi8J2RoiI7czoxOiJ1IjtzOjQ6IvCdkpYiO3M6MToidSI7czo0OiLwnZOKIjtzOjE6InUiO3M6NDoi8J2TviI7czoxOiJ1IjtzOjQ6IvCdlLIiO3M6MToidSI7czo0OiLwnZWmIjtzOjE6InUiO3M6NDoi8J2WmiI7czoxOiJ1IjtzOjQ6IvCdl44iO3M6MToidSI7czo0OiLwnZiCIjtzOjE6InUiO3M6NDoi8J2YtiI7czoxOiJ1IjtzOjQ6IvCdmaoiO3M6MToidSI7czo0OiLwnZqeIjtzOjE6InUiO3M6Mzoi6p6fIjtzOjE6InUiO3M6Mzoi4bScIjtzOjE6InUiO3M6Mzoi6q2OIjtzOjE6InUiO3M6Mzoi6q2SIjtzOjE6InUiO3M6MjoiyosiO3M6MToidSI7czoyOiLPhSI7czoxOiJ1IjtzOjQ6IvCdm5YiO3M6MToidSI7czo0OiLwnZyQIjtzOjE6InUiO3M6NDoi8J2diiI7czoxOiJ1IjtzOjQ6IvCdnoQiO3M6MToidSI7czo0OiLwnZ6+IjtzOjE6InUiO3M6Mjoi1b0iO3M6MToidSI7czo0OiLwkJO2IjtzOjE6InUiO3M6NDoi8JGjmCI7czoxOiJ1IjtzOjM6IuKIqiI7czoxOiJVIjtzOjM6IuKLgyI7czoxOiJVIjtzOjQ6IvCdkJQiO3M6MToiVSI7czo0OiLwnZGIIjtzOjE6IlUiO3M6NDoi8J2RvCI7czoxOiJVIjtzOjQ6IvCdkrAiO3M6MToiVSI7czo0OiLwnZOkIjtzOjE6IlUiO3M6NDoi8J2UmCI7czoxOiJVIjtzOjQ6IvCdlYwiO3M6MToiVSI7czo0OiLwnZaAIjtzOjE6IlUiO3M6NDoi8J2WtCI7czoxOiJVIjtzOjQ6IvCdl6giO3M6MToiVSI7czo0OiLwnZicIjtzOjE6IlUiO3M6NDoi8J2ZkCI7czoxOiJVIjtzOjQ6IvCdmoQiO3M6MToiVSI7czoyOiLVjSI7czoxOiJVIjtzOjM6IuGIgCI7czoxOiJVIjtzOjQ6IvCQk44iO3M6MToiVSI7czozOiLhkYwiO3M6MToiVSI7czozOiLqk7QiO3M6MToiVSI7czo0OiLwlr2CIjtzOjE6IlUiO3M6NDoi8JGiuCI7czoxOiJVIjtzOjM6IuKIqCI7czoxOiJ2IjtzOjM6IuKLgSI7czoxOiJ2IjtzOjM6Iu+9liI7czoxOiJ2IjtzOjM6IuKFtCI7czoxOiJ2IjtzOjQ6IvCdkK8iO3M6MToidiI7czo0OiLwnZGjIjtzOjE6InYiO3M6NDoi8J2SlyI7czoxOiJ2IjtzOjQ6IvCdk4siO3M6MToidiI7czo0OiLwnZO/IjtzOjE6InYiO3M6NDoi8J2UsyI7czoxOiJ2IjtzOjQ6IvCdlaciO3M6MToidiI7czo0OiLwnZabIjtzOjE6InYiO3M6NDoi8J2XjyI7czoxOiJ2IjtzOjQ6IvCdmIMiO3M6MToidiI7czo0OiLwnZi3IjtzOjE6InYiO3M6NDoi8J2ZqyI7czoxOiJ2IjtzOjQ6IvCdmp8iO3M6MToidiI7czozOiLhtKAiO3M6MToidiI7czoyOiLOvSI7czoxOiJ2IjtzOjQ6IvCdm44iO3M6MToidiI7czo0OiLwnZyIIjtzOjE6InYiO3M6NDoi8J2dgiI7czoxOiJ2IjtzOjQ6IvCdnbwiO3M6MToidiI7czo0OiLwnZ62IjtzOjE6InYiO3M6Mjoi0bUiO3M6MToidiI7czoyOiLXmCI7czoxOiJ2IjtzOjQ6IvCRnIYiO3M6MToidiI7czozOiLqrqkiO3M6MToidiI7czo0OiLwkaOAIjtzOjE6InYiO3M6NDoi8J2IjSI7czoxOiJWIjtzOjI6ItmnIjtzOjE6IlYiO3M6Mjoi27ciO3M6MToiViI7czozOiLihaQiO3M6MToiViI7czo0OiLwnZCVIjtzOjE6IlYiO3M6NDoi8J2RiSI7czoxOiJWIjtzOjQ6IvCdkb0iO3M6MToiViI7czo0OiLwnZKxIjtzOjE6IlYiO3M6NDoi8J2TpSI7czoxOiJWIjtzOjQ6IvCdlJkiO3M6MToiViI7czo0OiLwnZWNIjtzOjE6IlYiO3M6NDoi8J2WgSI7czoxOiJWIjtzOjQ6IvCdlrUiO3M6MToiViI7czo0OiLwnZepIjtzOjE6IlYiO3M6NDoi8J2YnSI7czoxOiJWIjtzOjQ6IvCdmZEiO3M6MToiViI7czo0OiLwnZqFIjtzOjE6IlYiO3M6Mjoi0bQiO3M6MToiViI7czozOiLitLgiO3M6MToiViI7czozOiLhj5kiO3M6MToiViI7czozOiLhkK8iO3M6MToiViI7czozOiLqm58iO3M6MToiViI7czozOiLqk6YiO3M6MToiViI7czo0OiLwlryIIjtzOjE6IlYiO3M6NDoi8JGioCI7czoxOiJWIjtzOjQ6IvCQlJ0iO3M6MToiViI7czoyOiLJryI7czoxOiJ3IjtzOjQ6IvCdkLAiO3M6MToidyI7czo0OiLwnZGkIjtzOjE6InciO3M6NDoi8J2SmCI7czoxOiJ3IjtzOjQ6IvCdk4wiO3M6MToidyI7czo0OiLwnZSAIjtzOjE6InciO3M6NDoi8J2UtCI7czoxOiJ3IjtzOjQ6IvCdlagiO3M6MToidyI7czo0OiLwnZacIjtzOjE6InciO3M6NDoi8J2XkCI7czoxOiJ3IjtzOjQ6IvCdmIQiO3M6MToidyI7czo0OiLwnZi4IjtzOjE6InciO3M6NDoi8J2ZrCI7czoxOiJ3IjtzOjQ6IvCdmqAiO3M6MToidyI7czozOiLhtKEiO3M6MToidyI7czoyOiLRoSI7czoxOiJ3IjtzOjI6ItSdIjtzOjE6InciO3M6Mjoi1aEiO3M6MToidyI7czo0OiLwkZyKIjtzOjE6InciO3M6NDoi8JGcjiI7czoxOiJ3IjtzOjQ6IvCRnI8iO3M6MToidyI7czozOiLqroMiO3M6MToidyI7czo0OiLwkaOvIjtzOjE6IlciO3M6NDoi8JGjpiI7czoxOiJXIjtzOjQ6IvCdkJYiO3M6MToiVyI7czo0OiLwnZGKIjtzOjE6IlciO3M6NDoi8J2RviI7czoxOiJXIjtzOjQ6IvCdkrIiO3M6MToiVyI7czo0OiLwnZOmIjtzOjE6IlciO3M6NDoi8J2UmiI7czoxOiJXIjtzOjQ6IvCdlY4iO3M6MToiVyI7czo0OiLwnZaCIjtzOjE6IlciO3M6NDoi8J2WtiI7czoxOiJXIjtzOjQ6IvCdl6oiO3M6MToiVyI7czo0OiLwnZieIjtzOjE6IlciO3M6NDoi8J2ZkiI7czoxOiJXIjtzOjQ6IvCdmoYiO3M6MToiVyI7czoyOiLUnCI7czoxOiJXIjtzOjM6IuGOsyI7czoxOiJXIjtzOjM6IuGPlCI7czoxOiJXIjtzOjM6IuqTqiI7czoxOiJXIjtzOjM6IuGZriI7czoxOiJ4IjtzOjI6IsOXIjtzOjE6IngiO3M6Mzoi4qSrIjtzOjE6IngiO3M6Mzoi4qSsIjtzOjE6IngiO3M6Mzoi4qivIjtzOjE6IngiO3M6Mzoi772YIjtzOjE6IngiO3M6Mzoi4oW5IjtzOjE6IngiO3M6NDoi8J2QsSI7czoxOiJ4IjtzOjQ6IvCdkaUiO3M6MToieCI7czo0OiLwnZKZIjtzOjE6IngiO3M6NDoi8J2TjSI7czoxOiJ4IjtzOjQ6IvCdlIEiO3M6MToieCI7czo0OiLwnZS1IjtzOjE6IngiO3M6NDoi8J2VqSI7czoxOiJ4IjtzOjQ6IvCdlp0iO3M6MToieCI7czo0OiLwnZeRIjtzOjE6IngiO3M6NDoi8J2YhSI7czoxOiJ4IjtzOjQ6IvCdmLkiO3M6MToieCI7czo0OiLwnZmtIjtzOjE6IngiO3M6NDoi8J2aoSI7czoxOiJ4IjtzOjI6ItGFIjtzOjE6IngiO3M6Mzoi4ZWBIjtzOjE6IngiO3M6Mzoi4ZW9IjtzOjE6IngiO3M6Mzoi4ZmtIjtzOjE6IlgiO3M6Mzoi4pWzIjtzOjE6IlgiO3M6NDoi8JCMoiI7czoxOiJYIjtzOjQ6IvCRo6wiO3M6MToiWCI7czozOiLvvLgiO3M6MToiWCI7czozOiLihakiO3M6MToiWCI7czo0OiLwnZCXIjtzOjE6IlgiO3M6NDoi8J2RiyI7czoxOiJYIjtzOjQ6IvCdkb8iO3M6MToiWCI7czo0OiLwnZKzIjtzOjE6IlgiO3M6NDoi8J2TpyI7czoxOiJYIjtzOjQ6IvCdlJsiO3M6MToiWCI7czo0OiLwnZWPIjtzOjE6IlgiO3M6NDoi8J2WgyI7czoxOiJYIjtzOjQ6IvCdlrciO3M6MToiWCI7czo0OiLwnZerIjtzOjE6IlgiO3M6NDoi8J2YnyI7czoxOiJYIjtzOjQ6IvCdmZMiO3M6MToiWCI7czo0OiLwnZqHIjtzOjE6IlgiO3M6Mzoi6p6zIjtzOjE6IlgiO3M6MjoizqciO3M6MToiWCI7czo0OiLwnZq+IjtzOjE6IlgiO3M6NDoi8J2buCI7czoxOiJYIjtzOjQ6IvCdnLIiO3M6MToiWCI7czo0OiLwnZ2sIjtzOjE6IlgiO3M6NDoi8J2epiI7czoxOiJYIjtzOjM6IuKyrCI7czoxOiJYIjtzOjI6ItClIjtzOjE6IlgiO3M6Mzoi4rWdIjtzOjE6IlgiO3M6Mzoi4Zq3IjtzOjE6IlgiO3M6Mzoi6pOrIjtzOjE6IlgiO3M6NDoi8JCKkCI7czoxOiJYIjtzOjQ6IvCQirQiO3M6MToiWCI7czo0OiLwkIyXIjtzOjE6IlgiO3M6NDoi8JCUpyI7czoxOiJYIjtzOjI6IsmjIjtzOjE6InkiO3M6Mzoi4baMIjtzOjE6InkiO3M6Mzoi772ZIjtzOjE6InkiO3M6NDoi8J2QsiI7czoxOiJ5IjtzOjQ6IvCdkaYiO3M6MToieSI7czo0OiLwnZKaIjtzOjE6InkiO3M6NDoi8J2TjiI7czoxOiJ5IjtzOjQ6IvCdlIIiO3M6MToieSI7czo0OiLwnZS2IjtzOjE6InkiO3M6NDoi8J2VqiI7czoxOiJ5IjtzOjQ6IvCdlp4iO3M6MToieSI7czo0OiLwnZeSIjtzOjE6InkiO3M6NDoi8J2YhiI7czoxOiJ5IjtzOjQ6IvCdmLoiO3M6MToieSI7czo0OiLwnZmuIjtzOjE6InkiO3M6NDoi8J2aoiI7czoxOiJ5IjtzOjI6IsqPIjtzOjE6InkiO3M6Mzoi4bu/IjtzOjE6InkiO3M6Mzoi6q2aIjtzOjE6InkiO3M6MjoizrMiO3M6MToieSI7czozOiLihL0iO3M6MToieSI7czo0OiLwnZuEIjtzOjE6InkiO3M6NDoi8J2bviI7czoxOiJ5IjtzOjQ6IvCdnLgiO3M6MToieSI7czo0OiLwnZ2yIjtzOjE6InkiO3M6NDoi8J2erCI7czoxOiJ5IjtzOjI6ItGDIjtzOjE6InkiO3M6Mjoi0q8iO3M6MToieSI7czozOiLhg6ciO3M6MToieSI7czo0OiLwkaOcIjtzOjE6InkiO3M6Mzoi77y5IjtzOjE6IlkiO3M6NDoi8J2QmCI7czoxOiJZIjtzOjQ6IvCdkYwiO3M6MToiWSI7czo0OiLwnZKAIjtzOjE6IlkiO3M6NDoi8J2StCI7czoxOiJZIjtzOjQ6IvCdk6giO3M6MToiWSI7czo0OiLwnZScIjtzOjE6IlkiO3M6NDoi8J2VkCI7czoxOiJZIjtzOjQ6IvCdloQiO3M6MToiWSI7czo0OiLwnZa4IjtzOjE6IlkiO3M6NDoi8J2XrCI7czoxOiJZIjtzOjQ6IvCdmKAiO3M6MToiWSI7czo0OiLwnZmUIjtzOjE6IlkiO3M6NDoi8J2aiCI7czoxOiJZIjtzOjI6Is6lIjtzOjE6IlkiO3M6Mjoiz5IiO3M6MToiWSI7czo0OiLwnZq8IjtzOjE6IlkiO3M6NDoi8J2btiI7czoxOiJZIjtzOjQ6IvCdnLAiO3M6MToiWSI7czo0OiLwnZ2qIjtzOjE6IlkiO3M6NDoi8J2epCI7czoxOiJZIjtzOjM6IuKyqCI7czoxOiJZIjtzOjI6ItCjIjtzOjE6IlkiO3M6Mjoi0q4iO3M6MToiWSI7czozOiLhjqkiO3M6MToiWSI7czozOiLhjr0iO3M6MToiWSI7czozOiLqk6wiO3M6MToiWSI7czo0OiLwlr2DIjtzOjE6IlkiO3M6NDoi8JGipCI7czoxOiJZIjtzOjQ6IvCQirIiO3M6MToiWSI7czo0OiLwnZCzIjtzOjE6InoiO3M6NDoi8J2RpyI7czoxOiJ6IjtzOjQ6IvCdkpsiO3M6MToieiI7czo0OiLwnZOPIjtzOjE6InoiO3M6NDoi8J2UgyI7czoxOiJ6IjtzOjQ6IvCdlLciO3M6MToieiI7czo0OiLwnZWrIjtzOjE6InoiO3M6NDoi8J2WnyI7czoxOiJ6IjtzOjQ6IvCdl5MiO3M6MToieiI7czo0OiLwnZiHIjtzOjE6InoiO3M6NDoi8J2YuyI7czoxOiJ6IjtzOjQ6IvCdma8iO3M6MToieiI7czo0OiLwnZqjIjtzOjE6InoiO3M6Mzoi4bSiIjtzOjE6InoiO3M6Mzoi6q6TIjtzOjE6InoiO3M6NDoi8JGjhCI7czoxOiJ6IjtzOjQ6IvCQi7UiO3M6MToiWiI7czo0OiLwkaOlIjtzOjE6IloiO3M6Mzoi77y6IjtzOjE6IloiO3M6Mzoi4oSkIjtzOjE6IloiO3M6Mzoi4oSoIjtzOjE6IloiO3M6NDoi8J2QmSI7czoxOiJaIjtzOjQ6IvCdkY0iO3M6MToiWiI7czo0OiLwnZKBIjtzOjE6IloiO3M6NDoi8J2StSI7czoxOiJaIjtzOjQ6IvCdk6kiO3M6MToiWiI7czo0OiLwnZaFIjtzOjE6IloiO3M6NDoi8J2WuSI7czoxOiJaIjtzOjQ6IvCdl60iO3M6MToiWiI7czo0OiLwnZihIjtzOjE6IloiO3M6NDoi8J2ZlSI7czoxOiJaIjtzOjQ6IvCdmokiO3M6MToiWiI7czoyOiLOliI7czoxOiJaIjtzOjQ6IvCdmq0iO3M6MToiWiI7czo0OiLwnZunIjtzOjE6IloiO3M6NDoi8J2coSI7czoxOiJaIjtzOjQ6IvCdnZsiO3M6MToiWiI7czo0OiLwnZ6VIjtzOjE6IloiO3M6Mzoi4Y+DIjtzOjE6IloiO3M6Mzoi6pOcIjtzOjE6IloiO3M6NDoi8JGiqSI7czoxOiJaIjtzOjI6Isa/IjtzOjE6Iv4iO3M6Mjoiz7giO3M6MToi/iI7czoyOiLPtyI7czoxOiLeIjtzOjQ6IvCQk4QiO3M6MToi3iI7fQ==";

    private static function need_skip($string, $i)
    {
        $chars = " @\r\n\t";
        if (isset($string[$i]) && strpos($chars, $string[$i]) !== false) {
            $i++;
            return $i;
        }
        return false;
    }

    private static function match_shortopen_tag($string, $i, $needle, $j)
    {
        $pos_needle = false;
        $pos_string = false;
        if ((isset($needle[$j - 2]) && isset($string[$i - 2]))
            && (($needle[$j - 2] == '<') && ($string[$i - 2] == '<'))
            && (isset($needle[$j - 1]) && isset($string[$i - 1]))
            && ($needle[$j - 1] == '?' && $string[$i - 1] == '?')
        ) {
            $pos_needle = $j;
            $pos_string = $i;
        }
        if ($pos_needle && (isset($needle[$pos_needle]) && $needle[$pos_needle] == 'p')
            && (isset($needle[$pos_needle + 1]) && $needle[$pos_needle + 1] == 'h')
            && (isset($needle[$pos_needle + 2]) && $needle[$pos_needle + 2] == 'p')
        ) {
            $pos_needle = $pos_needle + 3;
        }

        if ($pos_string && (isset($string[$pos_string]) && $string[$pos_string] == 'p')
            && (isset($string[$pos_string + 1]) && $string[$pos_string + 1] == 'h')
            && (isset($string[$pos_string + 2]) && $string[$pos_string + 2] == 'p')
        ) {

            $pos_string = $pos_string + 3;
        }
        return [$pos_needle, $pos_string];
    }

    public static function strip_whitespace($string, $save_length = false)
    {
        StringToStreamWrapper::prepare($string);
        $strippedStr = @php_strip_whitespace(StringToStreamWrapper::WRAPPER_NAME . '://');

        if (!$save_length) {
            return $strippedStr;
        } else {
            $iMax = strlen($string);
            $jMax = strlen($strippedStr);

            if ($iMax != $jMax) {
                $newStr = '';
                $j = 0;

                for ($i = 0; $i < $iMax; $i++) {
                    if (isset($strippedStr[$j]) && trim($string[$i]) === trim($strippedStr[$j])) {
                        $newStr .= $string[$i];
                        $j++;
                    } else {
                        $newStr .= ' ';
                    }
                }

                return $newStr;
            }

            return $strippedStr;
        }
    }

    public static function normalize($string, $save_length = false)
    {
        $search  = [ ' ;', ' =', ' ,', ' .', ' (', ' )', ' {', ' }', '; ', '= ', ', ', '. '
            , '( ', '( ', '{ ', '} ', ' !', ' >', ' <', ' _', '_ ', '< ',  '> ', ' $', ' %', '% '
            , '# ', ' #', '^ ', ' ^', ' &', '& ', ' ?', '? '];
        $replace = [  ';',  '=',  ',',  '.',  '(',  ')',  '{',  '}', ';',  '=',  ',',  '.'
            ,  '(',   ')', '{',  '}',   '!',  '>',  '<',  '_', '_',  '<',   '>',   '$',  '%', '%'
            ,  '#',   '#', '^',   '^',  '&', '&',   '?', '?'];

        if (!$save_length) {
            $string = str_replace('@', '', $string);
            $string = preg_replace('~\s+~smi', ' ', $string);
            $string = str_replace($search, $replace, $string);
        }

        $string = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX]+)\s*\)~', function($m) use ($save_length) {
            if ($save_length) {
                return str_pad("'" . @chr(intval($m[1], 0)) . "'", strlen($m[0]), ' ');
            } else {
                return "'" . @chr(intval($m[1], 0)) . "'";
            }
        }, $string);

        for ($i = 0; $i < 2; $i++) {
            $string = preg_replace_callback('~%([0-9a-fA-F]{2})~', function($m) use ($save_length) {
                if ($save_length) {
                    return str_pad(chr(@hexdec($m[1])), strlen($m[0]), ' ');
                } else {
                    return @chr(hexdec($m[1]));
                }
            }, $string);
        }

        $iter = 0;
        $regexpHtmlAmp = '/\&[#\w]{2,20};/i';
        while ($iter < self::MAX_ITERATION && preg_match($regexpHtmlAmp, $string)) {
            $string = preg_replace_callback($regexpHtmlAmp, function ($m) use ($save_length) {
                if ($save_length) {
                    return str_pad(@html_entity_decode($m[0], ENT_QUOTES | ENT_HTML5), strlen($m[0]), ' ', STR_PAD_LEFT);
                } else {
                    return @html_entity_decode($m[0], ENT_QUOTES | ENT_HTML5);
                }
            }, $string);
            $iter++;
        }

        $string = preg_replace_callback('/\\\\x([a-fA-F0-9]{1,2})/i', function($m) use ($save_length) {
            if ($save_length) {
                return str_pad(chr(@hexdec($m[1])), strlen($m[0]), ' ');
            } else {
                return @chr(hexdec($m[1]));
            }
        }, $string);

        $string = preg_replace_callback('/\\\\([0-9]{1,3})/i', function($m) use ($save_length) {
            if ($save_length) {
                return str_pad(@chr(octdec($m[1])), strlen($m[0]), ' ');
            } else {
                return @chr(octdec($m[1]));
            }
        }, $string);

        $string = preg_replace_callback('/[\'"]\s*?\.+\s*?[\'"]/smi', function($m) use ($save_length) {
            if ($save_length) {
                return str_repeat(' ', strlen($m[0]));
            } else {
                return '';
            }
        }, $string);

        $string = preg_replace_callback('/[\'"]\s*?\++\s*?[\'"]/smi', function($m) use ($save_length) {
            if ($save_length) {
                return str_repeat(' ', strlen($m[0]));
            } else {
                return '';
            }
        }, $string);

        $string = preg_replace_callback('~<title[^>]{0,99}>\s*\K(.{0,300}?)(?=<\/title>)~mis', function($m) use ($save_length) {
            if(preg_match('~(?:\w[^\x00-\x7F]{1,9}|[^\x00-\x7F]{1,9}\w)~', $m[1])) {
                return self::HomoglyphNormalize($m[1]);
            }
            return $m[1];
        }, $string);

        if (!$save_length) {
            $string = str_replace('<?php', '<?php ', $string);
            $string = preg_replace('~\s+~', ' ', $string);
        }

        return $string;
    }

    public static function string_pos($string, $needle)
    {
        $j      = 0;
        $skip   = false;
        $start  = false;
        $end    = 0;
        $last_tag = [false, false];

        $string = self::strip_whitespace($string, true);
        $string = self::normalize($string, true);

        $needle = self::normalize($needle, true);

        for ($i = 0, $iMax = strlen($string); $i < $iMax; $i++) {
            if(trim($string[$i]) === '' && trim($needle[$j]) === '') {
                $string[$i] = $needle[$j] = ' ';
            }
            if ($string[$i] == $needle[$j]) {
                if ($j == 0) {
                    $start = $i;
                } elseif ($j == strlen($needle) - 1) {
                    $end = $i;
                    return [$start, $end];
                }
                $j++;
            } else {
                $match_php_tag = self::match_shortopen_tag($string, $i, $needle, $j);
                if ($match_php_tag[0] !== false && ($last_tag[0] !== $match_php_tag[0])) {
                    $j = $match_php_tag[0];
                }
                if ($match_php_tag[1] !== false && ($last_tag[1] !== $match_php_tag[1])) {
                    $i = $match_php_tag[1] - 1;
                }
                $last_tag = $match_php_tag;
                if ($match_php_tag[0] !== false || ($match_php_tag[1] !== false && (!empty($last_tag)))) {
                    continue;
                }
                $skip = self::need_skip($string, $i);
                if ($skip !== false && $start !== false) {
                    $i = $skip - 1;
                } else {
                    $j = 0;
                }
            }
        }
        return false;
    }

    private static function HomoglyphNormalize($str)
    {
        if (!is_array(self::$confusables)) {
            self::$confusables = @unserialize(@base64_decode(self::$confusables));
        }
        return str_replace(array_keys(self::$confusables), array_values(self::$confusables), $str);
    }

    /**
     * @param array $confusables
     */
    public static function setConfusables(array $confusables)
    {
        self::$confusables = $confusables;
    }
}

class Encoding
{
    // Unicode BOM is U+FEFF, but after encoded, it will look like this.

    const UTF32_BIG_ENDIAN_BOM = "\x00\x00\xFE\xFF";
    const UTF32_LITTLE_ENDIAN_BOM = "\xFF\xFE\x00\x00";
    const UTF16_BIG_ENDIAN_BOM = "\xFE\xFF";
    const UTF16_LITTLE_ENDIAN_BOM = "\xFF\xFE";
    const UTF8_BOM = "\xEF\xBB\xBF";

    public static function detectUTFEncoding($text)
    {
        $first2 = substr($text, 0, 2);
        $first3 = substr($text, 0, 3);
        $first4 = substr($text, 0, 4);

        if ($first3 == self::UTF8_BOM) {
            return 'UTF-8';
        } elseif ($first4 == self::UTF32_BIG_ENDIAN_BOM) {
            return 'UTF-32BE';
        } elseif ($first4 == self::UTF32_LITTLE_ENDIAN_BOM) {
            return 'UTF-32LE';
        } elseif ($first2 == self::UTF16_BIG_ENDIAN_BOM) {
            return 'UTF-16BE';
        } elseif ($first2 == self::UTF16_LITTLE_ENDIAN_BOM) {
            return 'UTF-16LE';
        }
        return false;
    }

    public static function iconvSupported()
    {
        return (function_exists('iconv') && is_callable('iconv'));
    }

    public static function convertToCp1251($from, $str)
    {
        $ret = @iconv($from, 'CP1251//TRANSLIT', $str);
        if ($ret === false) {
            $ret = @iconv($from, 'CP1251//IGNORE', Normalization::normalize($str));
        }
        return $ret;
    }

    public static function convertToUTF8($from, $str)
    {
        return @iconv($from, 'UTF-8//IGNORE', $str);
    }
}

class ScanUnit
{
    public static function QCR_ScanContent($checkers, $l_Unwrapped, $l_Content, $signs, $debug = null, $precheck = null, $processResult = null, &$return = null)
    {
        $smart_skipped = false;
        $flag = false;
        foreach ($checkers as $checker => $full) {
            $l_pos = 0;
            $l_SignId = '';
            if (isset($precheck) && is_callable($precheck)) {
                if (!$precheck($checker, $l_Unwrapped) && ($full && !$precheck($checker, $l_Content))) {
                    $smart_skipped = true;
                    continue;
                }
            }
            $flag = ScanCheckers::{$checker}($l_Unwrapped, $l_pos, $l_SignId, $signs, $debug);
            if ($flag && isset($processResult) && is_callable($processResult)) {
                $processResult($checker, $l_Unwrapped, $l_pos, $l_SignId, $return);
            }

            if (!$flag && $full) {
                $flag = ScanCheckers::{$checker}($l_Content, $l_pos, $l_SignId, $signs, $debug);
                if ($flag && isset($processResult) && is_callable($processResult)) {
                    $processResult($checker, $l_Content, $l_pos, $l_SignId, $return);
                }
            }
            if ($flag) {
                return true;
            }
        }
        if (!$flag && $smart_skipped) {
            $return = [RapidScanStorageRecord::RX_SKIPPED_SMART, '', ''];
        }
        return false;
    }
}

class ScanCheckers
{
    const URL_GRAB = '~(?:https?:)?\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+\~#=]{2,256}\.[a-z]{2,4}\b(?:[-a-zA-Z0-9@:%_\+.\~#?&/=]*)~msi';

    public static function WarningPHP($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->_SusDB as $l_Item) {
            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);
                    return true;
                }
            }
        }
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function Adware($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Res = false;

        foreach ($signs->_AdwareSig as $l_Item) {
            $offset = 0;
            while (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos = $l_Found[0][1];
                    $l_SigId = 'adware';
                    return true;
                }

                $offset = $l_Found[0][1] + 1;
            }
        }

        return $l_Res;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function CheckException(&$l_Content, &$l_Found, $signs, $debug = null)
    {
        $l_FoundStrPlus = substr($l_Content, max($l_Found[0][1] - 10, 0), 70);

        foreach ($signs->_ExceptFlex as $l_ExceptItem) {
            if (@preg_match('~' . $l_ExceptItem . '~smi', $l_FoundStrPlus, $l_Detected)) {
                return true;
            }
        }

        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function Phishing($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Res = false;

        foreach ($signs->_PhishingSig as $l_Item) {
            $offset = 0;
            while (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "Phis: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return $l_Pos;
                }
                $offset = $l_Found[0][1] + 1;

            }
        }

        return $l_Res;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function CriticalJS($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Res = false;

        foreach ($signs->_JSVirSig as $l_Item) {
            $offset = 0;
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }

            while (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "JS: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    $l_Res = true;
                    break;
                }

                $offset = $l_Found[0][1] + 1;

            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }

        }

        return $l_Res;
    }

    public static function CriticalJS_PARA($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->X_JSVirSig as $l_Item) {
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    //$l_SigId = myCheckSum($l_Item);
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "JS PARA: $l_Content matched [$l_Item] in $l_Pos\n";
                    }
                    return true;
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }
        }
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function CriticalPHPGIF($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        if (strpos($l_Content, 'GIF89') === 0) {
            $l_Pos = 0;
            $l_SigId = 'GIF';
            if (is_object($debug) && $debug->getDebugMode() == true) {
                echo "CRIT 6: $l_Content matched [GIF] in $l_Pos\n";
            }

            return true;
        }
        return false;
    }

    public static function CriticalPHPUploader($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        // detect uploaders / droppers
        $l_Found = null;
        if ((strlen($l_Content) < 2048) && ((($l_Pos = strpos($l_Content, 'multipart/form-data')) > 0) || (($l_Pos = strpos($l_Content, '$_FILE[') > 0)) || (($l_Pos = strpos($l_Content, 'move_uploaded_file')) > 0) || (preg_match('|\bcopy\s*\(|smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)))) {
            if ($l_Found != null) {
                $l_Pos = $l_Found[0][1];
                $l_SigId = 'uploader';
            }
            if (is_object($debug) && $debug->getDebugMode() == true) {
                echo "CRIT 7: $l_Content matched [uploader] in $l_Pos\n";
            }

            return true;
        }
    }

    public static function CriticalPHP_3($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->X_FlexDBShe as $l_Item) {
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "CRIT 3: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }
        }
        return false;
    }

    public static function CriticalPHP_2($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->XX_FlexDBShe as $l_Item) {
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "CRIT 2: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }
        }
        return false;
    }

    public static function CriticalPHP_4($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Content_lo = strtolower($l_Content);

        foreach ($signs->_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = AibolitHelpers::myCheckSum($l_Item);

                if (is_object($debug) && $debug->getDebugMode() == true) {
                    echo "CRIT 4: $l_Content matched [$l_Item] in $l_Pos\n";
                }

                return true;
            }
        }
        return false;
    }

    public static function CriticalPHP_5($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Content_lo = strtolower($l_Content);

        foreach ($signs->X_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = AibolitHelpers::myCheckSum($l_Item);

                if (is_object($debug) && $debug->getDebugMode() == true) {
                    echo "CRIT 5: $l_Content matched [$l_Item] in $l_Pos\n";
                }

                return true;
            }
        }
        return false;
    }

    public static function CriticalPHP($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->_FlexDBShe as $l_Item) {
            $offset = 0;

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }
            while (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    //$l_SigId = myCheckSum($l_Item);
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "CRIT 1: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }

                $offset = $l_Found[0][1] + 1;

            }
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }

        }

        return false;
    }

    public static function isOwnUrl($url, $own_domain)
    {
        if (!isset($own_domain)) {
            return false;
        }
        return (bool)preg_match('~^(http(s)?:)?//(www\.)?' . preg_quote($own_domain) . '~msi', $url);
    }

    public static function isUrlInList($url, $list)
    {
        if (isset($list)) {
            foreach ($list as $item) {
                if (preg_match('~' . $item . '~msiS', $url, $id, PREG_OFFSET_CAPTURE)) {
                    return $id;
                }
            }
        }

        return false;
    }

    public static function UrlChecker($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Pos      = [];
        $l_SigId    = [];
        $offset     = 0;
        
        while (preg_match(self::URL_GRAB, $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!self::isOwnUrl($l_Found[0][0], $signs->getOwnUrl())
                && (isset($signs->whiteUrls) && !self::isUrlInList($l_Found[0][0], $signs->whiteUrls->getDb()))
            ) {
                if ($id = self::isUrlInList($l_Found[0][0], $signs->blackUrls->getDb())) {
                    $l_Pos['black'][] = $l_Found[0][1];
                    $l_SigId['black'][] = $signs->blackUrls->getSig($id);
                } else {
                    $l_Pos['unk'][] = $l_Found[0][1];
                    $l_SigId['unk'][] = $l_Found[0][0];
                }
            }
            $offset = $l_Found[0][1] + strlen($l_Found[0][0]);
        }
        return !empty($l_Pos);
    }
}class Helpers
{

    public static function normalize($string, $save_length = false)
    {
        $search  = [ ' ;', ' =', ' ,', ' .', ' (', ' )', ' {', ' }', '; ', '= ', ', ', '. '
        , '( ', '( ', '{ ', '} ', ' !', ' >', ' <', ' _', '_ ', '< ',  '> ', ' $', ' %', '% '
        , '# ', ' #', '^ ', ' ^', ' &', '& ', ' ?', '? '];
        $replace = [  ';',  '=',  ',',  '.',  '(',  ')',  '{',  '}', ';',  '=',  ',',  '.'
        ,  '(',   ')', '{',  '}',   '!',  '>',  '<',  '_', '_',  '<',   '>',   '$',  '%', '%'
        ,  '#',   '#', '^',   '^',  '&', '&',   '?', '?'];

        if (!$save_length) {
            $string = str_replace('@', '', $string);
            $string = preg_replace('~\s+~smi', ' ', $string);
            $string = str_replace($search, $replace, $string);
        }

        $string = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX]+)\s*\)~', function($m) use ($save_length) {
            if ($save_length) {
                return str_pad("'" . @chr(intval($m[1], 0)) . "'", strlen($m[0]), ' ');
            } else {
                return "'" . @chr(intval($m[1], 0)) . "'";
            }
        }, $string);

        $string = preg_replace_callback('/\&\#([0-9]{1,3});/i', function($m) use ($save_length) {
            if ($save_length) {
                return str_pad(@chr((int)$m[1]), strlen($m[0]), ' ');
            } else {
                return @chr((int)$m[1]);
            }
        }, $string);

        $string = preg_replace_callback('/\\\\x([a-fA-F0-9]{1,2})/i', function($m) use ($save_length) {
            if ($save_length) {
                return str_pad(chr(@hexdec($m[1])), strlen($m[0]), ' ');
            } else {
                return @chr(hexdec($m[1]));
            }
        }, $string);

        $string = preg_replace_callback('/\\\\([0-9]{1,3})/i', function($m) use ($save_length) {
            if ($save_length) {
                return str_pad(@chr(octdec($m[1])), strlen($m[0]), ' ');
            } else {
                return @chr(octdec($m[1]));
            }
        }, $string);

        $string = preg_replace_callback('/[\'"]\s*?\.+\s*?[\'"]/smi', function($m) use ($save_length) {
            if ($save_length) {
                return str_repeat(' ', strlen($m[0]));
            } else {
                return '';
            }
        }, $string);

        $string = preg_replace_callback('/[\'"]\s*?\++\s*?[\'"]/smi', function($m) use ($save_length) {
            if ($save_length) {
                return str_repeat(' ', strlen($m[0]));
            } else {
                return '';
            }
        }, $string);

        if (!$save_length) {
            $string = str_replace('<?php', '<?php ', $string);
            $string = preg_replace('~\s+~', ' ', $string);
        }

        return $string;
    }

    public static function format($source)
    {
        $t_count = 0;
        $in_object = false;
        $in_at = false;
        $in_php = false;
        $in_for = false;
        $in_comp = false;
        $in_quote = false;
        $in_var = false;

        if (!defined('T_ML_COMMENT')) {
            define('T_ML_COMMENT', T_COMMENT);
        }

        $result = '';
        @$tokens = token_get_all($source);
        foreach ($tokens as $token) {
            if (is_string($token)) {
                $token = trim($token);
                if ($token == '{') {
                    if ($in_for) {
                        $in_for = false;
                    }
                    if (!$in_quote && !$in_var) {
                        $t_count++;
                        $result = rtrim($result) . ' ' . $token . "\n" . str_repeat('    ', $t_count);
                    } else {
                        $result = rtrim($result) . $token;
                    }
                } elseif ($token == '$') {
                    $in_var = true;
                    $result .= $token;
                } elseif ($token == '}') {
                    if (!$in_quote && !$in_var) {
                        $new_line = true;
                        $t_count--;
                        if ($t_count < 0) {
                            $t_count = 0;
                        }
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) .
                            $token . "\n" . @str_repeat('    ', $t_count);
                    } else {
                        $result = rtrim($result) . $token;
                    }
                    if ($in_var) {
                        $in_var = false;
                    }
                } elseif ($token == ';') {
                    if ($in_comp) {
                        $in_comp = false;
                    }
                    if ($in_for) {
                        $result .= $token . ' ';
                    } else {
                        $result .= $token . "\n" . str_repeat('    ', $t_count);
                    }
                } elseif ($token == ':') {
                    if ($in_comp) {
                        $result .= ' ' . $token . ' ';
                    } else {
                        $result .= $token . "\n" . str_repeat('    ', $t_count);
                    }
                } elseif ($token == '(') {
                    $result .= ' ' . $token;
                } elseif ($token == ')') {
                    $result .= $token;
                } elseif ($token == '@') {
                    $in_at = true;
                    $result .= $token;
                } elseif ($token == '.') {
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '=') {
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '?') {
                    $in_comp = true;
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '"') {
                    if ($in_quote) {
                        $in_quote = false;
                    } else {
                        $in_quote = true;
                    }
                    $result .= $token;
                } else {
                    $result .= $token;
                }
            } else {
                list($id, $text) = $token;
                switch ($id) {
                    case T_OPEN_TAG:
                    case T_OPEN_TAG_WITH_ECHO:
                        $in_php = true;
                        $result .= trim($text) . "\n";
                        break;
                    case T_CLOSE_TAG:
                        $in_php = false;
                        $result .= trim($text);
                        break;
                    case T_FOR:
                        $in_for = true;
                        $result .= trim($text);
                        break;
                    case T_OBJECT_OPERATOR:
                        $result .= trim($text);
                        $in_object = true;
                        break;

                    case T_ENCAPSED_AND_WHITESPACE:
                    case T_WHITESPACE:
                        $result .= trim($text);
                        break;
                    case T_RETURN:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_ELSE:
                    case T_ELSEIF:
                        $result = rtrim($result) . ' ' . trim($text) . ' ';
                        break;
                    case T_CASE:
                    case T_DEFAULT:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count - 1) . trim($text) . ' ';
                        break;
                    case T_FUNCTION:
                    case T_CLASS:
                        $result .= "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_AND_EQUAL:
                    case T_AS:
                    case T_BOOLEAN_AND:
                    case T_BOOLEAN_OR:
                    case T_CONCAT_EQUAL:
                    case T_DIV_EQUAL:
                    case T_DOUBLE_ARROW:
                    case T_IS_EQUAL:
                    case T_IS_GREATER_OR_EQUAL:
                    case T_IS_IDENTICAL:
                    case T_IS_NOT_EQUAL:
                    case T_IS_NOT_IDENTICAL:
                    case T_LOGICAL_AND:
                    case T_LOGICAL_OR:
                    case T_LOGICAL_XOR:
                    case T_MINUS_EQUAL:
                    case T_MOD_EQUAL:
                    case T_MUL_EQUAL:
                    case T_OR_EQUAL:
                    case T_PLUS_EQUAL:
                    case T_SL:
                    case T_SL_EQUAL:
                    case T_SR:
                    case T_SR_EQUAL:
                    case T_START_HEREDOC:
                    case T_XOR_EQUAL:
                        $result = rtrim($result) . ' ' . trim($text) . ' ';
                        break;
                    case T_COMMENT:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_ML_COMMENT:
                        $result = rtrim($result) . "\n";
                        $lines = explode("\n", $text);
                        foreach ($lines as $line) {
                            $result .= str_repeat('    ', $t_count) . trim($line);
                        }
                        $result .= "\n";
                        break;
                    case T_INLINE_HTML:
                        $result .= $text;
                        break;
                    default:
                        $result .= trim($text);
                        break;
                }
            }
        }
        return $result;
    }

    public static function replaceCreateFunction($str)
    {
        $hangs = 20;
        while (strpos($str, 'create_function') !== false && $hangs--) {
            $start_pos = strpos($str, 'create_function');
            $end_pos = 0;
            $brackets = 0;
            $started = false;
            $opened = 0;
            $closed = 0;
            for ($i = $start_pos, $iMax = strlen($str); $i < $iMax; $i++) {
                if ($str[$i] == '(') {
                    $started = true;
                    $brackets++;
                    $opened++;
                } else if ($str[$i] == ')') {
                    $closed++;
                    $brackets--;
                }
                if ($brackets == 0 && $started) {
                    $end_pos = $i + 1;
                    break;
                }
            }

            $cr_func = substr($str, $start_pos, $end_pos - $start_pos);
            $func = implode('function(', explode('create_function(\'', $cr_func, 2));
            //$func = substr_replace('create_function(\'', 'function(', $cr_func);
            //$func = str_replace('\',\'', ') {', $func);
            $func = implode(') {', explode('\',\'', $func, 2));
            $func = substr($func, 0, -2) . '}';
            $str = str_replace($cr_func, $func, $str);
        }
        return $str;
    }

    public static function calc($expr)
    {
        if (is_array($expr)) {
            $expr = $expr[0];
        }
        preg_match('~(chr|min|max|round)?\(([^\)]+)\)~msi', $expr, $expr_arr);
        if (@$expr_arr[1] == 'min' || @$expr_arr[1] == 'max') {
            return $expr_arr[1](explode(',', $expr_arr[2]));
        } elseif (@$expr_arr[1] == 'chr') {
            if ($expr_arr[2][0] === '(') {
                $expr_arr[2] = substr($expr_arr[2], 1);
            }
            $expr_arr[2] = self::calc($expr_arr[2]);
            return $expr_arr[1](intval($expr_arr[2]));
        } elseif (@$expr_arr[1] == 'round') {
            $expr_arr[2] = self::calc($expr_arr[2]);
            return $expr_arr[1]($expr_arr[2]);
        } else {
            preg_match_all('~([\d\.a-fx]+)([\*\/\-\+\^\|\&])?~', $expr, $expr_arr);
            foreach ($expr_arr[1] as &$expr_arg) {
                if (strpos($expr_arg, "0x")!==false) {
                    $expr = str_replace($expr_arg, hexdec($expr_arg), $expr);
                    $expr_arg = hexdec($expr_arg);
                }
            }
            if (in_array('*', $expr_arr[2]) !== false) {
                $pos = array_search('*', $expr_arr[2]);
                $res = $expr_arr[1][$pos] * $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '*' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '*' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('/', $expr_arr[2]) !== false) {
                $pos = array_search('/', $expr_arr[2]);
                $res = $expr_arr[1][$pos] / $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '/' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '/' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('-', $expr_arr[2]) !== false) {
                $pos = array_search('-', $expr_arr[2]);
                $res = $expr_arr[1][$pos] - $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '-' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '-' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('+', $expr_arr[2]) !== false) {
                $pos = array_search('+', $expr_arr[2]);
                $res = $expr_arr[1][$pos] + $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '+' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '+' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('^', $expr_arr[2]) !== false) {
                $pos = array_search('^', $expr_arr[2]);
                $res = $expr_arr[1][$pos] ^ $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '^' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '^' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('|', $expr_arr[2]) !== false) {
                $pos = array_search('|', $expr_arr[2]);
                $res = $expr_arr[1][$pos] | $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '|' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '|' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('&', $expr_arr[2]) !== false) {
                $pos = array_search('&', $expr_arr[2]);
                $res = $expr_arr[1][$pos] & $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '&' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '&' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } else {
                return $expr;
            }

            return $expr;
        }
    }

    public static function getEvalCode($string)
    {
        preg_match("/eval\(([^\)]+)\)/msi", $string, $matches);
        return (empty($matches)) ? '' : end($matches);
    }

    public static function getTextInsideQuotes($string)
    {
        if (preg_match_all('/("(.*)")/msi', $string, $matches)) {
            return @end(end($matches));
        } elseif (preg_match_all('/\((\'(.*)\')/msi', $string, $matches)) {
            return @end(end($matches));
        } else {
            return '';
        }
    }

    public static function getNeedles($string)
    {
        preg_match_all("/'(.*?)'/msi", $string, $matches);

        return (empty($matches)) ? [] : $matches[1];
    }

    public static function getHexValues($string)
    {
        preg_match_all('/0x[a-fA-F0-9]{1,8}/msi', $string, $matches);
        return (empty($matches)) ? [] : $matches[0];
    }

    public static function formatPHP($string)
    {
        $string = str_replace('<?php', '', $string);
        $string = str_replace('?>', '', $string);
        $string = str_replace(PHP_EOL, "", $string);
        $string = str_replace(";", ";\n", $string);
        $string = str_replace("}", "}\n", $string);
        return $string;
    }

    public static function detect_utf_encoding($text)
    {
        $first2 = substr($text, 0, 2);
        $first3 = substr($text, 0, 3);
        $first4 = substr($text, 0, 4);

        if ($first4 == chr(0x00) . chr(0x00) . chr(0xFE) . chr(0xFF)) {
            return 'UTF-32BE';
        } elseif ($first4 == chr(0xFF) . chr(0xFE) . chr(0x00) . chr(0x00)) {
            return 'UTF-32LE';
        } elseif ($first2 == chr(0xFE) . chr(0xFF)) {
            return 'UTF-16BE';
        } elseif ($first2 == chr(0xFF) . chr(0xFE)) {
            return 'UTF-16LE';
        }

        return false;
    }

    //from sample_16
    public static function someDecoder($str)
    {
        $str = base64_decode($str);
        $TC9A16C47DA8EEE87 = 0;
        $TA7FB8B0A1C0E2E9E = 0;
        $T17D35BB9DF7A47E4 = 0;
        $T65CE9F6823D588A7 = (ord($str[1]) << 8) + ord($str[2]);
        $i = 3;
        $T77605D5F26DD5248 = 0;
        $block = 16;
        $T7C7E72B89B83E235 = "";
        $T43D5686285035C13 = "";
        $len = strlen($str);

        $T6BBC58A3B5B11DC4 = 0;

        for (; $i < $len;) {
            if ($block == 0) {
                $T65CE9F6823D588A7 = (ord($str[$i++]) << 8);
                $T65CE9F6823D588A7 += ord($str[$i++]);
                $block = 16;
            }
            if ($T65CE9F6823D588A7 & 0x8000) {
                $TC9A16C47DA8EEE87 = (ord($str[$i++]) << 4);
                $TC9A16C47DA8EEE87 += (ord($str[$i]) >> 4);
                if ($TC9A16C47DA8EEE87) {
                    $TA7FB8B0A1C0E2E9E = (ord($str[$i++]) & 0x0F) + 3;
                    for ($T17D35BB9DF7A47E4 = 0; $T17D35BB9DF7A47E4 < $TA7FB8B0A1C0E2E9E; $T17D35BB9DF7A47E4++) {
                        $T7C7E72B89B83E235[$T77605D5F26DD5248 + $T17D35BB9DF7A47E4] =
                            $T7C7E72B89B83E235[$T77605D5F26DD5248 - $TC9A16C47DA8EEE87 + $T17D35BB9DF7A47E4];
                    }
                    $T77605D5F26DD5248 += $TA7FB8B0A1C0E2E9E;
                } else {
                    $TA7FB8B0A1C0E2E9E = (ord($str[$i++]) << 8);
                    $TA7FB8B0A1C0E2E9E += ord($str[$i++]) + 16;
                    for ($T17D35BB9DF7A47E4 = 0; $T17D35BB9DF7A47E4 < $TA7FB8B0A1C0E2E9E;
                         $T7C7E72B89B83E235[$T77605D5F26DD5248 + $T17D35BB9DF7A47E4++] = $str[$i]) {
                    }
                    $i++;
                    $T77605D5F26DD5248 += $TA7FB8B0A1C0E2E9E;
                }
            } else {
                $T7C7E72B89B83E235[$T77605D5F26DD5248++] = $str[$i++];
            }
            $T65CE9F6823D588A7 <<= 1;
            $block--;
            if ($i == $len) {
                $T43D5686285035C13 = $T7C7E72B89B83E235;
                if (is_array($T43D5686285035C13)) {
                    $T43D5686285035C13 = implode($T43D5686285035C13);
                }
                $T43D5686285035C13 = "?" . ">" . $T43D5686285035C13;
                return $T43D5686285035C13;
            }
        }
    }
    //

    public static function someDecoder2($WWAcmoxRAZq, $sBtUiFZaz)   //sample_05
    {
        $JYekrRTYM = str_rot13(gzinflate(str_rot13(base64_decode('y8svKCwqLiktK6+orFdZV0FWWljPyMzKzsmNNzQyNjE1M7ewNAAA'))));
        if ($WWAcmoxRAZq == 'asedferg456789034689gd') {
            $cEerbvwKPI = $JYekrRTYM[18] . $JYekrRTYM[19] . $JYekrRTYM[17] . $JYekrRTYM[17] . $JYekrRTYM[4] . $JYekrRTYM[21];
            return $cEerbvwKPI($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'zfcxdrtgyu678954ftyuip') {
            $JWTDeUKphI = $JYekrRTYM[1] . $JYekrRTYM[0] . $JYekrRTYM[18] . $JYekrRTYM[4] . $JYekrRTYM[32] .
                $JYekrRTYM[30] . $JYekrRTYM[26] . $JYekrRTYM[3] . $JYekrRTYM[4] . $JYekrRTYM[2] . $JYekrRTYM[14] .
                $JYekrRTYM[3] . $JYekrRTYM[4];
            return $JWTDeUKphI($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'gyurt456cdfewqzswexcd7890df') {
            $rezmMBMev = $JYekrRTYM[6] . $JYekrRTYM[25] . $JYekrRTYM[8] . $JYekrRTYM[13] . $JYekrRTYM[5] . $JYekrRTYM[11] . $JYekrRTYM[0] . $JYekrRTYM[19] . $JYekrRTYM[4];
            return $rezmMBMev($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'zcdfer45dferrttuihvs4321890mj') {
            $WbbQXOQbH = $JYekrRTYM[18] . $JYekrRTYM[19] . $JYekrRTYM[17] . $JYekrRTYM[26] . $JYekrRTYM[17] . $JYekrRTYM[14] . $JYekrRTYM[19] . $JYekrRTYM[27] . $JYekrRTYM[29];
            return $WbbQXOQbH($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'zsedrtre4565fbghgrtyrssdxv456') {
            $jPnPLPZcMHgH = $JYekrRTYM[2] . $JYekrRTYM[14] . $JYekrRTYM[13] . $JYekrRTYM[21] . $JYekrRTYM[4] . $JYekrRTYM[17] . $JYekrRTYM[19] . $JYekrRTYM[26] . $JYekrRTYM[20] . $JYekrRTYM[20] . $JYekrRTYM[3] . $JYekrRTYM[4] . $JYekrRTYM[2] . $JYekrRTYM[14] . $JYekrRTYM[3] . $JYekrRTYM[4];
            return $jPnPLPZcMHgH($sBtUiFZaz);
        }
    }

    public static function someDecoder3($str)
    {
        $l = base64_decode($str);
        $lllllll = 0;
        $lllll = 3;
        $llllll = (ord($l[1]) << 8) + ord($l[2]);
        $lllllllll = 16;
        $llllllll = [];
        for ($lllllMax = strlen($l); $lllll < $lllllMax;) {
            if ($lllllllll == 0) {
                $llllll = (ord($l[$lllll++]) << 8);
                $llllll+= ord($l[$lllll++]);
                $lllllllll = 16;
            }
            if ($llllll & 0x8000) {
                $lll = (ord($l[$lllll++]) << 4);
                $lll+= (ord($l[$lllll]) >> 4);
                if ($lll) {
                    $ll = (ord($l[$lllll++]) & 0x0f) + 3;
                    for ($llll = 0;$llll < $ll;$llll++) $llllllll[$lllllll + $llll] = $llllllll[$lllllll - $lll + $llll];
                    $lllllll+= $ll;
                } else {
                    $ll = (ord($l[$lllll++]) << 8);
                    $ll+= ord($l[$lllll++]) + 16;
                    for ($llll = 0;$llll < $ll;$llllllll[$lllllll + $llll++] = ord($l[$lllll]));
                    $lllll++;
                    $lllllll+= $ll;
                }
            } else {
                $llllllll[$lllllll++] = ord($l[$lllll++]);
            }
            $llllll <<= 1;
            $lllllllll--;
        }
        $lllll = 0;
        $lllllllll="?".chr(62);
        $llllllllll = "";
        for (;$lllll < $lllllll;) {
            $llllllllll.= chr($llllllll[$lllll++] ^ 0x07);
        }
        $lllllllll.=$llllllllll.chr(60)."?";
        return $lllllllll;
    }

    public static function PHPJiaMi_decoder($str, $md5, $rand, $lower_range = '')
    {
        $md5_xor = md5($md5);
        $lower_range = !$lower_range ? ord($rand) : $lower_range;
        $layer1 = '';
        for ($i=0, $iMax = strlen($str); $i < $iMax; $i++) {
            $layer1 .= ord($str[$i]) < 245 ? ((ord($str[$i]) > $lower_range && ord($str[$i]) < 245) ? chr(ord($str[$i]) / 2) : $str[$i]) : '';
        }
        $layer1 = base64_decode($layer1);
        $result = '';
        $j = $len_md5_xor = strlen($md5_xor);
        for ($i=0, $iMax = strlen($layer1); $i < $iMax; $i++) {
            $j = $j ? $j : $len_md5_xor;
            $j--;
            $result .= $layer1[$i] ^ $md5_xor[$j];
        }
        return $result;
    }

    public static function someDecoder4($ae, $key)
    {
        $at = [];
        for ($i = 0, $iMax = strlen($key); $i < $iMax; $i++) {
            if ((int)$key[$i] > 0) {
                $at[$i] = $key[$i];
            }
        }
        $at = array_values($at);
        $str = "";
        for ($i = 0, $iMax = count($ae); $i < $iMax; $i++) {
            if ($i < count($ae) - 1) {
                $str .= str_replace(md5($at[$i]), "", $ae[$i]);
            } else {
                $str .= $ae[$i];
            }
        }
        return $str;
    }

    public static function OELoveDecoder($arg1, $arg2 = '')
    {
        if (empty($arg1)) {
            return '';
        }
        $arg1 = base64_decode($arg1);
        if ($arg2 == '') return ~$arg1;
        //if ($arg2 == '-1') @271552362217();
        $len = strlen($arg1);
        $arg2 = str_pad($arg2, $len, $arg2);
        return $arg2 ^ $arg1;
    }

    public static function decodeEvalFuncBinary($input)
    {
        if (empty($input)) {
            return;
        }
        $keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        $chr1 = $chr2 = $chr3 = "";
        $enc1 = $enc2 = $enc3 = $enc4 = "";
        $i = 0;
        $output = "";
        $input = preg_replace("[^A-Za-z0-9\+\/\=]", "", $input);
        do {
            $enc1 = strpos($keyStr, substr($input, $i++, 1));
            $enc2 = strpos($keyStr, substr($input, $i++, 1));
            $enc3 = strpos($keyStr, substr($input, $i++, 1));
            $enc4 = strpos($keyStr, substr($input, $i++, 1));
            $chr1 = ($enc1 << 2) | ($enc2 >> 4);
            $chr2 = (($enc2 & 15) << 4) | ($enc3 >> 2);
            $chr3 = (($enc3 & 3) << 6) | $enc4;
            $output = $output . chr((int)$chr1);
            if ($enc3 != 64) {
                $output = $output . chr((int)$chr2);
            }
            if ($enc4 != 64) {
                $output = $output . chr((int)$chr3);
            }
            $chr1 = $chr2 = $chr3 = "";
            $enc1 = $enc2 = $enc3 = $enc4 = "";
        } while ($i < strlen($input));

        return $output;
    }

    public static function stripsquoteslashes($str)
    {
        $res = '';
        for ($i = 0, $iMax = strlen($str); $i < $iMax; $i++) {
            if (isset($str[$i+1]) && ($str[$i] == '\\' && ($str[$i+1] == '\\' || $str[$i+1] == '\''))) {
                continue;
            } else {
                $res .= $str[$i];
            }
        }
        return $res;
    }

    public static function isSafeFunc($str)
    {
        $safeFuncs = [
            'base64_decode', 'gzinflate', 'gzuncompress', 'strrev', 'strlen',
            'str_rot13', 'urldecode', 'rawurldecode', 'stripslashes', 'chr',
            'htmlspecialchars_decode', 'convert_uudecode','pack', 'ord',
            'str_repeat', 'sprintf', 'str_replace', 'strtr', 'hex2bin'
        ];
        return in_array(strtolower($str), $safeFuncs);

    }

    public static function aanKFMDigitsDecode($digits)
    {
        $res = '';
        $len = ceil(strlen($digits) / 3) * 3;
        $cipher = str_pad($digits, $len, '0', STR_PAD_LEFT);
        for ($i = 0; $i < (strlen($cipher) / 3);$i++) {
            $res .= chr(substr(strval($cipher), $i * 3, 3));
        }
        return $res;
    }

    public static function obf20200414_1_decrypt($data, $key)
    {
        $key = md5($key);
        $x = 0;
        $data = base64_decode($data);
        $len = strlen($data);
        $l = strlen($key);
        $char = '';
        for ($i = 0; $i < $len; $i++) {
            if ($x == $l) {
                $x = 0;
            }
            $char .= substr($key, $x, 1);
            $x++;
        }
        $str = '';
        for ($i = 0; $i < $len; $i++) {
            if (ord(substr($data, $i, 1)) < ord(substr($char, $i, 1))) {
                $str .= chr((ord(substr($data, $i, 1)) + 256) - ord(substr($char, $i, 1)));
            } else {
                $str .= chr(ord(substr($data, $i, 1)) - ord(substr($char, $i, 1)));
            }
        }
        return $str;
    }

    public static function Xtea_decrypt($text, $key)
    {
        $_key = '';
        $cbc = 1;

        if(is_array($key)) {
            $_key = $key;
        } else if(isset($key) && !empty($key)) {
            $_key = self::_str2long(str_pad($key, 16, $key));
        } else {
            $_key = [0, 0, 0, 0];
        }

        $plain = [];
        $cipher = self::_str2long(base64_decode($text));

        if($cbc == 1) {
            $i = 2;
        } else {
            $i = 0;
        }

        for ($i, $iMax = count($cipher); $i < $iMax; $i += 2) {
            $return = self::block_decrypt($cipher[$i], $cipher[$i+1], $_key);
            if($cbc == 1) {
                $plain[] = [$return[0] ^ $cipher[$i - 2], $return[1] ^ $cipher[$i - 1]];
            } else {
                $plain[] = $return;
            }
        }

        $output = "";
        for($i = 0, $iMax = count($plain); $i < $iMax; $i++) {
            $output .= self::_long2str($plain[$i][0]);
            $output .= self::_long2str($plain[$i][1]);
        }

        return $output;
    }

    public static function calculateMathStr($task)
    {
        $res = $task;

        while (preg_match('~\(?(\d+)\s?([+\-*\/])\s?(\d+)\)?~', $res, $subMatch)) {
            if (count($subMatch) === 4) {
                $subSearch = $subMatch[0];
                $operator = $subMatch[2];
                $number_1 = $subMatch[1];
                $number_2 = $subMatch[3];
                $res = str_replace($subSearch, self::calc("$number_1$operator$number_2"), $res);
            } else {
                return $res;
            }
        }

        return $res;
    }

    public static function decrypt_T_func($l)
    {
        $x2 = 256;
        $W2 = 8;
        $cY = [];
        $I3 = 0;
        $C4 = 0;
        for ($bs = 0; $bs < strlen($l); $bs++) {
            $I3 = ($I3 << 8) + ord($l[$bs]);
            $C4 += 8;
            if ($C4 >= $W2) {
                $C4 -= $W2;
                $cY[] = $I3 >> $C4;
                $I3 &= (1 << $C4) - 1;
                $x2++;
                if ($x2 >> $W2) {
                    $W2++;
                }
            }
        }
        $K5 = range("\x0", "\377");
        $UH = '';
        foreach ($cY as $bs => $xd) {
            if (!isset($K5[$xd])) {
                $iU = $Co . $Co[0];
            } else {
                $iU = $K5[$xd];
            }
            $UH .= $iU;
            if ($bs) {
                $K5[] = $Co . $iU[0];
            }
            $Co = $iU;
        }
        return $UH;
    }

    public static function getDecryptKeyForTinkleShell($size)
    {
        $bx = md5(base64_encode($size));
        $len = strlen($bx);
        $arr = [];
        for ($i = 0; $i < $len; $i++) {
            $arr[] = substr($bx, $i, 1);
        }
        $arr = array_unique($arr);
        $newstr = "";
        foreach ($arr as $k => $v) {
            $newstr .= $v;
        }
        if (strlen($newstr) < 9) {
            if (strpos($newstr, 'A') === false) {
                $newstr .= 'A';
            }
            if (strpos($newstr, 'B') === false) {
                $newstr .= 'B';
            }
            if (strpos($newstr, 'C') === false) {
                $newstr .= 'C';
            }
            if (strpos($newstr, 'D') === false) {
                $newstr .= 'D';
            }
            if (strpos($newstr, 'E') === false) {
                $newstr .= 'E';
            }
            if (strpos($newstr, 'F') === false) {
                $newstr .= 'F';
            }
            if (strpos($newstr, 'G') === false) {
                $newstr .= 'G';
            }
        }

       return strtoupper($newstr);
    }

    /**
     * For 4 args
     * @param array $arr
     *
     * @return string
     */
    public static function decodeEvalCreateFunc_1(array $arr) : string
    {
        $args = $arr;

        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < strlen($args[$i]); $j++) {
                $args[$i][$j] = chr(ord($args[$i][$j]) - ($i ? $args[$j xor $j] : 1));
            }
            if ($i == 2 && self::isSafeFunc($args[1]) && self::isSafeFunc($args[2])) {
                $args[3] = @$args[1](@$args[2]($args[3]));
            }
        }

        return $args[3];
    }

    /**
     * For 3 args
     * @param array $arr
     *
     * @return string
     */
    public static function decodeEvalCreateFunc_2(array $arr) : string
    {
        $args = $arr;

        for ($i = 0; $i < 3; $i++) {
            for ($j = 0; $j < strlen($args[$i]); $j++) {
                $args[$i][$j] = chr(ord($args[$i][$j]) - 1);
            }
            if ($i == 1 && self::isSafeFunc($args[0]) && self::isSafeFunc($args[1])) {
                $args[2] = @$args[0](@$args[1]($args[2]));
            }
        }

        return $args[2];
    }

    /**
     * @param string $key
     * @param string $data
     *
     * @return string
     */
    public static function decodeFuncVars(string $key, string $data): string
    {
        $hakfku = $data;
        $keyLen = strlen($key);
        $dataLen = strlen($hakfku);
        $res = "";
        for ($i = 0; $i < $dataLen;) {
            for ($j = 0; ($j < $keyLen && $i < $dataLen); $j++, $i++) {
                $res .= $hakfku[$i] ^ $key[$j];
            }
        }

        return $res;
    }

    /**
     * @param string $dictionary
     * @param string $content
     *
     * @return array
     */
    public static function getVarsFromDictionary($dictionary, $content) : array
    {
        $vars = [];

        preg_match_all('~(\$(?:[^\w]+|\w+)\s*=(\s?\.?\s?\$(?:[^\w]+|\w+)[{\[]\d+[\]}])+)~msi', $content, $concatMatches);
        for ($i = 0; $iMax = count($concatMatches[0]), $i <= $iMax; $i++) {
            preg_match_all('~(\$(?:[^\w]+|\w+)(=))?(\s?(\.?)\s?\$(?:[^\w]+|\w+)[{\[](\d+)[\]}])~msi',
                $concatMatches[0][$i], $varMatches);
            for ($j = 0; $jMax = count($varMatches[0]), $j < $jMax; $j++) {
                $varName = substr($varMatches[1][0], 0, -1);
                $value = $dictionary[(int)$varMatches[5][$j]] ?? '';

                if ($varMatches[2][$j] === '=') {
                    $vars[$varName] = $value;
                } else {
                    $vars[$varName] .= $value;
                }
            }
        }

        return $vars;
    }

    /**
     * @param array  $vars
     * @param string $content
     *
     * @return array
     */
    public static function getVarsFromDictionaryDynamically(array &$vars = [], string $content = ''): array
    {
        preg_match_all('~(\$\w+)(\.)?\s?=\s?(?:\$\w+[{\[]?\d+[}\]]?\.?)+;~msi', $content, $varsMatches, PREG_SET_ORDER);
        foreach ($varsMatches as $varsMatch) {
            preg_match_all('~(\$\w+)[{\[]?(\d+)?[}\]]?~msi', $varsMatch[0], $subVarsMatches, PREG_SET_ORDER);
            $concat = '';
            foreach ($subVarsMatches as $subVarsMatch) {
                if (isset($subVarsMatch[2])) {
                    $concat .= $vars[$subVarsMatch[1]][(int)$subVarsMatch[2]] ?? '';
                } else if ($varsMatch[1] !== $subVarsMatch[1]) {
                    $concat .= $vars[$subVarsMatch[1]];
                }
            }
            if (isset($vars[$varsMatch[1]])) {
                $vars[$varsMatch[1]] .= $concat;
            } else {
                $vars[$varsMatch[1]] = $concat;
            }
        }

        return $vars;
    }

    /**
     * @param string $str
     * @return string
     */
    public static function concatVariableValues($str) : string
    {
        preg_match_all('/\$\w+\s?(\.?)=\s?"([\w=\+\/]+)"/', $str, $concatVars);

        $strVar = "";

        foreach ($concatVars[2] as $index => $concatVar) {
            if ($concatVars[1][$index] === '.') {
                $strVar .= $concatVar;
            } else {
                $strVar = $concatVar;
            }
        }

        return $strVar;
    }

    /**
     * Concats simple str without variable
     *
     * @param string $str
     * @return string
     */
    public static function concatStr($str) : string
    {
        preg_match_all('~(\.?)\s?[\'"]([\w=\+/%&]+)[\'"]\s?~msi', $str, $concatStrings);

        $strVar = "";

        foreach ($concatStrings[2] as $index => $concatString) {
            if ($concatStrings[1][$index] === '.') {
                $strVar .= $concatString;
            } else {
                $strVar = $concatString;
            }
        }

        return $strVar;
    }

    /**
     * Concats simple strings without variable in content globally
     *
     * @param string $str
     * @return string
     */
    public static function concatStringsInContent($str) : string
    {
        $strVar = preg_replace_callback('~((?:\.?[\'"][\w=]+[\'"]){2,})~msi', function ($m) {
            return '\'' . self::concatStr($m[1]) . '\'';
        }, $str);

        return $strVar;
    }

    /**
     * @param $dictionaryVar
     * @param $dictionaryValue
     * @param $str
     *
     * @return string
     */
    public static function replaceVarsFromDictionary($dictionaryVar, $dictionaryValue, $str) : string
    {
        $dictionaryName = $dictionaryVar[0] === '$' ? ('\\' . $dictionaryVar) : $dictionaryVar;
        $result = $str;

        if (preg_match('~\$GLOBALS\[([\'"]\w+[\'"])\]~msi', $dictionaryVar, $match)) {
            $dictionaryName = '\$GLOBALS\[' . $match[1] . '\]';
        }

        $result = preg_replace_callback(
            '~(?:' . $dictionaryName . '[\[{][\'"]?(?:\d+)[\'"]?[\]}]\s?\.?\s?)+~msi',
            function ($match) use ($dictionaryValue) {
                preg_match_all('~\]?[\[{][\'"]?(\d+)[\'"]?[\]}]\.?~msi', $match[0], $varsMatch);

                $result = "";

                foreach ($varsMatch[1] as $index) {
                    $result .= $dictionaryValue[(int)$index];
                }

                $lastChar = $match[0][strlen($match[0]) - 1] ?? null;
                $lastChar = $lastChar === '.' ? '.' : '';

                return "'$result'" . $lastChar;
            },
            $result
        );

        return $result;
    }

    /**
     * @param string $arrayName
     * @param array  $array
     * @param string $str
     *
     * @return string
     */
    public static function replaceVarsByArrayName(string $arrayName, array $array, string $str): string
    {
        $result = preg_replace_callback('~\s?\\' . $arrayName . '\s?\[\s?(\d+)\s?\]\s?~msi',
            function ($match) use ($array) {
                return $array[$match[1]] ?? $match[0];
            },
            $str
        );

        return $result;
    }

    /**
     * Collects simple or concated vars from str
     * @param string $str
     * @param string $trimQuote
     *
     * @return array
     */
    public static function collectVars($str, string $trimQuote = '"', &$vars = []) : array
    {
        preg_match_all('~(\$\w+)\s?(\.)?=\s?([\'"].*?[\'"]);~msi', $str, $matches);

        foreach ($matches[1] as $index => $match) {
            $varName = $match;
            $varValue = str_replace("$trimQuote.$trimQuote", '', $matches[3][$index]);
            $varValue = stripcslashes(trim($varValue, $trimQuote));
            if ($matches[2][$index] !== '.') {
                $vars[$varName] = $varValue;
            } else {
                $vars[$varName] .= $varValue;
            }
        }

        return $vars;
    }

    /**
     * Collects simple or concated str
     * @param string $str
     * @param string $trimQuote
     *
     * @return string
     */
    public static function collectStr($str, string $trimQuote = '"') : string
    {
        preg_match('~["\'\w%=\.]+~msi', $str, $match);

        $str = str_replace("$trimQuote.$trimQuote", '', $match[0]);
        $str = trim($str, $trimQuote);

        return $str;
    }

    /**
     * Collects function wrapped vars with one arg from str
     * ex. var1 = base64_decode(str1); var2 = gzinflate(str2); and etc.
     *
     * @param string $str
     *
     * @return array
     */
    public static function collectFuncVars(string $str, &$vars = []): array
    {
        preg_match_all('~(\$\w+)\s*=\s*(\w+)\([\'"]([\w+/=]+)[\'"]\);~msi', $str, $matches);

        foreach ($matches[1] as $index => $match) {
            $func = $matches[2][$index];
            $str = $matches[3][$index];

            if (self::isSafeFunc($func)) {
                $str = @$func($str);
            }
            $vars[$match] = self::isSafeFunc($str) ? $str : "'$str'";
        }

        return $vars;
    }

    /**
     * @param array  $vars
     * @param string $str
     *
     * @return string
     */
    public static function replaceVarsFromArray(array $vars, string $str, bool $isFunc = false, $toStr = false) : string
    {
        $result = $str;

        uksort($vars, function($a, $b) {
            return strlen($b) <=> strlen($a);
        });

        foreach ($vars as $name => $value) {
            $result = preg_replace_callback('~{?(@)?\${?[\'"]?GLOBALS[\'"]?}?\[[\'"]' . substr($name, 1) . '[\'"]\]}?~msi',
                function ($m) use ($value) {
                    return $m[1] . $value;
                }, $result);

            $result = str_replace('{' . $name . '}', $value, $result);
            $result = str_replace($name . '(', trim($value, '\'"') . '(', $result);

            if (!$isFunc && !$toStr) {
                $result = str_replace($name, $value, $result);
            } else if ($toStr) {
                $result = str_replace($name, "'$value'", $result);
            }

        }

        return $result;
    }

    /**
     * @param $str
     * @return array
     */
    public static function collectVarsChars($str)
    {
        $vars = [];
        preg_match_all('~(\$\w+)=\'(\w)\';~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $m) {
            $vars[$m[1]] = $m[2];
        }
        return $vars;
    }

    /**
     * Removes duplicated string variables after replacing
     *
     * @param string $str
     *
     * @return string
     */
    public static function removeDuplicatedStrVars($str) : string
    {
        return preg_replace('~[\'"]?([^\'"]+)[\'"]?\s?=\s?[\'"]?\1[\'"]?;~msi','', $str);
    }

    /**
     * @param $chars
     * @param $str
     * @return array
     */
    public static function assembleStrings($chars, $str)
    {
        $vars = [];
        foreach($chars as $var => $char) {
            $str = preg_replace_callback('~\\' . $var . '\s*([.;])~ms',
                function ($m) use ($char) {
                return '\'' . $char . '\''. $m[1];
            }, $str);
        }
        $vars = self::collectVars($str, '\'');
        return $vars;
    }

    private static function block_decrypt($y, $z, $key)
    {
        $delta = 0x9e3779b9;
        $sum = 0xC6EF3720;
        $n = 32;

        for ($i = 0; $i < 32; $i++) {
            $z = self::_add($z, -(self::_add($y << 4 ^ self::_rshift($y, 5), $y)
                ^ self::_add($sum, $key[self::_rshift($sum, 11) & 3])));
            $sum = self::_add($sum, -$delta);
            $y = self::_add($y, -(self::_add($z << 4 ^ self::_rshift($z, 5), $z)
                ^ self::_add($sum, $key[$sum & 3])));

        }
        return [$y, $z];
    }

    private static function _rshift($integer, $n)
    {
        if (0xffffffff < $integer || -0xffffffff > $integer) {
            $integer = fmod($integer, 0xffffffff + 1);
        }

        if (0x7fffffff < $integer) {
            $integer -= 0xffffffff + 1.0;
        } else if (-0x80000000 > $integer) {
            $integer += 0xffffffff + 1.0;
        }

        if (0 > $integer) {
            $integer &= 0x7fffffff;
            $integer >>= $n;
            $integer |= 1 << (31 - $n);
        } else {
            $integer >>= $n;
        }
        return $integer;
    }

    private static function _add($i1, $i2)
    {
        $result = 0.0;

        foreach (func_get_args() as $value) {
            if (0.0 > $value) {
                $value -= 1.0 + 0xffffffff;
            }
            $result += $value;
        }

        if (0xffffffff < $result || -0xffffffff > $result) {
            $result = fmod($result, 0xffffffff + 1);
        }

        if (0x7fffffff < $result) {
            $result -= 0xffffffff + 1.0;
        } else if (-0x80000000 > $result) {
            $result += 0xffffffff + 1.0;
        }
        return $result;
    }

    private static function _str2long($data)
    {
        $tmp = unpack('N*', $data);
        $data_long = [];
        $j = 0;

        foreach ($tmp as $value) $data_long[$j++] = $value;
        return $data_long;
    }

    private static function _long2str($l){
        return pack('N', $l);
    }

    ///////////////////////////////////////////////////////////////////////////
}




///////////////////////////////////////////////////////////////////////////

function parseArgs($argv)
{
    array_shift($argv);
    $o = [];
    foreach ($argv as $a) {
        if (substr($a, 0, 2) == '--') {
            $eq = strpos($a, '=');
            if ($eq !== false) {
                $o[substr($a, 2, $eq - 2)] = substr($a, $eq + 1);
            } else {
                $k = substr($a, 2);
                if (!isset($o[$k])) {
                    $o[$k] = true;
                }
            }
        } else {
            if (substr($a, 0, 1) == '-') {
                if (substr($a, 2, 1) == '=') {
                    $o[substr($a, 1, 1)] = substr($a, 3);
                } else {
                    foreach (str_split(substr($a, 1)) as $k) {
                        if (!isset($o[$k])) {
                            $o[$k] = true;
                        }
                    }
                }
            } else {
                $o[] = $a;
            }
        }
    }
    return $o;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////
// cli handler
if (!defined('AIBOLIT_START_TIME') && !defined('PROCU_CLEAN_DB') && @strpos(__FILE__, @$argv[0])!==false) {

    set_time_limit(0);
    ini_set('max_execution_time', '900000');
    ini_set('realpath_cache_size', '16M');
    ini_set('realpath_cache_ttl', '1200');
    ini_set('pcre.backtrack_limit', '1000000');
    ini_set('pcre.recursion_limit', '12500');
    ini_set('pcre.jit', '1');
    $options = parseArgs($argv);
    $str = php_strip_whitespace($options[0]);
    $str2 = file_get_contents($options[0]);
    $l_UnicodeContent = Helpers::detect_utf_encoding($str);
    $l_UnicodeContent2 = Helpers::detect_utf_encoding($str2);
    if ($l_UnicodeContent !== false) {
        if (function_exists('iconv')) {
            $str = iconv($l_UnicodeContent, "UTF-8", $str);
            $str2 = iconv($l_UnicodeContent2, "UTF-8", $str2);
        }
    }
    $d = new Deobfuscator($str, $str2);
    $start = microtime(true);
    $deobf_type = $d->getObfuscateType($str);
    if ($deobf_type != '') {
        $str = $d->deobfuscate();
    }
    $code = $str;
    if (isset($options['prettyprint'])) {
        $code = Helpers::normalize($code);
        $code = Helpers::format($code);
    }
    if ($l_UnicodeContent !== false) {
        if (function_exists('iconv')) {
            $code = iconv('UTF-8', $l_UnicodeContent . '//IGNORE', $code);
        }
    }
    echo $code;
    echo "\n";
    //echo 'Execution time: ' . round(microtime(true) - $start, 4) . ' sec.';
}

class Deobfuscator
{
    private $signatures = [
        [
            'full' => '~for\((\$\w{1,40})=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);(if\(isset\(\$_(GET|REQUEST|POST|COOKIE)\[[\'"][^\'"]+[\'"]\]\)\)\{[^}]+;\})?~msi',
            'fast' => '~for\((\$\w{1,40})=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);~msi',
            'id'   => 'parenthesesString',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*\'[\'.error_reporting]+;\s*\1\(0\);((?:\s*\$\w+\s*=\s*[\'abcdefgilnorstz64_.]+;)+)((?:\s*\$\w+\s*=\s*\'[^;]+\';)+)((?:\s*\$\w+\()+)(\$\w+)[\s\)]+;\s*die\(\);~mis',
            'fast' => '~(\$\w+)\s*=\s*\'[\'.error_reporting]+;\s*\1\(0\);((?:\s*\$\w+\s*=\s*[\'abcdefgilnorstz64_.]+;)+)((?:\s*\$\w+\s*=\s*\'[^;]+\';)+)((?:\s*\$\w+\()+)(\$\w+)[\s\)]+;\s*die\(\);~mis',
            'id'   => 'blackScorpShell',
        ],
        [
            'full' => '~(?(DEFINE)(?\'c\'(?:/\*\w+\*/)*))(\$\w+)\s*=\s*basename(?&c)\((?&c)trim(?&c)\((?&c)preg_replace(?&c)\((?&c)rawurldecode(?&c)\((?&c)"[%0-9A-F\.]+"(?&c)\)(?&c),\s*\'\',\s*__FILE__(?&c)\)(?&c)\)(?&c)\)(?&c);(\$\w+)\s*=\s*"([%\w\.\-\~]+)";(?:(\$\w+)=[^;]+;\5(?&c)\((?&c)\'\',\s*\'};\'\s*\.\s*(?&c)\()?(?:eval(?&c)\()?(?&c)rawurldecode(?&c)\((?&c)\3(?&c)\)(?&c)\s*\^\s*substr(?&c)\((?&c)str_repeat(?&c)\((?&c)\2,\s*(?&c)\((?&c)strlen(?&c)\((?&c)\3(?&c)\)(?&c)/strlen(?&c)\((?&c)\2(?&c)\)(?&c)\)(?&c)\s*\+\s*1(?&c)\)(?&c),\s*0,(?&c)\s*strlen(?&c)\((?&c)\3(?&c)\)(?&c)\)(?&c)\)(?:(?&c)\s*\.\s*\'{\'(?&c)\))?(?&c);~msi',
            'fast' => '~(?(DEFINE)(?\'c\'(?:/\*\w+\*/)*))(\$\w+)\s*=\s*basename(?&c)\((?&c)trim(?&c)\((?&c)preg_replace(?&c)\((?&c)rawurldecode(?&c)\((?&c)"[%0-9A-F\.]+"(?&c)\)(?&c),\s*\'\',\s*__FILE__(?&c)\)(?&c)\)(?&c)\)(?&c);(\$\w+)\s*=\s*"([%\w\.\-\~]+)";(?:(\$\w+)=[^;]+;\5(?&c)\((?&c)\'\',\s*\'};\'\s*\.\s*(?&c)\()?(?:eval(?&c)\()?(?&c)rawurldecode(?&c)\((?&c)\3(?&c)\)(?&c)\s*\^\s*substr(?&c)\((?&c)str_repeat(?&c)\((?&c)\2,\s*(?&c)\((?&c)strlen(?&c)\((?&c)\3(?&c)\)(?&c)/strlen(?&c)\((?&c)\2(?&c)\)(?&c)\)(?&c)\s*\+\s*1(?&c)\)(?&c),\s*0,(?&c)\s*strlen(?&c)\((?&c)\3(?&c)\)(?&c)\)(?&c)\)(?:(?&c)\s*\.\s*\'{\'(?&c)\))?(?&c);~msi',
            'id'   => 'xorFName',
        ],
        [
            'full' => '~(\$\w{1,40})=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'([^\']+)\'\);eval\(\1\(gzuncompress\(\2\(\3\)\)\)\);~msi',
            'fast' => '~(\$\w{1,40})=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'([^\']+)\'\);eval\(\1\(gzuncompress\(\2\(\3\)\)\)\);~msi',
            'id'   => 'phpMess',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\"([^\"]+)\";\s*\$\w+\s*=\s*\$\w+\(\1,\"[^\"]+\",\"[^\"]+\"\);\s*\$\w+\(\"[^\"]+\",\"[^\"]+\",\"\.\"\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\"([^\"]+)\";\s*\$\w+\s*=\s*\$\w+\(\1,\"[^\"]+\",\"[^\"]+\"\);\s*\$\w+\(\"[^\"]+\",\"[^\"]+\",\"\.\"\);~msi',
            'id'   => 'pregReplaceSample05',
        ],


        [
            'full' => '~(\$\w{1,40})\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\"([^\"]+)\";\s*(\$\w+)\s*=\s*.+?;\s*\2\(\5,\"[^\']+\'\3\'[^\"]+\",\"\.\"\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\"([^\"]+)\";\s*(\$\w+)\s*=\s*.+?;\s*\2\(\5,\"[^\']+\'\3\'[^\"]+\",\"\.\"\);~msi',
            'id'   => 'pregReplaceB64',
        ],
        [
            'full' => '~preg_replace\([\'"]/\(\.\*\)/e[\'"],[\'"]([^\'"]+)[\'"],\s?NULL\);~msi',
            'fast' => '~preg_replace\([\'"]/\(\.\*\)/e[\'"],[\'"]([^\'"]+)[\'"],\s?NULL\);~msi',
            'id'   => 'pregReplaceStr',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\'([^\']+)\';\s*\1\s*=\s*gzinflate\s*\(base64_decode\s*\(\1\)\);\s*\1\s*=\s*str_replace\s*\(\"__FILE__\",\"\'\$\w+\'\",\1\);\s*eval\s*\(\1\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\'([^\']+)\';\s*\1\s*=\s*gzinflate\s*\(base64_decode\s*\(\1\)\);\s*\1\s*=\s*str_replace\s*\(\"__FILE__\",\"\'\$\w+\'\",\1\);\s*eval\s*\(\1\);~msi',
            'id'   => 'GBE',
        ],
        [
            'full' => '~(\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\])\s*=\s*\s*array\s*\(\s*base64_decode\s*\(.+?((.+?\1\[\d+\]).+?)+[^;]+;(\s*include\(\$_\d+\);)?}?((.+?_+\d+\(\d+\))+[^;]+;)?(.*?(\$[a-z]+).+\8_\d+;)?(echo\s*\$\w+;})?}?~msi',
            'fast' => '~\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\]\s*=\s*\s*array\s*\(\s*base64_decode\s*\(~msi',
            'id'   => 'Bitrix',
        ],
        [
            'full' => '~\$\w{1,40}\s*=\s*(__FILE__|__LINE__);\s*\$\w{1,40}\s*=\s*(\d+);\s*eval(\s*\()+\$?\w+\s*\([\'"][^\'"]+[\'"](\s*\))+;\s*return\s*;\s*\?>(.+)~msi',
            'fast' => '~\$\w{1,40}\s*=\s*(__FILE__|__LINE__);\s*\$\w{1,40}\s*=\s*(\d+);\s*eval(\s*\()+\$?\w+\s*\([\'"][^\'"]+[\'"](\s*\))+;\s*return\s*;\s*\?>(.+)~msi',
            'id'   => 'B64inHTML',
        ],
        [
            'full' => '~<\?php\s+(?:/[*/].*?)?(?:\$[O0]*=__FILE__;\s*)?(\$[O0]*)=urldecode\(\'([%a-f0-9]+)\'\);(\$(GLOBALS\[\')?[O0]*(\'\])?=(\d+);)?(.*?)(\$(GLOBALS\[\')?[O0]*(\'\])?\.?=(\$(GLOBALS\[\')?[O0]*(\'\])?([{\[]\d+[}\]])?\.?)+;)+([^\?]+)\?\>[\s\w\~=/+\\\\^{`%|@[}]+~msi',
            'fast' => '~(\$[O0]*)=urldecode\(\'([%a-f0-9]+)\'\);(\$(GLOBALS\[\')?[O0]*(\'\])?=(\d+);)?(.*?)(\$(GLOBALS\[\')?[O0]*(\'\])?\.?=(\$(GLOBALS\[\')?[O0]*(\'\])?([{\[]\d+[}\]])?\.?)+;)+([^\?]+)\?\>[\s\w\~=/+\\\\^{`%|@[}]+~msi',
            'id'   => 'LockIt',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\"(\\\\142|\\\\x62)[0-9a-fx\\\\]+";\s*@?eval\s*\(\1\s*\([^\)]+\)+\s*;~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\"(\\\\142|\\\\x62)[0-9a-fx\\\\]+";\s*@?eval\s*\(\1\s*\(~msi',
            'id'   => 'FOPO',
        ],
        [
            'full' => '~\$_F=__FILE__;\$_X=\'([^\']+\');eval\([^\)]+\)+;~msi',
            'fast' => '~\$_F=__FILE__;\$_X=\'([^\']+\');eval\(~ms',
            'id'   => 'ByteRun',
        ],
        [
            'full' => '~(\$\w{1,40}=\'[^\']+\';\s*)+(\$[\w{1,40}]+)=(urldecode|base64_decode){0,1}\(?[\'"]([\w+%=-]+)[\'"]\)?;(\$[\w+]+=(\$(\w+\[\')?[O_0]*(\'\])?([\{\[]\d+[\}\]])?\.?)+;)+[^\?]+(\?\>[\w\~\=\/\+]+|.+\\\\x[^;]+;)~msi',
            'fast' => '~(\$\w{1,40}=\'[^\']+\';\s*)+(\$[\w{1,40}]+)=(urldecode|base64_decode){0,1}\(?[\'"]([\w+%=-]+)[\'"]\)?;(\$[\w+]+=(\$(\w+\[\')?[O_0]*(\'\])?([\{\[]\d+[\}\]])?\.?)+;)+[^\?]+(\?\>[\w\~\=\/\+]+|.+\\\\x[^;]+;)~msi',
            'id'   => 'Urldecode',
        ],
        [
            'full' => '~(\$[\w{1,40}]+)\s?=\s?(urldecode|base64_decode)\(?[\'"]([\w+%=-]+)[\'"]\);(\s*\$\w+\.?\s?=\s?((?:\$\w+\s*\.\s*)?\$\w+[{\[]\d+[}\]]\s*[\.;]?\s*)+)+((\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*\d,\s]+);|(eval\(\s?\$\w+\([\'"]([^\'"]+)[\'"][)\s]+;)|header\(\'[^\']+\'\);(?:\$\w+=\${[^}]+}\[[^\]]+\]\(\'.*?\'?;}?\'\);)+\${[^}]+}\[[^\]]+\]\(\);)~msi',
            'fast' => '~(\$[\w{1,40}]+)\s?=\s?(urldecode|base64_decode)\(?[\'"]([\w+%=-]+)[\'"]\);(\s*\$\w+\.?\s?=\s?((?:\$\w+\s*\.\s*)?\$\w+[{\[]\d+[}\]]\s*[\.;]?\s*)+)+((\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*\d,\s]+);|(eval\(\s?\$\w+\([\'"]([^\'"]+)[\'"][)\s]+;)|header\(\'[^\']+\'\);(?:\$\w+=\${[^}]+}\[[^\]]+\]\(\'.*?\'?;}?\'\);)+\${[^}]+}\[[^\]]+\]\(\);)~msi',
            'id'   => 'UrlDecode2',
        ],
        [
            'full' => '~\$\w{1,40}\s?=\s?[\'"]?[\d\w]+[\'"]?;((?:(\$\w{1,40})=[\'"]([^\'"]+)[\'"];\s*)+(\$[\w{1,40}]+)=urldecode\(\2\);)\w+\((?:\4[{\[]\d+[}\]]\.?)+\);(?:(?:(?:\$\w+\s?=\s?@\$_SERVER\[)?\4[{\[]\d+[}\]]\.?\]?)+;)+(?:.*?\4[\[{]\d+[}\]])+.*?;}\?>~msi',
            'fast' => '~\$\w{1,40}\s?=\s?[\'"]?[\d\w]+[\'"]?;((?:(\$\w{1,40})=[\'"]([^\'"]+)[\'"];\s*)+(\$[\w{1,40}]+)=urldecode\(\2\);)\w+\((?:\4[{\[]\d+[}\]]\.?)+\);(?:(?:(?:\$\w+\s?=\s?@\$_SERVER\[)?\4[{\[]\d+[}\]]\.?\]?)+;)+(?:.*?\4[\[{]\d+[}\]])+.*?;}\?>~msi',
            'id'   => 'UrlDecode3',
        ],
        [
            'full' => '~(?:@?session_start\(\);)?(?:@?(?:set_time_limit|error_reporting)\(\d+\);){1,2}(?:@\$\w{1,50}=\$_POST\[base64_decode\([\'"][^\'"]+[\'"]\)\];|if\(\w{1,50}\(\)\){foreach\(\$_POST\s{0,50}as\s{0,50}\$\w{1,50}=>\$\w{1,50}\))(?:.*?base64_decode\([\'"][^\'"]+[\'"]\)){1,200}\)\);return\s?\$\w{1,50};}~msi',
            'fast' => '~(?:@?session_start\(\);)?(?:@?(?:set_time_limit|error_reporting)\(\d+\);){1,2}(?:@\$\w{1,50}=\$_POST\[base64_decode\([\'"][^\'"]+[\'"]\)\];|if\(\w{1,50}\(\)\){foreach\(\$_POST\s{0,50}as\s{0,50}\$\w{1,50}=>\$\w{1,50}\))(?:.*?base64_decode\([\'"][^\'"]+[\'"]\)){1,200}\)\);return\s?\$\w{1,50};}~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~explode\(\"\*\*\*\",\s*\$\w+\);\s*eval\(eval\(\"return strrev\(base64_decode\([^\)]+\)+;~msi',
            'fast' => '~explode\(\"\*\*\*\",\s*\$\w+\);\s*eval\(eval\(\"return strrev\(base64_decode\(~msi',
            'id'   => 'cobra',
        ],
        [
            'full' => '~\$[O0]+=\(base64_decode\(strtr\(fread\(\$[O0]+,(\d+)\),\'([^\']+)\',\'([^\']+)\'\)\)\);eval\([^\)]+\)+;~msi',
            'fast' => '~\$[O0]+=\(base64_decode\(strtr\(fread\(\$[O0]+,(\d+)\),\'([^\']+)\',\'([^\']+)\'\)\)\);eval\(~msi',
            'id'   => 'strtrFread',
        ],
        [
            'full' => '~if\s*\(\!extension_loaded\(\'IonCube_loader\'\)\).+pack\(\"H\*\",\s*\$__ln\(\"/\[A-Z,\\\\r,\\\\n\]/\",\s*\"\",\s*substr\(\$__lp,\s*([0-9a-fx]+\-[0-9a-fx]+)\)\)\)[^\?]+\?\>\s*[0-9a-z\r\n]+~msi',
            'fast' => '~IonCube_loader~ms',
            'id'   => 'FakeIonCube',
        ],
        [
            'full' => '~(\$\w{1,40})="([\w\]\[\<\&\*\_+=/]{300,})";\$\w+=\$\w+\(\1,"([\w\]\[\<\&\*\_+=/]+)","([\w\]\[\<\&\*\_+=/]+)"\);~msi',
            'fast' => '~(\$\w{1,40})="([\w\]\[\<\&\*\_+=/]{300,})";\$\w+=\$\w+\(\1,"([\w\]\[\<\&\*\_+=/]+)","([\w\]\[\<\&\*\_+=/]+)"\);~msi',
            'id'   => 'strtrBase64',
        ],
        [
            'full' => '~\$\w+\s*=\s*array\((\'[^\']+\',?)+\);\s*.+?(\$_\w{1,40}\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\2\[[a-fx\d]+\])\(\);(.+?\2)+.+}~msi',
            'fast' => '~(\$_\w{1,40}\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\1\[[a-fx\d]+\])\(\);~msi',
            'id'   => 'explodeSubst',
        ],
        [
            'full' => '~(\$[\w{1,40}]+)\s*=\s*\'([\w+%=\-\#\\\\\'\*]+)\';(\$[\w+]+)\s*=\s*Array\(\);(\3\[\]\s*=\s*(\1\[\d+\]\.?)+;+)+(.+\3)[^}]+}~msi',
            'fast' => '~(\$[\w{1,40}]+)\s*=\s*\'([\w+%=\-\#\\\\\'\*]+)\';(\$[\w+]+)\s*=\s*Array\(\);(\3\[\]\s*=\s*(\1\[\d+\]\.?)+;+)+~msi',
            'id'   => 'subst',
        ],
        [
            'full' => '~if\(!function_exists\(\"(\w+)\"\)\){function \1\(.+?eval\(\1\(\"[^\"]+\"\)\);~msi',
            'fast' => '~if\(!function_exists\(\"(\w+)\"\)\){function \1\(.+?eval\(\1\(\"[^\"]+\"\)\);~msi',
            'id'   => 'decoder',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\"riny\(\"\.(\$\w+)\(\"base64_decode\"\);\s*(\$\w+)\s*=\s*\2\(\1\.\'\("([^"]+)"\)\);\'\);\s*\$\w+\(\3\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\"riny\(\"\.(\$\w+)\(\"base64_decode\"\);\s*(\$\w+)\s*=\s*\2\(\1\.\'\("([^"]+)"\)\);\'\);\s*\$\w+\(\3\);~msi',
            'id'   => 'GBZ',
        ],
        [
            'full' => '~\$\w+\s*=\s*\d+;\s*\$GLOBALS\[\'[^\']+\'\]\s*=\s*Array\(\);\s*global\s*\$\w+;(\$\w{1,40})\s*=\s*\$GLOBALS;\$\{"\\\\x[a-z0-9\\\\]+"\}\[(\'\w+\')\]\s*=\s*\"(([^\"\\\\]|\\\\.)*)\";\1\[(\1\[\2\]\[\d+\].?).+?exit\(\);\}+~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\$GLOBALS;\$\{"\\\\x[a-z0-9\\\\]+"\}\[(\'\w+\')\]\s*=\s*\"(([^\"\\\\]|\\\\.)*)\";\1\[(\1\[\2\]\[\d+\].?)~msi',
            'id'   => 'globalsArray',
        ],
        [
            'full' => '~(\${(["\w\\\\]+)}\[["\w\\\\]+\]=["\w\\\\]+;)+((\${\${(["\w\\\\]+)}\[["\w\\\\]+\]}).?=((urldecode\(["%\w]+\);)|(\${\${["\w\\\\]+}\[["\w\\\\]+\]}{\d+}.?)+;))+eval\(\${\${["\w\\\\]+}\[["\w\\\\]+\]}\(["\w+=]+\)\);~msi',
            'fast' => '~(\${(["\w\\\\]+)}\[["\w\\\\]+\]=["\w\\\\]+;)+((\${\${(["\w\\\\]+)}\[["\w\\\\]+\]}).?=((urldecode\(["%\w]+\);)|(\${\${["\w\\\\]+}\[["\w\\\\]+\]}{\d+}.?)+;))+eval\(\${\${["\w\\\\]+}\[["\w\\\\]+\]}\(["\w+=]+\)\);~msi',
            'id'   => 'xbrangwolf',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\'(\\\\.|[^\']){0,100}\';\s*\$\w+\s*=\s*\'(\\\\.|[^\']){0,100}\'\^\1;[^)]+\)+;\s*\$\w+\(\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\'(\\\\.|[^\']){0,100}\';\s*\$\w+\s*=\s*\'(\\\\.|[^\']){0,100}\'\^\1;~msi',
            'id'   => 'xoredVar',
        ],
        [
            'full' => '~\$\w{1,40}=\'[^\']{0,100}(?:\'\^\')?[^\']*\';(?:\$\w{1,40}=\w{1,3};)?(?:\$\w{1,40}=\'[^\']+(?:\'\^\')?[^\']*\';)+\w{1,40};(?:.{0,6000}?)if\(\$\w{1,40}==\$\w{1,40}\(\$\w{1,40}\)\){(?:.{0,6000}?)\w{1,40};\s?\$\w{1,40}\(\'[^\']{0,100}\',\'[^\']{0,100}\'\);\'[^\']{0,100}\';~msi',
            'fast' => '~\$\w{1,40}=\'[^\']{0,100}(?:\'\^\')?[^\']*\';(?:\$\w{1,40}=\w{1,3};)?(?:\$\w{1,40}=\'[^\']+(?:\'\^\')?[^\']*\';)+\w{1,40};(?:.{0,6000}?)if\(\$\w{1,40}==\$\w{1,40}\(\$\w{1,40}\)\)~msi',
            'id'   => 'xoredVar',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\'([^\']*)\';\s*(\$\w{1,40})\s*=\s*explode\s*\((chr\s*\(\s*\(\d+\-\d+\)\)),substr\s*\(\1,\s*\((\d+\-\d+)\),\s*\(\s*(\d+\-\d+)\)\)\);\s*(\$\w{1,40})\s*=\s*\3\[\d+\]\s*\(\3\[\s*\(\d+\-\d+\)\]\);\s*(\$\w{1,40})\s*=\s*\3\[\d+\]\s*\(\3\[\s*\(\d+\-\d+\)\]\);\s*if\s*\(!function_exists\s*\(\'([^\']*)\'\)\)\s*\{\s*function\s*\9\s*\(.+\1\s*=\s*\$\w+[+\-\*]\d+;~msi',
            'fast' => '~(\$\w{1,40})\s=\s\'([^\']*)\';\s(\$\w{1,40})=explode\((chr\(\(\d+\-\d+\)\)),substr\(\1,\((\d+\-\d+)\),\((\d+\-\d+)\)\)\);\s(\$\w{1,40})\s=\s\3\[\d+\]\(\3\[\(\d+\-\d+\)\]\);\s(\$\w{1,40})\s=\s\3\[\d+\]\(\3\[\(\d+\-\d+\)\]\);\sif\s\(!function_exists\(\'([^\']*)\'\)\)\s\{\sfunction\s*\9\(~msi',
            'id'   => 'arrayOffsets',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"](.*?)[\'"];\s?(\$\w+)\s?=\s?explode\(chr\(+(\d+\s?[-+]\s?\d+)\)+,\s?[\'"]((?:\d+,?)+)[\'"]\);\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?if\s?\(!function_exists\([\'"](\w+)[\'"]\)\)\s?{\s?function\s?\9\((\$\w+),\s?(\$\w+)\)\s?{\s?(\$\w+)\s?=\s?NULL;\s?for\s?\((\$\w+)\s?=\s0;\s?\13\s?<\s?\(sizeof\(\10\)\s?/\s?(\d+)\);\s?\13\+\+\)\s?{\s?\12\s?\.=\s?substr\(\11,\s?\10\[\(\13\s?\*\s?(\d+)\)\],\s?\10\[\(\13\s?\*\s?(\d+)\)\s?\+\s?(\d+)\]\);\s?}\s?return\s?\12;\s?}\s;\s?}\s?(\$\w+)\s?=\s?[\'"](.*?eval\(str_replace\(chr\(\(+(\d+\s?[-+]\s?\d+)\)\),\s?chr\(\(+(\d+\s?[-+]\s?\d+)\)\),\s?\9\(\3,\1\)\)\);.*?)[\'"];\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?\22\(\6,\s?\18,\s?NULL\);\s?\22\s?=\s?\18;\s?\22\s?=\s?\(+(\d+\s?[-+]\s?\d+)\);\s?\$\w+\s?=\s?\$\w+\s?\-\s?\d+;~msi',
            'fast' => '~(\$\w+)\s?=\s?[\'"](.*?)[\'"];\s?(\$\w+)\s?=\s?explode\(chr\(+(\d+\s?[-+]\s?\d+)\)+,\s?[\'"]((?:\d+,?)+)[\'"]\);\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?if\s?\(!function_exists\([\'"](\w+)[\'"]\)\)\s?{\s?function\s?\9\((\$\w+),\s?(\$\w+)\)\s?{\s?(\$\w+)\s?=\s?NULL;\s?for\s?\((\$\w+)\s?=\s0;\s?\13\s?<\s?\(sizeof\(\10\)\s?/\s?(\d+)\);\s?\13\+\+\)\s?{\s?\12\s?\.=\s?substr\(\11,\s?\10\[\(\13\s?\*\s?(\d+)\)\],\s?\10\[\(\13\s?\*\s?(\d+)\)\s?\+\s?(\d+)\]\);\s?}\s?return\s?\12;\s?}\s;\s?}\s?(\$\w+)\s?=\s?[\'"](.*?eval\(str_replace\(chr\(\(+(\d+\s?[-+]\s?\d+)\)\),\s?chr\(\(+(\d+\s?[-+]\s?\d+)\)\),\s?\9\(\3,\1\)\)\);.*?)[\'"];\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?\22\(\6,\s?\18,\s?NULL\);\s?\22\s?=\s?\18;\s?\22\s?=\s?\(+(\d+\s?[-+]\s?\d+)\);\s?\$\w+\s?=\s?\$\w+\s?\-\s?\d+;~msi',
            'id'   => 'arrayOffsetsEval',
        ],
        [
            'full' => '~(\$\w{1,50}\s*=\s*array\((\'\d+\',?)+\);)+\$\w{1,40}=\"([^\"]+)\";if\s*\(!function_exists\(\"\w{1,50}\"\)\)\s*\{\s*function\s*[^\}]+\}\s*return\s*\$\w+;\}[^}]+}~msi',
            'fast' => '~(\$\w{1,50}=\s*array\((\'\d+\',?)+\);)+\$\w{1,40}=\"[^\"]+\";if\s*\(!function_exists\(\"\w{1,50}\"\)\)\{\s*function ~msi',
            'id'   => 'obfB64',
        ],
        [
            'full' => '~if\(\!function_exists\(\'findsysfolder\'\)\){function findsysfolder\(\$fld\).+\$REXISTHEDOG4FBI=\'([^\']+)\';\$\w+=\'[^\']+\';\s*eval\(\w+\(\'([^\']+)\',\$REXISTHEDOG4FBI\)\);~msi',
            'fast' => '~if\(!function_exists\(\'findsysfolder\'\)\){function findsysfolder\(\$fld\)\{\$fld1=dirname\(\$fld\);\$fld=\$fld1\.\'/scopbin\';clearstatcache\(\);if\(!is_dir\(\$fld\)\)return findsysfolder\(\$fld1\);else return \$fld;\}\}require_once\(findsysfolder\(__FILE__\)\.\'/911006\.php\'\);~msi',
            'id'   => 'sourceCop',
        ],
        [
            'full' => '~function\s*(\w{1,40})\s*\(\s*(\$\w{1,40})\s*,\s*(\$\w{1,40})\s*\)\s*\{\s*(\$\w{1,40})\s*=\s*str_rot13\s*\(\s*gzinflate\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(\s*[\'"][^\'"]*[\'"]\s*\)\s*\)\s*\)\s*\)\s*;\s*(if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*(\$\w{1,40})\s*=(\$\w+[\{\[]\d+[\}\]]\.?)+;return\s*(\$\w+)\(\3\);\s*\}\s*else\s*)+\s*if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*return\s*eval\(\3\);\s*\}\s*\};\s*(\$\w{1,40})\s*=\s*[\'"][^\'"]*[\'"];(\s*\9\([\'"][^\'"]*[\'"],)+\s*[\'"][^\'"]*[\'"]\s*\)+;~msi',
            'fast' => '~function\s*(\w{1,40})\s*\(\s*(\$\w{1,40})\s*,\s*(\$\w{1,40})\s*\)\s*\{\s*(\$\w{1,40})\s*=\s*str_rot13\s*\(\s*gzinflate\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(\s*[\'"][^\'"]*[\'"]\s*\)\s*\)\s*\)\s*\)\s*;\s*(if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*(\$\w{1,40})\s*=(\$\w+[\{\[]\d+[\}\]]\.?)+;return\s*(\$\w+)\(\3\);\s*\}\s*else\s*)+\s*if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*return\s*eval\(\3\);\s*\}\s*\};\s*(\$\w{1,40})\s*=\s*[\'"][^\'"]*[\'"];(\s*\9\([\'"][^\'"]*[\'"],)+\s*[\'"][^\'"]*[\'"]\s*\)+;~msi',
            'id'   => 'webshellObf',

        ],
        [
            'full' => '~(\$\w{1,40})=\'([^\'\\\\]|.*?)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';\s*(\$\w{1,40})\(\6,\$\w{1,40}\.\"([^\"]+)\"\.\$\w{1,40}\.\4\);~msi',
            'fast' => '~(\$\w{1,40})=\'([^\\\\\']|.*?)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';~msi',
            'id'   => 'substCreateFunc',
        ],
        [
            'full' => '~@error_reporting\(0\);\s*@ini_set\(\'error_log\',NULL\);\s*@ini_set\(\'log_errors\',0\);\s*@ini_set\(\'display_errors\',\s*0\);\s*@(\$\w+)="[create_function"\.]+;\s*(\$\w+)=\1\("([^"]+)","[eval\."]+\(\'\?>\'\.[base64_decode"\.]+\(\3\)\);"\);\s*\2\("([^"]+)"\);exit;~msi',
            'fast' => '~@error_reporting\(0\);\s*@ini_set\(\'error_log\',NULL\);\s*@ini_set\(\'log_errors\',0\);\s*@ini_set\(\'display_errors\',\s*0\);\s*@(\$\w+)="[create_function"\.]+;\s*(\$\w+)=\1\("([^"]+)","[eval\."]+\(\'\?>\'\.[base64_decode"\.]+\(\3\)\);"\);\s*\2\("([^"]+)"\);exit;~msi',
            'id'   => 'Obf_20200507_2',
        ],
        [
            'full' => '~\$\w+=([create_function"\'.]+);\s?\$\w+=\$\w+\([\'"]\\\\?\$\w+[\'"],((?:[\'"][eval]{0,4}[\'"]\.?)+)\.([\'"](\([\'"]\?>[\'"]\.)\w+[\'"]\.[^)\\\\]+)\\\\?\$\w+\)+;[\'"]\);\s?\$\w+\([\'"]([\w\+=\\\\\'"%/]+)[\'"]\);~msi',
            'fast' => '~\$\w+=([create_function"\'.]+);\s?\$\w+=\$\w+\([\'"]\\\\?\$\w+[\'"],((?:[\'"][eval]{0,4}[\'"]\.?)+)\.([\'"](\([\'"]\?>[\'"]\.)\w+[\'"]\.[^)\\\\]+)\\\\?\$\w+\)+;[\'"]\);\s?\$\w+\([\'"]([\w\+=\\\\\'"%/]+)[\'"]\);~msi',
            'id'   => 'createFunc',
        ],
        [
            'full' => '~(?(DEFINE)(?\'foreach\'(?:/\*\w+\*/)?\s*foreach\(\[[\d,]+\]\s*as\s*\$\w+\)\s*\{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\];\s*\}\s*(?:/\*\w+\*/)?\s*))(\$\w+)\s*=\s*"([^"]+)";\s*\$\w+\s*=\s*"";(?P>foreach)if\(isset\(\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\]\)+\{\s*\$\w+\s*=\s*\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\];(?:\s*\$\w+\s*=\s*"";\s*)+(?P>foreach)+\$\w+\s*=\s*\$\w+\([create_function\'\.]+\);\s*\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\)\);\s*\$\w+\(\);\s*(?:exit\(\);)?\s*}~mis',
            'fast' => '~(?(DEFINE)(?\'foreach\'(?:/\*\w+\*/)?\s*foreach\(\[[\d,]+\]\s*as\s*\$\w+\)\s*\{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\];\s*\}\s*(?:/\*\w+\*/)?\s*))(\$\w+)\s*=\s*"([^"]+)";\s*\$\w+\s*=\s*"";(?P>foreach)if\(isset\(\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\]\)+\{\s*\$\w+\s*=\s*\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\];(?:\s*\$\w+\s*=\s*"";\s*)+(?P>foreach)+\$\w+\s*=\s*\$\w+\([create_function\'\.]+\);\s*\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\)\);\s*\$\w+\(\);~mis',
            'id'   => 'forEach',
        ],
        [
            'full' => '~\$\w+\s*=\s*base64_decode\s*\([\'"][^\'"]+[\'"]\);\s*if\s*\(!function_exists\s*\("rotencode"\)\).{0,1000}eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"][^"\']+[\'"]\)+;~msi',
            'fast' => '~\$\w+\s*=\s*base64_decode\s*\([\'"][^\'"]+[\'"]\);\s*if\s*\(!function_exists\s*\("rotencode"\)\).{0,1000}eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"][^"\']+[\'"]\)+;~msi',
            'id'   => 'PHPMyLicense',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*file\(__FILE__\);\s*if\(!function_exists\(\"([^\"]*)\"\)\)\{function\s*\2\((\$\w{1,40}),(\$\w{1,40})=\d+\)\{(\$\w{1,40})=implode\(\"[^\"]*\",\3\);(\$\w{1,40})=array\((\d+),(\d+),(\d+)\);if\(\4==0\)\s*(\$\w{1,40})=substr\(\5,\6\[\d+\],\6\[\d+\]\);elseif\(\4==1\)\s*\10=substr\(\5,\6\[\d+\]\+\6\[\d+\],\6\[\d+\]\);else\s*\10=trim\(substr\(\5,\6\[\d+\]\+\6\[\d+\]\+\6\[\d+\]\)\);return\s*\(\10\);\}\}\s*eval\(\w{1,40}\(\2\(\1\s*,\s*2\)\s*,\s*\2\(\1\s*,\s*1\)\)\);\s*__halt_compiler\(\);\s*[\w\+\=/]+~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*file\(__FILE__\);\s*if\(!function_exists\(\"([^\"]*)\"\)\)\{function\s*\2\((\$\w{1,40}),(\$\w{1,40})=\d+\)\{(\$\w{1,40})=implode\(\"[^\"]*\",\3\);(\$\w{1,40})=array\((\d+),(\d+),(\d+)\);if\(\4==0\)\s*(\$\w{1,40})=substr\(\5,\6\[\d+\],\6\[\d+\]\);elseif\(\4==1\)\s*\10=substr\(\5,\6\[\d+\]\+\6\[\d+\],\6\[\d+\]\);else\s*\10=trim\(substr\(\5,\6\[\d+\]\+\6\[\d+\]\+\6\[\d+\]\)\);return\s*\(\10\);\}\}\s*eval\(\w{1,40}\(\2\(\1\s*,\s*2\)\s*,\s*\2\(\1\s*,\s*1\)\)\);\s*__halt_compiler\(\);~msi',
            'id'   => 'zeura',
        ],
        [
            'full' => '~<\?php\s*(eval(?:\(\w+)+\((substr\(file_get_contents\(__FILE__\),\s?(\d+)\))\)+;)\s*__halt_compiler\(\);\s*[\w+/]+~msi',
            'fast' => '~<\?php\s*(eval(?:\(\w+)+\((substr\(file_get_contents\(__FILE__\),\s?(\d+)\))\)+;)\s*__halt_compiler\(\);\s*[\w+/]+~msi',
            'id' => 'evalFileContentOffset',
        ],
        [
            'full' => '~(\$\w+)=base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.?)+)\);(\$\w+)=base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.?)+)\);(\$\w+)=base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.?)+)\);(\1\((\(-(\d+)-\(-\9\)\))\);@set_time_limit\((\(-(\d+)-\(-\11\)\))\);)eval\(base64_decode\(((?:(?|[\'"]\d+[\'"]|chr\(\d+\))\.?)+)\)\.gzinflate\(str_rot13\(\3\(\5\){4};~msi',
            'fast' => '~(\$\w+)=base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.?)+)\);(\$\w+)=base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.?)+)\);(\$\w+)=base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.?)+)\);(\1\((\(-(\d+)-\(-\9\)\))\);@set_time_limit\((\(-(\d+)-\(-\11\)\))\);)eval\(base64_decode\(((?:(?|[\'"]\d+[\'"]|chr\(\d+\))\.?)+)\)\.gzinflate\(str_rot13\(\3\(\5\){4};~msi',
            'id'   => 'evalConcatedVars',
        ],
        [
            'full' => '~(\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\]="[\w\\\\]+";(\$\w+="\w+";)?){5,}.+\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\].+}+~msi',
            'fast' => '~(\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\]="[\w\\\\]+";(\$\w+="\w+";)?){5,}.+\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\].+}+~msi',
            'id'   => 'Obf_20200618_1',
        ],
        [
            'full' => '~(\$\w+\s?=\s?(\w+)\(\'\d+\'\);\s*)+\$\w+\s?=\s?new\s?\$\w+\(\2\(\'(\d+)\'\)+;\s?error_reporting\(0\);\s?eval\(\$\w+\(\$\w+->\$\w+\("([^"]+)"\)+;.+?function \2.+?return\s\$\w+;\s}~msi',
            'fast' => '~(\$\w+\s?=\s?(\w+)\(\'\d+\'\);\s*)+\$\w+\s?=\s?new\s?\$\w+\(\2\(\'(\d+)\'\)+;\s?error_reporting\(0\);\s?eval\(\$\w+\(\$\w+->\$\w+\("([^"]+)"\)+;.+?function \2.+?return\s\$\w+;\s}~msi',
            'id'   => 'aanKFM',
        ],
        [
            'full' => '~error_reporting\(\d\);@?set_time_limit\(\d\);(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]{0,100})[\'"];(\$\w{1,50}\s?=\s?[\'"][^\'"]{0,500}[\'"];)eval\(gzinflate\(base64_decode\(\3\)\)\);rebirth\(\);eval\(gzinflate\(base64_decode\(hate\(\1,\5\){4};~msi',
            'fast' => '~error_reporting\(\d\);@?set_time_limit\(\d\);(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]{0,100})[\'"];(\$\w{1,50}\s?=\s?[\'"][^\'"]{0,500}[\'"];)eval\(gzinflate\(base64_decode\(\$\w{1,50}\)\)\);rebirth\(\);eval\(gzinflate\(base64_decode\(hate\(\$\w{1,50},\$\w{1,50}\){4};~msi',
            'id' => 'evalLoveHateFuncs',
        ],
        [
            'full' => '~function\s?(\w+)\(\){\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?\2\s?=\s?str_rot13\(\2\);\s?(\w+)\(\2\);\s?}\s?function\s?\4\((\$\w+)\){\s?(?:global\s?\$\w+;\s?)?\5\s?=\s?pack\([\'"]H\*[\'"],\5\);\s?(\$\w+)\s?=\s?[\'"]{2};\s?eval\(((?:\6|\5)\.?)+\);\s?}\s?\1\(\);~msi',
            'fast' => '~function\s?(\w+)\(\){\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?\2\s?=\s?str_rot13\(\2\);\s?(\w+)\(\2\);\s?}\s?function\s?\4\((\$\w+)\){\s?(?:global\s?\$\w+;\s?)?\5\s?=\s?pack\([\'"]H\*[\'"],\5\);\s?(\$\w+)\s?=\s?[\'"]{2};\s?eval\(((?:\6|\5)\.?)+\);\s?}\s?\1\(\);~msi',
            'id'   => 'evalPackStrrot',
        ],
        [
            'full' => '~error_reporting\(\d\);(?:\$\w+=[\'"]\w+[\'"];)?ini_set\([\'"]\w+[\'"],\d\);eval\(base64_decode\([\'"]([\w\+=]+)[\'"]\)\);\$\w+=str_split\([\'"]([}\w|,[=\'\.;\]&]+)[\'"]\);\$\w+=[\'"]{2};foreach\(\$\w+\s{0,50}as\s{0,50}\$\w+\){foreach\((\$\w+)\s{0,50}as\s{0,50}\$\w+\s{0,50}=>\s{0,50}\$\w+\){(?:\$\w+=[\'"]\w+[\'"];\$\w+=[\'"]\w+[\'"];)?if\(\$\w+\s{0,50}==\s{0,50}\(string\)\$\w+\){(?:\$\w+=[\'"]\w+[\'"];\$\w+=[\'"]\w+[\'"];)?\$\w+\s{0,50}\.=\s{0,50}\$\w+;break;}}}eval\([\'"]\?>[\'"]\.gzinflate\(base64_decode\(\$\w+\)\)\);~msi',
            'fast' => '~error_reporting\(\d\);(?:\$\w+=[\'"]\w+[\'"];)?ini_set\([\'"]\w+[\'"],\d\);eval\(base64_decode\([\'"]([\w\+=]+)[\'"]\)\);\$\w+=str_split\([\'"]([}\w|,[=\'\.;\]&]+)[\'"]\);\$\w+=[\'"]{2};foreach\(\$\w+\s{0,50}as\s{0,50}\$\w+\){foreach\((\$\w+)\s{0,50}as\s{0,50}\$\w+\s{0,50}=>\s{0,50}\$\w+\){(?:\$\w+=[\'"]\w+[\'"];\$\w+=[\'"]\w+[\'"];)?if\(\$\w+\s{0,50}==\s{0,50}\(string\)\$\w+\){(?:\$\w+=[\'"]\w+[\'"];\$\w+=[\'"]\w+[\'"];)?\$\w+\s{0,50}\.=\s{0,50}\$\w+;break;}}}eval\([\'"]\?>[\'"]\.gzinflate\(base64_decode\(\$\w+\)\)\);~msi',
            'id'   => 'evalArrayVar',
        ],
        [
            'full' => '~((\$\w+)\s*\.=\s*"[^"]+";\s*)+eval\((\$\w+\s*\.?\s*)+\)~msi',
            'fast' => '~((\$\w+)\s*\.=\s*"[^"]+";\s*)+eval\((\$\w+\s*\.?\s*)+\)~msi',
            'id'   => 'evalVarConcat',
        ],
        [
            'full' => '~((\$[^\s=]+)\s*=\s*[\'"]([^\'"]+)[\'"];\s*)+\s*.{0,10}?(?:error_reporting\(\d\);|@set_time_limit\(\d\);|@){0,2}eval\s*\(\s*([\'"?>.\s]+)?\(?(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()+(\({0,1}[\s"\']?(\$[^\s=\'")]+)?(?:str_replace\((?:.+?,){3}\2?)?[\s"\']?\){0,1})\)+;~msi',
            'fast' => '~((\$[^\s=]+)\s*=\s*[\'"]([^\'"]+)[\'"];\s*)+\s*.{0,10}?(?:error_reporting\(\d\);|@set_time_limit\(\d\);|@){0,2}eval\s*\(\s*([\'"?>.\s]+)?\(?(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()+(\({0,1}[\s"\']?(\$[^\s=\'")]+)?(?:str_replace\((?:.+?,){3}\2?)?[\s"\']?\){0,1})\)+;~msi',
            'id'   => 'evalVar',
        ],
        [
            'full' => '~((?:(?:\$\w+=[\'"]\\\\[^\'"]+)[\'"];)+)@(eval\((?:\$\w+\()+[\'"]([^\'"]+)[\'"]\)+;)~msi',
            'fast' => '~((?:(?:\$\w+=[\'"]\\\\[^\'"]+)[\'"];)+)@(eval\((?:\$\w+\()+[\'"]([^\'"]+)[\'"]\)+;)~msi',
            'id'   => 'evalVarSlashed',
        ],
        [
            'full' => '~function\s*(\w{1,40})\((\$\w{1,40})\)\{(\$\w{1,40})=\'base64_decode\';(\$\w{1,40})=\'gzinflate\';return\s*\4\(\3\(\2\)\);\}\$\w{1,40}=\'[^\']*\';\$\w{1,40}=\'[^\']*\';eval\(\1\(\'([^\']*)\'\)\);~msi',
            'fast' => '~function\s*(\w{1,40})\((\$\w{1,40})\)\{(\$\w{1,40})=\'base64_decode\';(\$\w{1,40})=\'gzinflate\';return\s*\4\(\3\(\2\)\);\}\$\w{1,40}=\'[^\']*\';\$\w{1,40}=\'[^\']*\';eval\(\1\(\'([^\']*)\'\)\);~msi',
            'id'   => 'evalFunc',
        ],
        [
            'full' => '~function\s*(\w{1,40})\s*\((\$\w{1,40})\)\s*\{\s*(\$\w{1,40})\s*=\s*"\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36\\\\x34\\\\x5f\\\\x64\\\\x65\\\\x63\\\\x6f\\\\x64\\\\x65";\s*(\$\w{1,40})\s*=\s*"\\\\x67\\\\x7a\\\\x69\\\\x6e\\\\x66\\\\x6c\\\\x61\\\\x74\\\\x65";\s*return\s*\4\s*\(\3\s*\(\2\)\);\s*\}\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*eval\s*\(\1\s*\(\"([^\"]*)\"\)\);~msi',
            'fast' => '~function\s*(\w{1,40})\s*\((\$\w{1,40})\)\s*\{\s*(\$\w{1,40})\s*=\s*"\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36\\\\x34\\\\x5f\\\\x64\\\\x65\\\\x63\\\\x6f\\\\x64\\\\x65";\s*(\$\w{1,40})\s*=\s*"\\\\x67\\\\x7a\\\\x69\\\\x6e\\\\x66\\\\x6c\\\\x61\\\\x74\\\\x65";\s*return\s*\4\s*\(\3\s*\(\2\)\);\s*\}\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*eval\s*\(\1\s*\(\"([^\"]*)\"\)\);~msi',
            'id'   => 'evalFunc',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"]@?(([\w."]+\()+[\'"]([\w\/+]+)[\'"])\)+;[\'"]\s?;\s?(\$\w+)\s?=\s?([\w@."]+)\s?;\s?@?(\$\w+)\s?=\s\5\([\'"]+,\s?"\1;"\s?\);\7\([\'"]{2}\);~msi',
            'fast' => '~(\$\w+)\s?=\s?[\'"]@?(([\w."]+\()+[\'"]([\w\/+]+)[\'"])\)+;[\'"]\s?;\s?(\$\w+)\s?=\s?([\w@."]+)\s?;\s?@?(\$\w+)\s?=\s\5\([\'"]+,\s?"\1;"\s?\);\7\([\'"]{2}\);~msi',
            'id'   => 'evalConcatFunc',
        ],
        [
            'full' => '~function\sT_\((\$\w+)\)\s{\s(\$\w+)\s=\s256;\s(\$w2)\s=\s8;\s(\$\w+)\s=\sarray\(\);\s(\$\w+)\s=\s0;\s(\$\w+)\s=\s0;\sfor\s\((\$\w+)\s=\s0;\s\7\s<\sstrlen\(\1\);\s\7\+\+\)\s{\s\5\s=\s\(\5\s<<\s8\)\s\+\sord\(\1\[\7\]\);\s\6\s\+=\s8;\sif\s\(\6\s>=\s\3\)\s{\s\6\s-=\s\3;\s(\$\w+)\[\]\s=\s\5\s>>\s\6;\s\5\s&=\s\(1\s<<\s\6\)\s-\s1;\s\2\+\+;\sif\s\(\2\s>>\s\3\)\s{\s\3\+\+;\s}\s}\s}\s(\$\w+)\s=\srange\("\\\\x0",\s"\\\\377"\);\s(\$\w+)\s=\s\'\';\sforeach\s\(\4\sas\s\7\s=>\s(\$\w+)\)\s{\sif\s\(!isset\(\9\[\11\]\)\)\s{\s(\$\w+)\s=\s(\$\w+)\s\.\s\13\[0\];\s}\selse\s{\s\12\s=\s\9\[\11\];\s}\s\10\s\.=\s\12;\sif\s\(\7\)\s{\s\9\[\]\s=\s\13\s\.\s\12\[0\];\s}\s\13\s=\s\12;\s}\sreturn\s\10;\s}\s(\$_\w+)="[\w\\\\]+";eval\(T_\(\14\("(.*)"\)\)\);~mis',
            'fast' => '~function\sT_\((\$\w+)\)\s{\s(\$\w+)\s=\s256;\s(\$w2)\s=\s8;\s(\$\w+)\s=\sarray\(\);\s(\$\w+)\s=\s0;\s(\$\w+)\s=\s0;\sfor\s\((\$\w+)\s=\s0;\s\7\s<\sstrlen\(\1\);\s\7\+\+\)\s{\s\5\s=\s\(\5\s<<\s8\)\s\+\sord\(\1\[\7\]\);\s\6\s\+=\s8;\sif\s\(\6\s>=\s\3\)\s{\s\6\s-=\s\3;\s(\$\w+)\[\]\s=\s\5\s>>\s\6;\s\5\s&=\s\(1\s<<\s\6\)\s-\s1;\s\2\+\+;\sif\s\(\2\s>>\s\3\)\s{\s\3\+\+;\s}\s}\s}\s(\$\w+)\s=\srange\("\\\\x0",\s"\\\\377"\);\s(\$\w+)\s=\s\'\';\sforeach\s\(\4\sas\s\7\s=>\s(\$\w+)\)\s{\sif\s\(!isset\(\9\[\11\]\)\)\s{\s(\$\w+)\s=\s(\$\w+)\s\.\s\13\[0\];\s}\selse\s{\s\12\s=\s\9\[\11\];\s}\s\10\s\.=\s\12;\sif\s\(\7\)\s{\s\9\[\]\s=\s\13\s\.\s\12\[0\];\s}\s\13\s=\s\12;\s}\sreturn\s\10;\s}\s(\$_\w+)="[\w\\\\]+";eval\(T_\(\14\("(.*)"\)\)\);~mis',
            'id'   => 'evalFuncFunc',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?bin2hex\(\5\);\s?(\$\w+)\s?=\s?hex2bin\(\7\);\s*(?:eval\()+[\'"]\?>[\'"]\.\1\(\3\(\8\)+;~msi',
            'fast' => '~(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?bin2hex\(\5\);\s?(\$\w+)\s?=\s?hex2bin\(\7\);\s*(?:eval\()+[\'"]\?>[\'"]\.\1\(\3\(\8\)+;~msi',
            'id'   => 'evalBinHexVar',
        ],
        [
            'full' => '~((?:\${"(?:\w{0,10}?\\\\x\w{1,10}){1,100}"}\["\w{0,10}?(?:\\\\x\w{1,10}){1,100}"\]="(?:\\\\x\w{1,10}){1,100}";)+.*?define.*?)\${\$\w{1,50}}=array\(array\(((?:"[^"]{1,500}",?){1,1000})\)\);(.*create_function\(.*?array_walk\(\${\${"(?:\\\\x\w{1,10}){1,10}"}\["(?:\\\\x\w{1,10}){1,10}"\]},\${\${"(?:\\\\x\w{1,10}){1,10}"}\["(?:\w?\\\\x\w{1,10}){1,10}"\]}\);)~msi',
            'fast' => '~((?:\${"(?:\w{0,10}?\\\\x\w{1,10}){1,100}"}\["\w{0,10}?(?:\\\\x\w{1,10}){1,100}"\]="(?:\\\\x\w{1,10}){1,100}";)+.*?define.*?)\${\$\w{1,50}}=array\(array\(((?:"[^"]{1,500}",?){1,1000})\)\);(.*create_function\(.*?array_walk\(\${\${"(?:\\\\x\w{1,10}){1,10}"}\["(?:\\\\x\w{1,10}){1,10}"\]},\${\${"(?:\\\\x\w{1,10}){1,10}"}\["(?:\w?\\\\x\w{1,10}){1,10}"\]}\);)~msi',
            'id' => 'evalArrayWalkFunc'
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s*eval\([\'"]\?>[\'"]\s?\.\s?base64_decode\(strtr\(substr\(\1\s?,(\d+)\*(\d+)\)\s?,\s?substr\(\1\s?,(\d+)\s?,\s?(\d+)\)\s?,\s*substr\(\s?\1\s?,\s?(\d+)\s?,\s?(\d+)(?:\s?\))+;~msi',
            'fast' => '~(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s*eval\([\'"]\?>[\'"]\s?\.\s?base64_decode\(strtr\(substr\(\1\s?,(\d+)\*(\d+)\)\s?,\s?substr\(\1\s?,(\d+)\s?,\s?(\d+)\)\s?,\s*substr\(\s?\1\s?,\s?(\d+)\s?,\s?(\d+)(?:\s?\))+;~msi',
            'id' => 'evalSubstrVal'
        ],
        [
            'full' => '~(preg_replace\(["\']/\.\*?/[^"\']+["\']\s*,\s*)[^\),]+(?:[\)\\\\0-5]+;[\'"])?(,\s*["\'][^"\']*["\'])\)+;~msi',
            'fast' => '~(preg_replace\(["\']/\.\*?/[^"\']+["\']\s*,\s*)[^\),]+(?:[\)\\\\0-5]+;[\'"])?(,\s*["\'][^"\']*["\'])\)+;~msi',
            'id'   => 'eval',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*[\'"]([^\'"]*)[\'"]\s*;\s*(\$\w{1,40}\s*=\s*(strtolower|strtoupper)\s*\((\s*\1[\[\{]\s*\d+\s*[\]\}]\s*\.?\s*)+\);\s*)+\s*if\s*\(\s*isset\s*\(\s*\$\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*\{\s*eval\s*\(\s*\$\w{1,40}\s*\(\s*\$\s*\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*;\s*\}\s*~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*[\'"]([^\'"]*)[\'"]\s*;\s*(\$\w{1,40}\s*=\s*(strtolower|strtoupper)\s*\((\s*\1[\[\{]\s*\d+\s*[\]\}]\s*\.?\s*)+\);\s*)+\s*if\s*\(\s*isset\s*\(\s*\$\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*\{\s*eval\s*\(\s*\$\w{1,40}\s*\(\s*\$\s*\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*;\s*\}\s*~msi',
            'id'   => 'evalInject',

        ],
        [
            'full' => '~((\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));\s*)+\$\w+\s*=\s*\$\w+\(\'\',(\s*\$\w+\s*\(\s*)+\'[^\']+\'\)+;\s*\$\w+\(\);~msi',
            'fast' => '~((\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));\s*)+\$\w+\s*=\s*\$\w+\(\'\',(\s*\$\w+\s*\(\s*)+\'[^\']+\'\)+;\s*\$\w+\(\);~msi',
            'id'   => 'createFuncConcat',

        ],
        [
            'full' => '~(\$\w+)\s*=\s*base64_decode\("([^"]+)"\);(\1\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);)+\1=base64_decode\(\1\);eval\(\1\);~msi',
            'fast' => '~(\$\w+)\s*=\s*base64_decode\("([^"]+)"\);(\1\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);)+\1=base64_decode\(\1\);eval\(\1\);~msi',
            'id'   => 'evalEregReplace',

        ],
        [
            'full' => '~((\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));\s*)+\s*@?eval\(\$[^)]+\)+;~msi',
            'fast' => '~((\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));\s*)+\s*@?eval\(\$[^)]+\)+;~msi',
            'id'   => 'evalWrapVar',

        ],
        [
            'full' => '~\$\{"(.{1,20}?(\\\\x[0-9a-f]{2})+)+.?";@?eval\s*\(\s*([\'"?>.]+)?@?\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+\(?\$\{\$\{"[^\)]+\)+;~msi',
            'fast' => '~\$\{"(.{1,20}?(\\\\x[0-9a-f]{2})+)+.?";@?eval\s*\(\s*([\'"?>.]+)?@?\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+\(?\$\{\$\{"[^\)]+\)+;~msi',
            'id'   => 'escapes',
        ],
        [
            'full' => '~(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*@?\1\s*\(@?\2\s*\([\'"]([^\'"]+)[\'"]\)+;~msi',
            'fast' => '~(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*@?\1\s*\(@?\2\s*\([\'"]([^\'"]+)[\'"]\)+;~msi',
            'id'   => 'assert',
        ],
        [
            'full' => '~eval\s*\(str_rot13\s*\([\'"]+\s*(?:.+(?=\\\\\')\\\\\'[^\'"]+)+[\'"]+\)+;~msi',
            'fast' => '~eval\s*\(str_rot13\s*\([\'"]+\s*(?:.+(?=\\\\\')\\\\\'[^\'"]+)+[\'"]+\)+;~msi',
            'id'   => 'evalCodeFunc',
        ],
        [
            'full' => '~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\']\2[\'"];\${\$\{"GLOBALS"\}\[[\'"]\3[\'"]\]}=[\'"]([^\'"]+)[\'"];eval.{10,50}?\$\{\$\{"GLOBALS"\}\[[\'"]\1[\'"]\]\}\)+;~msi',
            'fast' => '~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\']\2[\'"];\${\$\{"GLOBALS"\}\[[\'"]\3[\'"]\]}=[\'"]([^\'"]+)[\'"];eval.{10,50}?\$\{\$\{"GLOBALS"\}\[[\'"]\1[\'"]\]\}\)+;~msi',
            'id'   => 'evalVarVar',
        ],
        [
            'full' => '~(\$\w+)=[\'"][^"\']+[\'"];(\$\w+)=strrev\(\'edoced_46esab\'\);eval\(\2\([\'"][^\'"]+[\'"]\)+;~msi',
            'fast' => '~(\$\w+)=[\'"][^"\']+[\'"];(\$\w+)=strrev\(\'edoced_46esab\'\);eval\(\2\([\'"][^\'"]+[\'"]\)+;~msi',
            'id'   => 'edoced_46esab',
        ],
        [
            'full' => '~(\$\w+)=strrev\([\'"](?:|ed|oc|_|4|6|es|ab|(?:"\."))+[\'"]\);\s*(\$\w+)=strrev\([\'"](?:|et|al|fn|iz|g|(?:"\."))+[\'"]\);\s?@?eval\(\2\(\1\([\'"]([\w\/\+=]+)[\'"]\)\)\);~msi',
            'fast' => '~(\$\w+)=strrev\([\'"](?:|ed|oc|_|4|6|es|ab|(?:"\."))+[\'"]\);\s*(\$\w+)=strrev\([\'"](?:|et|al|fn|iz|g|(?:"\."))+[\'"]\);\s?@?eval\(\2\(\1\([\'"]([\w\/\+=]+)[\'"]\)\)\);~msi',
            'id'   => 'edoced_46esab_etalfnizg',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)")*)";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."[^"]+"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi',
            'fast' => '~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)"){0,1000})";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."[^"]+"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi',
            'id'   => 'eval2',
        ],
        [
            'full' => '~(?:\${"\\\\x[\\\\\w]+"}\["\\\\x[\\\\\w]+"\]\s?=\s?"[\w\\\\]+";){1,10}\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\s?=\s?"\w{1,100}";\${\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\s?}="(\\\\x[\\\\\w]+)";eval\(((?|str_rot13\(|gzinflate\(|base64_decode\(){1,10})\(\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\){1,5};~msi',
            'fast' => '~(?:\${"\\\\x[\\\\\w]+"}\["\\\\x[\\\\\w]+"\]\s?=\s?"[\w\\\\]+";){1,10}\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\s?=\s?"\w{1,100}";\${\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\s?}="(\\\\x[\\\\\w]+)";eval\(((?|str_rot13\(|gzinflate\(|base64_decode\(){1,10})\(\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\){1,5};~msi',
            'id'   => 'evalEscapedCharsContent',
        ],
        [
            'full' => '~@?(eval|echo|(\$\w+)\s*=\s*create_function)(?:\/\*+\/)?\s*\((\'\',)?\s*([\'"?>.\s]+)?\s*\(?\s*@?\s*(base64_decode\s*\(|pack\s*\(\'H\*\',|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\(|hex2bin\()+.*?[^\'");]+((\s*\.?[\'"]([^\'";]+[\'"]*\s*)+)?\s*[\'"\);]+)+(\s*\2\(\);)?~msi',
            'fast' => '~@?(eval|echo|(\$\w+)\s*=\s*create_function)(?:\/\*+\/)?\s*\((\'\',)?\s*([\'"?>.\s]+)?\s*\(?\s*@?\s*(base64_decode\s*\(|pack\s*\(\'H\*\',|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\(|hex2bin\()+.*?[^\'");]+((\s*\.?[\'"]([^\'";]+[\'"]*\s*)+)?\s*[\'"\);]+)+(\s*\2\(\);)?~msi',
            'id'   => 'eval',
        ],
        [
            'full' => '~eval\s*/\*[\w\s\.:,]+\*/\s*\([^\)]+\)+;~msi',
            'fast' => '~eval\s*/\*[\w\s\.:,]+\*/\s*\(~msi',
            'id'   => 'eval',
        ],
        [
            'full' => '~((?:\$\w+\s?=\s?(?:base64_decode|str_rot13)\([\'"][^\'"]+[\'"]\);)+)\s?(eval\((?:(?:\w+\()*\$\w+\(?)+(?:.*?)?\)+;)~msi',
            'fast' => '~((?:\$\w+\s?=\s?(?:base64_decode|str_rot13)\([\'"][^\'"]+[\'"]\);)+)\s?(eval\((?:(?:\w+\()*\$\w+\(?)+(?:.*?)?\)+;)~msi',
            'id'   => 'evalFuncVars',
        ],
        [
            'full' => '~eval\("\\\\145\\\\166\\\\141\\\\154\\\\050\\\\142\\\\141\\\\163[^\)]+\)+;~msi',
            'fast' => '~eval\("\\\\145\\\\166\\\\141\\\\154\\\\050\\\\142\\\\141\\\\163~msi',
            'id'   => 'evalHex',
        ],
        [
            'full' => '~eval\s*\("\\\\x?\d+[^\)]+\)+;(?:[\'"]\)+;)?~msi',
            'fast' => '~eval\s*\("\\\\x?\d+~msi',
            'id'   => 'evalHex',
        ],
        [
            'full' => '~(\$\w+)\s=\s(["\']?[\w\/\+]+["\']?);\s(\$\w+)\s=\s((?:str_rot13\(|rawurldecode\(|convert_uudecode\(|gzinflate\(|str_rot13\(|base64_decode\(|rawurldecode\(|)+\1\)\)+);\secho\s(eval\(\3\);)~msi',
            'fast' => '~(\$\w+)\s=\s(["\']?[\w\/\+]+["\']?);\s(\$\w+)\s=\s((?:str_rot13\(|rawurldecode\(|convert_uudecode\(|gzinflate\(|str_rot13\(|base64_decode\(|rawurldecode\(|)+\1\)\)+);\secho\s(eval\(\3\);)~msi',
            'id'   => 'echoEval',
        ],
        [
            'full' => '~if\(!function_exists\([\'"](\w+)[\'"]\)\){function\s?\1\((\$\w+)\){(\$\w+)=array\(\'(\d+)\',\'([^\']+)\',\'([^\']+)\',\2\);for\((\$\w+)=0;\7<4;\7\+\+\){for\((\$\w+)=0;\8<strlen\(\3\[\7\]\);\8\+\+\)\s?\3\[\7\]\[\8\]\s?=\s?chr\(ord\(\3\[\7\]\[\8\]\)-\(\7\?\3\[\8\s?xor\s?\8\]:1\)\);if\(\7==2\)\s?\3\[3\]=\3\[1\]\(\3\[2\]\(\3\[3\]\)\);}\s?return\s?\3\[3\];}(\$\w+)=["\']([\w\+\/=]+)["\'];(\$\w+)=[\'"]\1[\'"];(\$\w+)=\11\([\'"]([\w=]+)[\'"]\);\$\w+=\12\(\'\',\11\(\9\)\);\$\w+\(\);}~msi',
            'fast' => '~if\(!function_exists\([\'"](\w+)[\'"]\)\){function\s?\1\((\$\w+)\){(\$\w+)=array\(\'(\d+)\',\'([^\']+)\',\'([^\']+)\',\2\);for\((\$\w+)=0;\7<4;\7\+\+\){for\((\$\w+)=0;\8<strlen\(\3\[\7\]\);\8\+\+\)\s?\3\[\7\]\[\8\]\s?=\s?chr\(ord\(\3\[\7\]\[\8\]\)-\(\7\?\3\[\8\s?xor\s?\8\]:1\)\);if\(\7==2\)\s?\3\[3\]=\3\[1\]\(\3\[2\]\(\3\[3\]\)\);}\s?return\s?\3\[3\];}(\$\w+)=["\']([\w\+\/=]+)["\'];(\$\w+)=[\'"]\1[\'"];(\$\w+)=\11\([\'"]([\w=]+)[\'"]\);\$\w+=\12\(\'\',\11\(\9\)\);\$\w+\(\);}~msi',
            'id'   => 'evalCreateFunc',
        ],
        [
            'full' => '~(\$\w{1,1000})=[\'"]([\'"\w/\+=]+)[\'"];(\$\w{1,3000}=(?:base64_decode|gzinflate|convert_uudecode|str_rot13)\(\$\w{1,3000}\);){1,100}eval\((\$\w{1,3000})\);~msi',
            'fast' => '~(\$\w{1,1000})=[\'"]([\'"\w/\+=]+)[\'"];(\$\w{1,3000}=(?:base64_decode|gzinflate|convert_uudecode|str_rot13)\(\$\w{1,3000}\);){1,100}eval\((\$\w{1,3000})\);~msi',
            'id'   => 'evalAssignedVars',
        ],
        [
            'full' => '~\$\w{1,50}=\'printf\';(\s*\$\w{1,50}\s*=\s*\'[^\']+\'\s*;)+\s*(\$\w{1,50}\s*=\s*\$\w{1,50}\([^\)]+\);\s*|(?:if\(!function_exists\(\'[^\']+\'\)\){function\s\w{1,50}\(\$\w{1,50},\$\w{1,50}\){return\s?eval\("return function\(\$\w{1,50}\){{\$\w{1,50}}};"\);}}\s*)?)+(\$\w{1,50}\s*=\s*\'[^\']+\';\s*)?(\s*(\$\w{1,50}\s*=\s*)?\$\w+\([^)]*\)+;\s*)+(echo\s*\$\w{1,50};)?~msi',
            'fast' => '~\$\w{1,50}=\'printf\';(\s*\$\w{1,50}\s*=\s*\'[^\']+\'\s*;)+\s*(\$\w{1,50}\s*=\s*\$\w{1,50}\([^\)]+\);\s*|(?:if\(!function_exists\(\'[^\']+\'\)\){function\s\w{1,50}\(\$\w{1,50},\$\w{1,50}\){return\s?eval\("return function\(\$\w{1,50}\){{\$\w{1,50}}};"\);}}\s*)?)+(\$\w{1,50}\s*=\s*\'[^\']+\';\s*)?(\s*(\$\w{1,50}\s*=\s*)?\$\w+\([^)]*\)+;\s*)+(echo\s*\$\w{1,50};)?~msi',
            'id'   => 'seolyzer',
        ],
        [
            'full' => '~(\$\w+)="((?:[^"]|(?<=\\\\)")*)";(\s*\$GLOBALS\[\'\w+\'\]\s*=\s*(?:\${)?(\1\[\d+\]}?\.?)+;\s*)+(.{0,400}\s*\1\[\d+\]\.?)+;\s*}~msi',
            'fast' => '~(\$\w+)="((?:[^"]|(?<=\\\\)"){0,1000})";(\s*\$GLOBALS\[\'\w+\'\]\s*=\s*(?:\${)?(\1\[\d+\]}?\.?)+;\s*)+(.{0,400}\s*\1\[\d+\]\.?)+;\s*}~msi',
            'id'   => 'subst2',
        ],
        [
            'full' => '~(\$\w{1,50}\s*=\s*"[^"]{1,1000}";\s*)+(\$\w{1,50}\s*=\s*\$?\w{1,50}\("\w{1,50}"\s*,\s*""\s*,\s*"\w{1,50}"\);\s*)+\$\w{1,50}\s*=\s*\$\w{1,50}\("",\s*\$\w{1,50}\(\$\w{1,50}\("\w{1,50}",\s*"",(\s*\$\w{1,50}\.?)+\)+;\$\w{1,50}\(\);~msi',
            'fast' => '~(\$\w{1,50}\s*=\s*"[^"]{1,1000}";\s*)+(\$\w{1,50}\s*=\s*\$?\w{1,50}\("\w{1,50}"\s*,\s*""\s*,\s*"\w{1,50}"\);\s*)+\$\w{1,50}\s*=\s*\$\w{1,50}\("",\s*\$\w{1,50}\(\$\w{1,50}\("\w{1,50}",\s*"",(\s*\$\w{1,50}\.?)+\)+;\$\w{1,50}\(\);~msi',
            'id'   => 'strreplace',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?\'[^\']{1,500}\';\s?\$\w{1,50}\s?=\s?str_replace\(\'\w{1,50}\',\'\',\'\w{1,100}\'\);\s?(?:\$\w{1,50}\s?=\s?\'[^\']{1,500}\';\s?){1,15}\$\w{1,50}\s?=\s?str_replace\(\'[^\']{1,100}\',\'\',(?:\$\w{1,50}\.?){1,50}\);\s?\$\w{1,50}\s?=\s?\$\w{1,50}\(\'\',\$\w{1,50}\);\$\w{1,50}\(\);~msi',
            'fast' => '~\$\w{1,50}\s?=\s?\'[^\']{1,500}\';\s?\$\w{1,50}\s?=\s?str_replace\(\'\w{1,50}\',\'\',\'\w{1,100}\'\);\s?(?:\$\w{1,50}\s?=\s?\'[^\']{1,500}\';\s?){1,15}\$\w{1,50}\s?=\s?str_replace\(\'[^\']{1,100}\',\'\',(?:\$\w{1,50}\.?){1,50}\);\s?\$\w{1,50}\s?=\s?\$\w{1,50}\(\'\',\$\w{1,50}\);\$\w{1,50}\(\);~msi',
            'id'   => 'strreplace',
        ],
        [
            'full' => '~@?echo\s*([\'"?>.\s]+)?@?\s*(base64_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+.*?[^\'")]+((\s*\.?[\'"]([^\'";]+\s*)+)?\s*[\'"\);]+)+~msi',
            'fast' => '~@?echo\s*([\'"?>.\s]+)?@?\s*(base64_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+.*?[^\'")]+((\s*\.?[\'"]([^\'";]+\s*)+)?\s*[\'"\);]+)+~msi',
            'id'   => 'echo',
        ],
        [
            'full' => '~(\$\w+)="([^"]+)";\s*(\$\w+)=strtoupper\s*\((\1\[\d+\]\s*\.?\s*)+\)\s*;\s*if\(\s*isset\s*\(\${\s*\3\s*}\[\d*\s*\'\w+\'\s*\]\s*\)\s*\)\s*{eval\(\${\3\s*}\[\'\w+\']\s*\)\s*;}~smi',
            'fast' => '~(\$\w+)="([^"]+)";\s*(\$\w+)=strtoupper\s*\((\1\[\d+\]\s*\.?\s*)+\)\s*;\s*if\(\s*isset\s*\(\${\s*\3\s*}\[\d*\s*\'\w+\'\s*\]\s*\)\s*\)\s*{eval\(\${\3\s*}\[\'\w+\']\s*\)\s*;}~smi',
            'id'   => 'strtoupper',
        ],
        [
            'full' => '~(\$\w+)="[^"]+";\s*(\$\w+)=str_ireplace\("[^"]+","",\1\);(\$\w+)\s*=\s*"[^"]+";\s*function\s*(\w+)\((\$\w+,?)+\){\s*(\$\w+)=\s*create_function\(\'\',\$\w+\);\s*array_map\(\6,array\(\'\'\)+;\s*}\s*set_error_handler\(\'\4\'\);(\$\w+)=\2\(\3\);user_error\(\7,E_USER_ERROR\);\s*if\s*.+?}~msi',
            'fast' => '~(\$\w+)="[^"]+";\s*(\$\w+)=str_ireplace\("[^"]+","",\1\);(\$\w+)\s*=\s*"[^"]+";\s*function\s*(\w+)\((\$\w+,?)+\){\s*(\$\w+)=\s*create_function\(\'\',\$\w+\);\s*array_map\(\6,array\(\'\'\)+;\s*}\s*set_error_handler\(\'\4\'\);(\$\w+)=\2\(\3\);user_error\(\7,E_USER_ERROR\);\s*if\s*.+?}~msi',
            'id'   => 'errorHandler',
        ],
        [
            'full' => '~(\$\w+)=strrev\(str_ireplace\("[^"]+","","[^"]+"\)\);(\$\w+)="([^"]+)";eval\(\1\(\2\)+;}~msi',
            'fast' => '~(\$\w+)=strrev\(str_ireplace\("[^"]+","","[^"]+"\)\);(\$\w+)="([^"]+)";eval\(\1\(\2\)+;}~msi',
            'id'   => 'evalIReplace',
        ],
        [
            'full' => '~error_reporting\(0\);ini_set\("display_errors",\s*0\);if\(!defined\(\'(\w+)\'\)\){define\(\'\1\',__FILE__\);if\(!function_exists\("([^"]+)"\)\){function [^(]+\([^\)]+\).+?eval\(""\);.+?;eval\(\$[^\)]+\)\);[^\)]+\)+;return\s*\$[^;]+;\s*\?>([^;]+);~msi',
            'fast' => '~error_reporting\(0\);ini_set\("display_errors",\s*0\);if\(!defined\(\'(\w+)\'\)\){define\(\'\1\',__FILE__\);if\(!function_exists\("([^"]+)"\)\){function [^(]+\([^\)]+\).+?eval\(""\);.+?;eval\(\$[^\)]+\)\);[^\)]+\)+;return\s*\$[^;]+;\s*\?>([^;]+);~msi',
            'id'   => 'PHPJiaMi',
        ],
        [
            'full' => '~\$\w+=0;(\$GLOBALS\[\'\w+\'\])\s*=\s*\'([^\']+)\';\s*(\$\w+)=pack\(\'H\*\',substr\(\1,\s*([-\d]+)\)\);if\s*\(!function_exists\(\'(\w+)\'\)\){function\s*\5\(\$\w+,\s*\$\w+\){\$\w+=\1;\s*\$d=pack\(\'H\*\',substr\(\1,\s*\4\)\);\s*return\s*\$\w+\(substr\(\$\w+,\s*\$\w+,\s*\$\w+\)\);}};eval\(\3\(\'[^\']+\'\)\);~msi',
            'fast' => '~\$\w+=0;(\$GLOBALS\[\'\w+\'\])\s*=\s*\'([^\']+)\';\s*(\$\w+)=pack\(\'H\*\',substr\(\1,\s*([-\d]+)\)\);if\s*\(!function_exists\(\'(\w+)\'\)\){function\s*\5\(\$\w+,\s*\$\w+\){\$\w+=\1;\s*\$d=pack\(\'H\*\',substr\(\1,\s*\4\)\);\s*return\s*\$\w+\(substr\(\$\w+,\s*\$\w+,\s*\$\w+\)\);}};eval\(\3\(\'[^\']+\'\)\);~msi',
            'id'   => 'substr',
        ],
        [
            'full' => '~(function\s*(\w+)\((\$\w+)\){\s*return\s*(base64_decode|gzinflate|eval)\(\$\w+(,\d+)?\);}\s*)+(\$\w+)="([^"]+)";(\w+\()+\6\)+~msi',
            'fast' => '~(function\s*(\w+)\((\$\w+)\){\s*return\s*(base64_decode|gzinflate|eval)\(\$\w+(,\d+)?\);}\s*)+(\$\w+)="([^"]+)";(\w+\()+\6\)+~msi',
            'id'   => 'funcs',
        ],
        [
            'full' => '~\$_F=__(?:FILE|hex)__;\$_X=["\']([^\'"]+)[\'"];\s*(?:\$[_\w]+\.=[\'"][\w\+\/=]+[\'"];){0,30}\$_\w+=base64_decode\(\$_X\);\$_X=strtr\(\$_X,\'([^\']+)\',\'([^\']+)\'\);\$_R=@?(?:(str_replace)|(ereg_replace)|(preg_replace))\(\'\~?__FILE__\~?\',"\'".\$_F."\'",\$_X\);eval\(\$_R\);\$_R=0;\$_X=0;~msi',
            'fast' => '~\$_F=__(?:FILE|hex)__;\$_X=["\']([^\'"]+)[\'"];\s*(?:\$[_\w]+\.=[\'"][\w\+\/=]+[\'"];){0,30}\$_\w+=base64_decode\(\$_X\);\$_X=strtr\(\$_X,\'([^\']+)\',\'([^\']+)\'\);\$_R=@?(?:(str_replace)|(ereg_replace)|(preg_replace))\(\'\~?__FILE__\~?\',"\'".\$_F."\'",\$_X\);eval\(\$_R\);\$_R=0;\$_X=0;~msi',
            'id'   => 'LockIt2',
        ],
        [
            'full' => '~(?:@error_reporting\(\d+\);\s*@set_time_limit\(\d+\);)?\s*(\$\w+)=([\s\'\w\/+=]+);\s*(\$\w+)=(__FILE__);\s*\1=gzinflate\(str_rot13\(base64_decode\(\$tr\)\)\);\1=strtr\(\1,\'([^\']+)\'\s*,\'([^\']+)\'\);(\$_R)=@?ereg_replace\(\'\~?\4\~?\',"\'".\3."\'",\1\);eval\(\7\);\7=0;\1=0;~msi',
            'fast' => '~(\$\w+)=([\s\'\w\/+=]+);\s*(\$\w+)=(__FILE__);\s*\1=\w+\(\w+\(\w+\(\$tr\)\)\);\1=\w+\(\1,\'([^\']+)\'\s*,\'([^\']+)\'\);(\$_R)=@?\w+\(\'\~?\4\~?\',"\'".\3."\'",\1\);\w+\(\7\);\7=0;\1=0;~msi',
            'id'   => 'anaski',
        ],
        [
            'full' => '~\$\w+="[^"]+";\$l+=0;\$l+=\'base64_decode\';\$l+=0;eval\(.+?;eval\(\$l+\);return;~msi',
            'fast' => '~\$\w+="[^"]+";\$l+=0;\$l+=\'base64_decode\';\$l+=0;eval\(.+?;eval\(\$l+\);return;~msi',
            'id'   => 'custom1',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"(\w{32})";\s*(\$\w+)\s*=\s*array\s*\(\);\s*(\3\[\d+\]\s*=\s*"[^"]+";\s*)+\s*(\$\w+)\s*=\s*"base64_decode";\s*\$\w+\s*=\s*(\w+)\s*\(\3,\1\);function\s*\6\(\s*.{200,500}return\s*\$\w+;\s*}\s*eval\s*\(\5\s*\(\$\w+\)\);~msi',
            'fast' => '~(\$\w+)\s*=\s*"(\w{32})";\s*(\$\w+)\s*=\s*array\s*\(\);\s*(\3\[\d+\]\s*=\s*"[^"]+";\s*)+\s*(\$\w+)\s*=\s*"base64_decode";\s*\$\w+\s*=\s*(\w+)\s*\(\3,\1\);function\s*\6\(\s*.{200,500}return\s*\$\w+;\s*}\s*eval\s*\(\5\s*\(\$\w+\)\);~msi',
            'id'   => 'custom2',
        ],
        [
            'full' => '~\$\w+=\'=+\s*Obfuscation provided by Unknowndevice64 - Free Online PHP Obfuscator\s*(?:http://www\.ud64\.com/)?\s*=+\';\s*(\$ud64_c[o0]m="[\\\\0-9a-z\."]+;)+\$\w+=(\$ud64_c[o0]m\()+"([^"]+)"\)+;@eval\(\$ud64_c[o0]m\(\'[^\']+\'\)+;~msi',
            'fast' => '~\$\w+=\'=+\s*Obfuscation provided by Unknowndevice64 - Free Online PHP Obfuscator\s*(?:http://www\.ud64\.com/)?\s*=+\';\s*(\$ud64_c[o0]m="[\\\\0-9a-z\."]+;)+\$\w+=(\$ud64_c[o0]m\()+"([^"]+)"\)+;@eval\(\$ud64_c[o0]m\(\'[^\']+\'\)+;~msi',
            'id'   => 'ud64',
        ],
        [
            'full' => '~(\$[\w_]+=("[\\\\\\\\\w]+"\.?)+;)+\$\w+=(?:\$\w+\()+"([\w\/\+=]+)"\)+;@eval\(\$\w+\(\'.*?\'\)+;~msi',
            'fast' => '~(\$[\w_]+=("[\\\\\\\\\w]+"\.?)+;)+\$\w+=(?:\$\w+\()+"([\w\/\+=]+)"\)+;@eval\(\$\w+\(\'.*?\'\)+;~msi',
            'id'   => 'ud64',
        ],
        [
            'full' => '~\$\w+=__FILE__;\$\w+=fopen\(\$\w+,\'rb\'\);fread\(\$\w+,(\d+)\);\$\w+=explode\("\\\\t",base64_decode\(fread\(\$\w+,(\d+)\)+;\$\w+=\$\w+\[[\d+]\];[\$l1=\d{}\.;\(\)\[\]]+eval\(\$\w+\(\'[^\']+\'\)+;\s*return\s*;\?>[\w=\+]+~msi',
            'fast' => '~\$\w+=__FILE__;\$\w+=fopen\(\$\w+,\'rb\'\);fread\(\$\w+,(\d+)\);\$\w+=explode\("\\\\t",base64_decode\(fread\(\$\w+,(\d+)\)+;\$\w+=\$\w+\[[\d+]\];[\$l1=\d{}\.;\(\)\[\]]+eval\(\$\w+\(\'[^\']+\'\)+;\s*return\s*;\?>[\w=\+]+~msi',
            'id'   => 'qibosoft',
        ],
        [
            'full' => '~(\$\w+)=base64_decode\("([^"]+)"\);\s*eval\("return\s*eval\(\\\\"\1\\\\"\);"\)~msi',
            'fast' => '~(\$\w+)=base64_decode\("([^"]+)"\);\s*eval\("return\s*eval\(\\\\"\1\\\\"\);"\)~msi',
            'id'   => 'evalReturn',
        ],
        [
            'full' => '~(?:\$[0O]+\[[\'"](\w+)[\'"]\]\.?="[\\\\\w]+";)+(?:\$[0O]+\[[\'"]\w+[\'"]\]\.?=\$[0O]+\[[\'"]\w+[\'"]\]\([\'"][\d\(]+[\'"](,__FILE__)?\);)+@eval\((?:\$[0O]+\[[\'"]\w+[\'"]\]\()+"([^"]+)"\)+;~mis',
            'fast' => '~(?:\$[0O]+\[[\'"](\w+)[\'"]\]\.?="[\\\\\w]+";)+(?:\$[0O]+\[[\'"]\w+[\'"]\]\.?=\$[0O]+\[[\'"]\w+[\'"]\]\([\'"][\d\(]+[\'"](,__FILE__)?\);)+@eval\((?:\$[0O]+\[[\'"]\w+[\'"]\]\()+"([^"]+)"\)+;~mis',
            'id'   => 'evalChars',
        ],
        [
            'full' => '~<\?php\s+((\$GLOBALS\[\s*[\'"]\w+[\'"]\s*\])\s*=\s*base64_decode\("([^"]*)"\);)+\s*\?><\?php\s.+\2.+exit;\s}\sfunction\s\w+\(\)\s{\sreturn\sarray\(\s\'favicon\'\s=>\s\'[^\']+\',\s+\'sprites\'\s=>\s\'[^\']+\',\s\);\s}~msi',
            'fast' => '~<\?php\s+((\$GLOBALS\[\s*[\'"]\w+[\'"]\s*\])\s*=\s*base64_decode\("([^"]*)"\);)+\s*\?><\?php\s.+\2.+exit;\s}\sfunction\s\w+\(\)\s{\sreturn\sarray\(\s\'favicon\'\s=>\s\'[^\']+\',\s+\'sprites\'\s=>\s\'[^\']+\',\s\);\s}~msi',
            'id'   => 'globalsBase64',
        ],
        [
            'full' => '~(\$\w+=strrev\("[^"]+"\);)+eval\((\$\w+\()+"[^"]+"\)+;~mis',
            'fast' => '~(\$\w+=strrev\("[^"]+"\);)+eval\((\$\w+\()+"[^"]+"\)+;~mis',
            'id'   => 'strrevVarEval',
        ],
        [
            'full' => '~\$\w+=basename/\*\w+\*/\(/\*\w+\*/trim/\*\w+\*/\(.+?(\$\w+)=.+\1.+?;~msi',
            'fast' => '~\$\w+=basename/\*\w+\*/\(/\*\w+\*/trim/\*\w+\*/\(.+?(\$\w+)=.+\1.+?;~msi',
            'id'   => 'comments',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*(base64_decode\s*\(+|gzinflate\s*\(+|strrev\s*\(+|str_rot13\s*\(+|gzuncompress\s*\(+|convert_uudecode\s*\(+|urldecode\s*\(+|rawurldecode\s*\(+|htmlspecialchars_decode\s*\(+)+"([^"]+)"\)+;\s*@?eval\(([\'"?>.\s]+)?\1\);~',
            'fast' => '~(\$\w+)\s*=\s*(base64_decode\s*\(+|gzinflate\s*\(+|strrev\s*\(+|str_rot13\s*\(+|gzuncompress\s*\(+|convert_uudecode\s*\(+|urldecode\s*\(+|rawurldecode\s*\(+|htmlspecialchars_decode\s*\(+)+"([^"]+)"\)+;\s*@?eval\(([\'"?>.\s]+)?\1\);~',
            'id'   => 'varFuncsEval',
        ],
        [
            'full' => '~((\$\w+)="";\$\w+\s*\.=\s*"[^;]+;\s*)+(?:="";)?eval\((\s*\$\w+\s*\.)+\s*"[^"]+(?:"\);)+~msi',
            'fast' => '~((\$\w+)="";\$\w+\s*\.=\s*"[^;]+;\s*)+(?:="";)?eval\((\s*\$\w+\s*\.)+\s*"[^"]+(?:"\);)+~msi',
            'id'   => 'evalConcatVars',
        ],
        [
            'full' => '~<\?php\s*defined\(\'[^\']+\'\)\s*\|\|\s*define\(\'[^\']+\',__FILE__\);(global\s*\$[^;]+;)+\s*(if\(!function_exists\(\'([^\']+)\'\)\){\s*function\s*[^\)]+\(\$[^,]+,\$[^=]+=\'\'\){\s*if\(empty\(\$[^\)]+\)\)\s*return\s*\'\';\s*\$[^=]+=base64_decode\(\$[^\)]+\);\s*if\(\$[^=]+==\'\'\)\s*return\s*\~\$[^;]+;\s*if\(\$[^=]+==\'-1\'\)\s*@[^\(]+\(\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^\)]+\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^,]+,\$[^,]+,\$[^\)]+\);\s*return\s*\$[^^]+\^\$[^;]+;\s*}}\s*)+(\$[^\[]+\["[^"]+"]=[^\(]+\(\'[^\']+\',\'[^\']*\'\);\s*)+(\$[^\[]+\[\'[^\']+\'\]=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\([^\)]*\)+;\s*)+return\(eval\(\$[^\[]+\[\'[^\']+\'\]\)+;\s*\?>\s*#!/usr/bin/php\s*-q\s*(\s*[^\s]+)+~msi',
            'fast' => '~<\?php\s*defined\(\'[^\']{10,30}\'\)\s*\|\|\s*define\(\'[^\']{10,30}\',__FILE__\);(global\s*\$[^;]{10,30};)+\s*if\(!function_exists\(\'([^\']+)\'\)\){\s*function\s*[^\)]+\(\$[^,]{10,30},\$[^=]{10,30}=\'\'\){\s*if\(empty\(\$[^\)]+\)\)\s*return\s*\'\';\s*\$[^=]{10,30}=base64_decode~msi',
            'id'   => 'OELove',
        ],
        [
            'full' => '~\$\w+\s*=(\s*(\d+)\+)+\d+;(\$\w+="[^"]+";)+(\$\w+)\s*=\s*\w+\(\'[^\']+\',\s*\$\w+,\s*\'[^\']+\'\);.+\4\("[^"]+"\);\$\w+\s*=\s*\4;(\$\w+="[^"]+";)+.+\$\w+\(\$\w+,\$\w+\("",\s*\$\w+\(\$\w+\(\$\w+\(\$\w+\(\$\w+,\s*"(\d+)"\)+,\$\w+\);.+function \w+\((\$\w+),\s*\$\w+,\s(\$\w+)\)\s{\8\s=\s\8\s\.\s\8;.+return \7;}~msi',
            'fast' => '~\$\w+\s*=(\s*(\d+)\+)+\d+;(\$\w+="[^"]+";)+(\$\w+)\s*=\s*\w+\(\'[^\']+\',\s*\$\w+,\s*\'[^\']+\'\);.+\4\("[^"]+"\);\$\w+\s*=\s*\4;(\$\w+="[^"]+";)+~msi',
            'id'   => 'Obf_20200402_1',
        ],
        [
            'full' => '~(?:\$\w+\s*=\s*"[^"]+";\s*)?function\s(\w+)\((\$\w+),\s*(\$\w+),\s*(\$\w+)\){\s*return\s*([\'\.]*(\2|\3|\4)[\'\.]*)+;\s*}\s*(?:\$\w+\s*=\s*"[^"]+";)?(\s*\$\w+\s*=\s*\1\((((\'\')|(\$\w+)|(\$\w+[\[\{]\d+[\]\}](\.\'\')?)|(\$\w+[\[\{]\d+[\]\}]\.\$\w+[\[\{]\d+[\]\}]))\s*,?\s*)+\);\s*)+\s*\$\w+\s*=\s*\1[^"]+"\'([^\']+)\'".+?array\(\'\',\'}\'.\$\w+\.\'//\'\)\);~msi',
            'fast' => '~function\s(\w+)\((\$\w+),\s*(\$\w+),\s*(\$\w+)\){\s*return\s*([\'\.]*(\2|\3|\4)[\'\.]*)+;\s*}\s*(?:\$\w+\s*=\s*"[^"]+";)?(\s*\$\w+\s*=\s*\1\((((\'\')|(\$\w+)|(\$\w+[\[\{]\d+[\]\}](\.\'\')?)|(\$\w+[\[\{]\d+[\]\}]\.\$\w+[\[\{]\d+[\]\}]))\s*,?\s*)+\);\s*)+\s*\$\w+\s*=\s*\1[^"]+"\'([^\']+)\'".+?array\(\'\',\'}\'.\$\w+\.\'//\'\)\);~msi',
            'id'   => 'Obf_20200402_2',
        ],
        [
            'full' => '~(?:function\s*\w{1,50}\(\$\w{1,50},\s*\$\w{1,50}\)\s*\{(?:\s*\$\w{1,50}\s*=\s*(?:md5\(\$\w{1,50}\)|\d+|base64_decode\(\$\w{1,50}\)|strlen\(\$\w{1,50}\)|\'\');\s*)+\s*for\s*\(\$\w{1,50}\s*=\s\d+;\s*\$\w{1,50}\s*<\s*\$len;\s*\$\w{1,50}\+\+\)\s*\{\s*if\s*\(\$\w{1,50}\s*==\s*\$\w{1,50}\)\s*\{\s*\$\w{1,50}\s*=\s*\d+;\s*}\s*\$\w{1,50}\s*\.=\s*substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\);\s*\$\w{1,50}\+\+;\s*\}(?:\s*\$\w{1,50}\s*=\s*\'\';)?\s*for\s*\(\$\w{1,50}\s*=\s*\d+;\s*\$\w{1,50}\s*<\s*\$\w{1,50};\s*\$\w{1,50}\+\+\)\s*{\s*if\s*\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*<\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\)\s*\{\s*\$\w{1,50}\s*\.=\s*chr\(\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*\+\s*\d+\)\s*-\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\);\s*}\s*else\s*{\s*\$\w{1,50}\s*\.=\s*chr\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*-\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\);\s*}\s*}\s*return\s*\$\w{1,50};\s*\}\s*|\$\w{1,50}\s*=\s*"([^"]+)";\s*){2}\s*\$\w{1,50}\s*=\s*"([^"]+)";\s*\$\w{1,50}\s*=\s*\w{1,50}\(\$\w{1,50},\s*\$\w{1,50}\);\s*eval\(\$\w{1,50}\);~msi',
            'fast' => '~(?:function\s*\w{1,50}\(\$\w{1,50},\s*\$\w{1,50}\)\s*\{(?:\s*\$\w{1,50}\s*=\s*(?:md5\(\$\w{1,50}\)|\d+|base64_decode\(\$\w{1,50}\)|strlen\(\$\w{1,50}\)|\'\');\s*)+\s*for\s*\(\$\w{1,50}\s*=\s\d+;\s*\$\w{1,50}\s*<\s*\$len;\s*\$\w{1,50}\+\+\)\s*\{\s*if\s*\(\$\w{1,50}\s*==\s*\$\w{1,50}\)\s*\{\s*\$\w{1,50}\s*=\s*\d+;\s*}\s*\$\w{1,50}\s*\.=\s*substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\);\s*\$\w{1,50}\+\+;\s*\}(?:\s*\$\w{1,50}\s*=\s*\'\';)?\s*for\s*\(\$\w{1,50}\s*=\s*\d+;\s*\$\w{1,50}\s*<\s*\$\w{1,50};\s*\$\w{1,50}\+\+\)\s*{\s*if\s*\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*<\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\)\s*\{\s*\$\w{1,50}\s*\.=\s*chr\(\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*\+\s*\d+\)\s*-\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\);\s*}\s*else\s*{\s*\$\w{1,50}\s*\.=\s*chr\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*-\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\);\s*}\s*}\s*return\s*\$\w{1,50};\s*\}\s*|\$\w{1,50}\s*=\s*"([^"]+)";\s*){2}\s*\$\w{1,50}\s*=\s*"([^"]+)";\s*\$\w{1,50}\s*=\s*\w{1,50}\(\$\w{1,50},\s*\$\w{1,50}\);\s*eval\(\$\w{1,50}\);~msi',
            'id'   => 'Obf_20200414_1',
        ],
        [
            'full' => '~(?:\$\w+\s*=\s*\'\w+\';)?\s*(\$\w+)\s*=\s*urldecode\(\'[%0-9a-f]+\'\);(\s*(\$\w+)\s*=(\s*\1\{\d+\}\.?)+;)+\s*(\$\w+)\s*=\s*"[^"]+"\.\3\("[^"]+"\);\s*eval\(\5\);~msi',
            'fast' => '~(\$\w+)\s*=\s*urldecode\(\'[%0-9a-f]+\'\);(\s*(\$\w+)\s*=(\s*\1\{\d+\}\.?)+;)+\s*(\$\w+)\s*=\s*"[^"]+"\.\3\("[^"]+"\);\s*eval\(\5\);~msi',
            'id'   => 'Obf_20200421_1',
        ],
        [
            'full' => '~(\$\w+)=\'([^\']+)\';(\$\w+)=str_rot13\(gzinflate\(str_rot13\(base64_decode\(\1\)\)\)\);eval\(\3\);~msi',
            'fast' => '~(\$\w+)=\'([^\']+)\';(\$\w+)=str_rot13\(gzinflate\(str_rot13\(base64_decode\(\1\)\)\)\);eval\(\3\);~msi',
            'id'   => 'SmartToolsShop',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*\("\?>"\.gzuncompress\(base64_decode\("[^"]+"\)\)\);\s*@?eval\(\1\);~msi',
            'fast' => '~(\$\w+)\s*=\s*\("\?>"\.gzuncompress\(base64_decode\("[^"]+"\)\)\);\s*@?eval\(\1\);~msi',
            'id'   => 'Obf_20200504_1',
        ],
        [
            'full' => '~(\$\w+)=base64_decode\(\'[^\']+\'\);\s*eval\(\1\);~mis',
            'fast' => '~(\$\w+)=base64_decode\(\'[^\']+\'\);\s*eval\(\1\);~mis',
            'id'   => 'Obf_20200507_1',
        ],
        [
            'full' => '~@error_reporting\(0\);\s*@ini_set\(\'error_log\',NULL\);\s*@ini_set\(\'log_errors\',0\);\s*@ini_set\(\'output_buffering\',\s*0\);\s*@ini_set\(\'display_errors\',\s*0\);\s*\$\w+="(An0n_3xPloiTeR)";\$UeXploiT="([^"]+)";\$\1="([^"]+)";exit;~msi',
            'fast' => '~@error_reporting\(0\);\s*@ini_set\(\'error_log\',NULL\);\s*@ini_set\(\'log_errors\',0\);\s*@ini_set\(\'output_buffering\',\s*0\);\s*@ini_set\(\'display_errors\',\s*0\);\s*\$\w+="(An0n_3xPloiTeR)";\$UeXploiT="([^"]+)";\$\1="([^"]+)";exit;~msi',
            'id'   => 'Obf_20200507_3',
        ],
        [
            'full' => '~(?:error_reporting\(0\);\s*ini_set\("max_execution_time",0\);\s*(?:/\*.*?\*/)?\s*)?(\$\w+)=\s*\[(("."=>".",?\s*)+)];\s*(\$\w+)=str_split\("([^"]+)"\);\s*(?:\$\w+="";)?\s*foreach\(\4\s*as\s*(\$\w+)\)\s*{\s*foreach\(\s*\1\s*as\s*(\$\w+)=>(\$\w+)\)\s*{\s*if\(\6==\(string\)\8\)\s*\{\s*\$\w+\.=\7;\s*break;\s*}\s*}\s*}~msi',
            'fast' => '~(\$\w+)=\s*\[(("."=>".",?\s*)+)];\s*(\$\w+)=str_split\("([^"]+)"\);\s*(?:\$\w+="";)?\s*foreach\(\4\s*as\s*(\$\w+)\)\s*{\s*foreach\(\s*\1\s*as\s*(\$\w+)=>(\$\w+)\)\s*{\s*if\(\6==\(string\)\8\)\s*\{\s*\$\w+\.=\7;\s*break;\s*}\s*}\s*}~msi',
            'id'   => 'Obf_20200507_4',
        ],
        [
            'full' => '~assert\("[eval"\.]+\([base64_decode\."]+\(\'([^\']+)\'\)\)"\);~msi',
            'fast' => '~assert\("[eval"\.]+\([base64_decode\."]+\(\'([^\']+)\'\)\)"\);~msi',
            'id'   => 'Obf_20200507_5',
        ],
        [
            'full' => '~parse_str\(\'([^\']+)\',(\$\w+)\);(\2\[\d+\]\()+\'[^\']+\'\),array\(\),array\(\'[^\']+\'\.(\2\[\d+\]\()+\'([^\']+)\'\)+\.\'//\'\)+;~msi',
            'fast' => '~parse_str\(\'([^\']+)\',(\$\w+)\);(\2\[\d+\]\()+\'[^\']+\'\),array\(\),array\(\'[^\']+\'\.(\2\[\d+\]\()+\'([^\']+)\'\)+\.\'//\'\)+;~msi',
            'id'   => 'Obf_20200513_1',
        ],
        [
            'full' => '~function\s{0,50}(\w+)\((\$\w+)\)\s{0,50}\{\s{0,50}\2\s{0,50}=\s{0,50}substr\(\2,\s{0,50}\(int\)\(hex2bin\(\'([0-9a-f]+)\'\)\)\);\s{0,50}\2\s{0,50}=\s{0,50}substr\(\2,\s{0,50}\(int\)\(hex2bin\(\'([0-9a-f]+)\'\)\),\s{0,50}\(int\)\(hex2bin\(\'([0-9a-f]+)\'\)\)\);\s{0,50}return\s{0,50}\2;\s{0,50}\}\s{0,50}(\$\w+)\s{0,50}=\s{0,50}\'[^\']+\';\s{0,50}(\$\w+)\s{0,50}=\s{0,50}\'base64_decode\';\s{0,50}function\s{0,50}\w+\((\$\w+)\)\s{0,50}{\s{0,50}global\s{0,50}\6;\s{0,50}global\s{0,50}\7;\s{0,50}return\s{0,50}strrev\(gzinflate\(\7\(\1\(\8\)\)\)\);\s{0,50}\}\s{0,50}(?:eval\(\w+\(\')?([^\']+)\'\)+~msi',
            'fast' => '~function\s{0,50}(\w+)\((\$\w+)\)\s{0,50}\{\s{0,50}\2\s{0,50}=\s{0,50}substr\(\2,\s{0,50}\(int\)\(hex2bin\(\'([0-9a-f]+)\'\)\)\);\s{0,50}\2\s{0,50}=\s{0,50}substr\(\2,\s{0,50}\(int\)\(hex2bin\(\'([0-9a-f]+)\'\)\),\s{0,50}\(int\)\(hex2bin\(\'([0-9a-f]+)\'\)\)\);\s{0,50}return\s{0,50}\2;\s{0,50}\}\s{0,50}(\$\w+)\s{0,50}=\s{0,50}\'[^\']+\';\s{0,50}(\$\w+)\s{0,50}=\s{0,50}\'base64_decode\';\s{0,50}function\s{0,50}\w+\((\$\w+)\)\s{0,50}{\s{0,50}global\s{0,50}\6;\s{0,50}global\s{0,50}\7;\s{0,50}return\s{0,50}strrev\(gzinflate\(\7\(\1\(\8\)\)\)\);\s{0,50}\}\s{0,50}(?:eval\(\w+\(\')?([^\']+)\'\)+~msi',
            'id'   => 'Obf_20200522_1',
        ],
        [
            'full' => '~(\$\w+)=strrev\("[base64_decode"\.]+\);eval\(\1\(\'([^\']+)\'\)\);~msi',
            'fast' => '~(\$\w+)=strrev\("[base64_decode"\.]+\);eval\(\1\(\'([^\']+)\'\)\);~msi',
            'id'   => 'Obf_20200526_1',
        ],
        [
            'full' => '~error_reporting\(0\);define\(\'\w+\',\s*__FILE__\);define\(\'\w+\',\s*fopen\(__FILE__,\s*\'r\'\)\);fseek\(\w+,\s*__COMPILER_HALT_OFFSET__\);((\$\w+="\\\\x[0-9a-f]+";)+(\$\w+="[^"]+";)+eval\("\?>"\.(\$\w+\()+"([^"]+)"\)+;)+(?:/\*\w+\*/)?__halt_compiler\(\);[\w#|>^%\[\.\]\\\\/=]+~msi',
            'fast' => '~error_reporting\(0\);define\(\'\w+\',\s*__FILE__\);define\(\'\w+\',\s*fopen\(__FILE__,\s*\'r\'\)\);fseek\(\w+,\s*__COMPILER_HALT_OFFSET__\);((\$\w+="\\\\x[0-9a-f]+";)+(\$\w+="[^"]+";)+eval\("\?>"\.(\$\w+\()+"([^"]+)"\)+;)+(?:/\*\w+\*/)?__halt_compiler\(\);[\w#|>^%\[\.\]\\\\/=]+~msi',
            'id'   => 'Obf_20200527_1',
        ],
        [
            'full' => '~(\$\w+)=strrev\("[base64_decode]+"\)\.str_replace\(\'(\w+)\',\'\',\'\w+\'\);\s*eval\(\1\(\$\w+\)\);~msi',
            'fast' => '~(\$\w+)=strrev\("[base64_decode]+"\)\.str_replace\(\'(\w+)\',\'\',\'\w+\'\);\s*eval\(\1\(\$\w+\)\);~msi',
            'id'   => 'Obf_20200602_1',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*base64_decode\(\1\);\s*eval\(\3\);~msi',
            'fast' => '~(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*base64_decode\(\1\);\s*eval\(\3\);~msi',
            'id'   => 'Obf_20200720_1',
        ],
        [
            'full' => '~[\'".]+(\$\w+\s*=\s*[\'"]\w+[\'"];)+(\$\w+=\$\w+[\'.]+\$\w+;)+(\$\w+=(str_rot13|base64_decode|gzinflate)\(\$\w+\);)+eval\(\$\w+\);~msi',
            'fast' => '~[\'".]+(\$\w+\s*=\s*[\'"]\w+[\'"];)+(\$\w+=\$\w+[\'.]+\$\w+;)+(\$\w+=(str_rot13|base64_decode|gzinflate)\(\$\w+\);)+eval\(\$\w+\);~msi',
            'id'   => 'flamux',
        ],
        [
            'full' => '~function\s*(\w+)\(\)\{\s*return\s*"([^"]+)";\s*\}\s*eval\("([^"]+)"\.\1\(\)\."([^"]+)"\);~msi',
            'fast' => '~function\s*(\w+)\(\)\{\s*return\s*"([^"]+)";\s*\}\s*eval\("([^"]+)"\.\1\(\)\."([^"]+)"\);~msi',
            'id'   => 'bypass',
        ],
        [
            'full' => '~(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+(echo)\s*"(?:[<\w\\\\>\/\s={:}#]+);(?:[\\\\\w\-:]+;)+(?:[\\\\\w}:{\s#]+;)+(?:[\\\\\w}:{#\-\s]+;)+[\\\\\w}<\/]+";\$\w+=["\\\\\w]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";error_reporting\(\d\);\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;set_time_limit\(\d\);\$\w+=["\\\\\w]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+(if\(empty\()[\$_\w\["\\\\\]]+\)\){\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\w()]+;(}else{)\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;}chdir\(\${\$\w+}\);\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=htmlentities\(\$[_\w\["\\\\\].?]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);\1[<\\\\\w>\/"]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";(?:\$\w+=["\w\\\\]+;)+(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;)+\$\w+=["\w\\\\]+;\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["\\\\\w<>=\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=\s\/<>]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\1["<\\\\\w\s\'.\${}>\/]+;\1["<\\\\\w>\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."&\w\\\\\'<\/]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\1["<\\\\\w>\s=\'.\${}&\/]+;(?:\1["<\\\\\w>\/]+;)+\$\w+=["\\\\\w]+;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";switch\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){case"[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\$\w+=["\\\\\w]+;)+(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=fopen\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},"\w"\);\$\w+=["\\\\\w]+;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=(?:(?|fread|filesize)\(\${\$\w+},?)+\)\);\${\$\w+}=str_replace\("[\w\\\\\s]+",[<\w\\\\>"]+,\${\$\w+}\);\1["\\\\\w<>=\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=\s\/<>&\${}\']+;\1["\\\\\w\s.:]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\."[\w\\\\\s]+";\1["\\\\\w\s\'=]+\.\${\$\w+}\.["<\w\\\\>]+;\1["<\\\\\w>\s=\'\/;]+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";(?:\$\w+=["\w\\\\]+;)+\${\$\w+}=fopen\(\${\$\w+},"\w"\);if\(fwrite\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\s\\\\\w]+;\3\1["\\\\\w\s.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\\\\\w]+;}}fclose\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);(break;case")[\w\\\\\s]+":\${\$\w+}=[\$_\w\["\]\\\\]+;if\(unlink\([\${}\w]+\)\){\1\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\s\w\\\\.>]+;\3\$\w+=["\w\\\\]+;\1["\\\\\w\s.${}<]+;}\4[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\w\\\\\s=.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}.["\\\\\w&.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s=]+;(?:\1["\w\\\\:\s\'><=\/]+;)+\3(?:\$\w+=["\w\\\\]+;)+if\(copy\(\${\$\w+},\${\$\w+}\)\){\1"[\w\\\\\s]+";\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\'\\\\\w\s=>]+;\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\1["\\\\\w\s\'=>\/;]+\3if\(rename\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\$\w+=["\w\\\\]+;\1"[\w\\\\\s]+"\.\${\$\w+}[."\\\\\w>;]+}}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${\$\w+}=[\$_\w\["\]\\\\]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["\\\\\w\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\\\\\w=.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\\\\\w\s>]+;(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;)+\1["\\\\\w\s=\'<\/;]+\3if\(rename\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;if\(rmdir\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\$\w+=["\\\\\w]+;\1"[\w\\\\\s]+"\.\${\$\w+}[."\\\\\w]+;}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";system\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\$\w+=["\w\\\\]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\$\w+=["\w\\\\]+;if\(\${\$\w+}=fopen\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},"\w"\)\){\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;\3\$\w+=["\w\\\\]+;\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;}\$\w+=["\w\\\\]+;fclose\(\${\$\w+}\);}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${\$\w+}=basename\([\$_\w\["\\\\\]]+\);\2\${\$\w+}\)\){\1["<\\\\\w\s=\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["&\w\\\\\s=\/\-\'>]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";if\(move_uploaded_file\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;unlink\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);\3\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":\${\$\w+}=[\$_\w\["\]\\\\]+;\2\${\$\w+}\)\){(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=explode\(":",\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);if\(\(!is_numeric\(\${\$\w+}\[\d\]\)\)or\(!is_numeric\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\[\d\]\)\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3(?:\$\w+=["\w\\\\]+;)+\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\w\\\\]+;(?:\${\$\w+}=\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\[\d\];)+\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;while\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}<=\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=\d;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=fsockopen\(\$\w+,\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)or\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=\d;if\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}==\d\){\$\w+=["\\\\\w]+;echo\${\$\w+}\.["\\\\\w>]+;}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\+\+;fclose\(\${\$\w+}\);}}}break;}clearstatcache\(\);(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=scandir\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);foreach\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\s\w+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){if\(is_file\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=round\(filesize\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\/\d+,\d\);\$\w+=["\w\\\\]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\/\w\\\\>;]+\$\w+=["\\\\\w]+;\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s<\/>]+;\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=&]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\/<>;]+\$\w+=["\\\\\w]+;\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\${\$\w+}[.">\w\\\\\/<]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3(?:\$\w+=["\\\\\w]+;){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=scandir\(\${\$\w+}\);(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=count\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\-\d;\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\/\w+>";\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s=<\/]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;){3}}}\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;~msi',
            'fast' => '~(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+(echo)\s*"(?:[<\w\\\\>\/\s={:}#]+);(?:[\\\\\w\-:]+;)+(?:[\\\\\w}:{\s#]+;)+(?:[\\\\\w}:{#\-\s]+;)+[\\\\\w}<\/]+";\$\w+=["\\\\\w]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";error_reporting\(\d\);\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;set_time_limit\(\d\);\$\w+=["\\\\\w]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+(if\(empty\()[\$_\w\["\\\\\]]+\)\){\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\w()]+;(}else{)\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;}chdir\(\${\$\w+}\);\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=htmlentities\(\$[_\w\["\\\\\].?]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);\1[<\\\\\w>\/"]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";(?:\$\w+=["\w\\\\]+;)+(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;)+\$\w+=["\w\\\\]+;\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["\\\\\w<>=\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=\s\/<>]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\1["<\\\\\w\s\'.\${}>\/]+;\1["<\\\\\w>\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."&\w\\\\\'<\/]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\1["<\\\\\w>\s=\'.\${}&\/]+;(?:\1["<\\\\\w>\/]+;)+\$\w+=["\\\\\w]+;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";switch\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){case"[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\$\w+=["\\\\\w]+;)+(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=fopen\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},"\w"\);\$\w+=["\\\\\w]+;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=(?:(?|fread|filesize)\(\${\$\w+},?)+\)\);\${\$\w+}=str_replace\("[\w\\\\\s]+",[<\w\\\\>"]+,\${\$\w+}\);\1["\\\\\w<>=\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=\s\/<>&\${}\']+;\1["\\\\\w\s.:]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\."[\w\\\\\s]+";\1["\\\\\w\s\'=]+\.\${\$\w+}\.["<\w\\\\>]+;\1["<\\\\\w>\s=\'\/;]+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";(?:\$\w+=["\w\\\\]+;)+\${\$\w+}=fopen\(\${\$\w+},"\w"\);if\(fwrite\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\s\\\\\w]+;\3\1["\\\\\w\s.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\\\\\w]+;}}fclose\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);(break;case")[\w\\\\\s]+":\${\$\w+}=[\$_\w\["\]\\\\]+;if\(unlink\([\${}\w]+\)\){\1\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\s\w\\\\.>]+;\3\$\w+=["\w\\\\]+;\1["\\\\\w\s.${}<]+;}\4[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\w\\\\\s=.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}.["\\\\\w&.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s=]+;(?:\1["\w\\\\:\s\'><=\/]+;)+\3(?:\$\w+=["\w\\\\]+;)+if\(copy\(\${\$\w+},\${\$\w+}\)\){\1"[\w\\\\\s]+";\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\'\\\\\w\s=>]+;\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\1["\\\\\w\s\'=>\/;]+\3if\(rename\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\$\w+=["\w\\\\]+;\1"[\w\\\\\s]+"\.\${\$\w+}[."\\\\\w>;]+}}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${\$\w+}=[\$_\w\["\]\\\\]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["\\\\\w\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\\\\\w=.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\\\\\w\s>]+;(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;)+\1["\\\\\w\s=\'<\/;]+\3if\(rename\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;if\(rmdir\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\$\w+=["\\\\\w]+;\1"[\w\\\\\s]+"\.\${\$\w+}[."\\\\\w]+;}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";system\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\$\w+=["\w\\\\]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\$\w+=["\w\\\\]+;if\(\${\$\w+}=fopen\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},"\w"\)\){\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;\3\$\w+=["\w\\\\]+;\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;}\$\w+=["\w\\\\]+;fclose\(\${\$\w+}\);}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${\$\w+}=basename\([\$_\w\["\\\\\]]+\);\2\${\$\w+}\)\){\1["<\\\\\w\s=\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["&\w\\\\\s=\/\-\'>]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";if\(move_uploaded_file\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;unlink\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);\3\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":\${\$\w+}=[\$_\w\["\]\\\\]+;\2\${\$\w+}\)\){(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=explode\(":",\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);if\(\(!is_numeric\(\${\$\w+}\[\d\]\)\)or\(!is_numeric\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\[\d\]\)\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3(?:\$\w+=["\w\\\\]+;)+\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\w\\\\]+;(?:\${\$\w+}=\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\[\d\];)+\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;while\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}<=\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=\d;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=fsockopen\(\$\w+,\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)or\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=\d;if\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}==\d\){\$\w+=["\\\\\w]+;echo\${\$\w+}\.["\\\\\w>]+;}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\+\+;fclose\(\${\$\w+}\);}}}break;}clearstatcache\(\);(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=scandir\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);foreach\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\s\w+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){if\(is_file\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=round\(filesize\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\/\d+,\d\);\$\w+=["\w\\\\]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\/\w\\\\>;]+\$\w+=["\\\\\w]+;\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s<\/>]+;\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=&]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\/<>;]+\$\w+=["\\\\\w]+;\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\${\$\w+}[.">\w\\\\\/<]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3(?:\$\w+=["\\\\\w]+;){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=scandir\(\${\$\w+}\);(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=count\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\-\d;\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\/\w+>";\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s=<\/]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;){3}}}\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;~msi',
            'id'   => 'darkShell',
        ],
        [
            'full' => '~(\$\w+)=\'([\w\(;\$\)=\s\[\/\]."*]+)\';(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=\s+"([\'\w\/+=]+)";(\$\w+)\.=\4;\8\.=\6;\8\.=\5;@(\$\w+)=\3\(\(\'+\),\s+\(\8\)\);@\9\(\);~msi',
            'fast' => '~(\$\w+)=\'([\w\(;\$\)=\s\[\/\]."*]+)\';(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=\s+"([\'\w\/+=]+)";(\$\w+)\.=\4;\8\.=\6;\8\.=\5;@(\$\w+)=\3\(\(\'+\),\s+\(\8\)\);@\9\(\);~msi',
            'id'   => 'wso',
        ],
        [
            'full' => '~(?:(?:@?error_reporting|@?set_time_limit)\(\d+\);\s*){1,2}function\s*class_uc_key\((\$\w{1,50})\){\s*(\$\w{1,50})\s*=\s*strlen\s*\(trim\(\1\)\);\s*(\$\w{1,50})\s*=\s*\'\';\s*for\((\$\w{1,50})\s*=\s*0;\4\s*<\s*\2;\4\+=2\)\s*{\s*\3\s*\.=\s*pack\s*\("C",hexdec\s*\(substr\s\(\1,\4,2\)\)\);\s*}\s*return\s*\3;\s*}\s*header\("\w+-\w+:\s\w+\/\w+;\s*charset=(\w+)"\);\s*(\$\w{1,50})=(?:(?:class_uc_key\("(\w+)"\)|\$\w{1,50})\.?\s*)+\.\'([\w\/\+=\\\\]+\'\)\)\);)\';\s*(\$\w{1,50})=create_function\(\'\',\6\);\9\(\);~msi',
            'fast' => '~(?:(?:@?error_reporting|@?set_time_limit)\(\d+\);\s*){1,2}function\s*class_uc_key\((\$\w{1,50})\){\s*(\$\w{1,50})\s*=\s*strlen\s*\(trim\(\1\)\);\s*(\$\w{1,50})\s*=\s*\'\';\s*for\((\$\w{1,50})\s*=\s*0;\4\s*<\s*\2;\4\+=2\)\s*{\s*\3\s*\.=\s*pack\s*\("C",hexdec\s*\(substr\s\(\1,\4,2\)\)\);\s*}\s*return\s*\3;\s*}\s*header\("\w+-\w+:\s\w+\/\w+;\s*charset=(\w+)"\);\s*(\$\w{1,50})=(?:(?:class_uc_key\("(\w+)"\)|\$\w{1,50})\.?\s*)+\.\'([\w\/\+=\\\\]+\'\)\)\);)\';\s*(\$\w{1,50})=create_function\(\'\',\6\);\9\(\);~msi',
            'id'   => 'anonymousFox',
        ],
        [
            'full' => '~(\$my_sucuri_encoding)\s{0,10}=\s{0,10}[\'"]([^\'"]+)[\'"];\s{0,10}(\$tempb64)\s{0,10}=\s{0,10}base64_decode\(\s{0,10}\1\);\s{0,10}eval\(\s{0,10}\3\s{0,10}\);~msi',
            'fast' => '~(\$my_sucuri_encoding)\s{0,10}=\s{0,10}[\'"]([^\'"]+)[\'"];\s{0,10}(\$tempb64)\s{0,10}=\s{0,10}base64_decode\(\s{0,10}\1\);\s{0,10}eval\(\s{0,10}\3\s{0,10}\);~msi',
            'id'   => 'wsoEval',
        ],
        [
            'full' => '~\$fun\s=\s\'ass\';\$fun\s\.=\s\'ert\';@\$fun\(str_rot13\(\'(.*;)\'\)\);~msi',
            'fast' => '~\$fun\s=\s\'ass\';\$fun\s\.=\s\'ert\';@\$fun\(str_rot13\(\'(.*;)\'\)\);~msi',
            'id'   => 'assertStr',
        ],
        [
            'full' => '~(function\s\w+\(\$\w+,\$\w+,\$\w+\){return\sstr_replace\(\$\w+,\$\w+,\$\w+\);}\s?){3}(\$\w+)\s=\s\'(\w+)\';\s\2\s=\s(\w+)\(\'(\w+)\',\'\',\2\);\s(\$\w+)\s=\s\'(\w+)\';\s\6\s=\s\4\(\'(\w+)\',\'\',\6\);\s(\$\w+)\s=\s\'(\w+)\';\s\9\s=\s\4\(\'(\w+)\',\'\',\9\);\s(\$\w+)\s=\s\'(\$\w+)\';\s(\$\w+)\s=\s\6\(\12,\9\.\'\(\'\.\2\.\'\(\'\.\12\.\'\)\);\'\);\s\14\(\'(\w+)\'\);~msi',
            'fast' => '~(function\s\w+\(\$\w+,\$\w+,\$\w+\){return\sstr_replace\(\$\w+,\$\w+,\$\w+\);}\s?){3}(\$\w+)\s=\s\'(\w+)\';\s\2\s=\s(\w+)\(\'(\w+)\',\'\',\2\);\s(\$\w+)\s=\s\'(\w+)\';\s\6\s=\s\4\(\'(\w+)\',\'\',\6\);\s(\$\w+)\s=\s\'(\w+)\';\s\9\s=\s\4\(\'(\w+)\',\'\',\9\);\s(\$\w+)\s=\s\'(\$\w+)\';\s(\$\w+)\s=\s\6\(\12,\9\.\'\(\'\.\2\.\'\(\'\.\12\.\'\)\);\'\);\s\14\(\'(\w+)\'\);~msi',
            'id'   => 'funcVar',
        ],
        [
            'full' => '~(\$\w+)=[\'"]([\w</,\s()\$\+}\\\\\'"?\[\]{;%=^&-]+)[\'"];(\$\w+=(?:\s?\1\[\d+\](?:\s?\.?))+;)+((?:\$\w+\(\d+\);)?(\$\w+=(\$\w+)\(["\']{2},(\$\w+\(\$\w+\(["\'][=\w\+\/]+[\'"]\)\))\);\$\w+\(\);|.*?if\s?\(isset\(\${(?:\$\w+\[\d+\]\.?)+}.*?function\s\w+.*?include\s\${(?:\$\w+\[\d+\]\.?)+}\[(?:\$\w+\[\d+\]\.?)+\];\s?}))~msi',
            'fast' => '~(\$\w+)=[\'"]([\w</,\s()\$\+}\\\\\'"?\[\]{;%=^&-]+)[\'"];(\$\w+=(?:\s?\1\[\d+\](?:\s?\.?))+;)+((?:\$\w+\(\d+\);)?(\$\w+=(\$\w+)\(["\']{2},(\$\w+\(\$\w+\(["\'][=\w\+\/]+[\'"]\)\))\);\$\w+\(\);|.*?if\s?\(isset\(\${(?:\$\w+\[\d+\]\.?)+}.*?function\s\w+.*?include\s\${(?:\$\w+\[\d+\]\.?)+}\[(?:\$\w+\[\d+\]\.?)+\];\s?}))~msi',
            'id'   => 'dictionaryVars',
        ],
        [
            'full' => '~(?:(?<concatVar>\$\w+)\s?=\s?""\s?;((?:\s?(?P=concatVar)\s?\.=\s?"[\w]+"\s?;\s?)+))?(\$\w+)\s?=\s?(?:(?P=concatVar)|"(?<strVal>[\w]+)")\s?;\s?if\s?\(\s?!function_exists\s?\(\s?"(\w+)"\)\){function\s\5\(\s?(\$\w+)\){\s?(?:\$\w+=\s?""\s?;)?\s?(\$\w+)\s?=\s?strlen\s?\(\s?\6\s?\)\s?\/\s?2\s?;\s?for\s?\(\s?(\$\w+)\s?=0\s?;\s?\8\s?<\s?\7\s?;\s?\8\+\+\s?\)\s?{\s?\$\w+\s?\.=\s?chr\s?\(\s?base_convert\s?\(\s?substr\s?\(\s?\6\s?,\s?\8\s?\*\s?2\s?,\s?2\s?\)\s?,\s?16\s?,\s?10\s?\)\s?\)\s?;\s?}\s?return\s?\$\w+;\s?}\s?}\s?\$\w+\s?=\s?create_function\s?\(\s?null\s?,\s?\5\(\s?\3\)\)\s?;\s?\3\(\)\s?;~msi',
            'fast' => '~(?:(?<concatVar>\$\w+)\s?=\s?""\s?;((?:\s?(?P=concatVar)\s?\.=\s?"[\w]+"\s?;\s?)+))?(\$\w+)\s?=\s?(?:(?P=concatVar)|"(?<strVal>[\w]+)")\s?;\s?if\s?\(\s?!function_exists\s?\(\s?"(\w+)"\)\){function\s\5\(\s?(\$\w+)\){\s?(?:\$\w+=\s?""\s?;)?\s?(\$\w+)\s?=\s?strlen\s?\(\s?\6\s?\)\s?\/\s?2\s?;\s?for\s?\(\s?(\$\w+)\s?=0\s?;\s?\8\s?<\s?\7\s?;\s?\8\+\+\s?\)\s?{\s?\$\w+\s?\.=\s?chr\s?\(\s?base_convert\s?\(\s?substr\s?\(\s?\6\s?,\s?\8\s?\*\s?2\s?,\s?2\s?\)\s?,\s?16\s?,\s?10\s?\)\s?\)\s?;\s?}\s?return\s?\$\w+;\s?}\s?}\s?\$\w+\s?=\s?create_function\s?\(\s?null\s?,\s?\5\(\s?\3\)\)\s?;\s?\3\(\)\s?;~msi',
            'id'   => 'concatVarFunc',
        ],
        [
            'full' => '~function\s?(\w+)\(\){(((\$\w+)\.?="\w+";)+)return\seval\(\4\(\w+\(\)\)\);}function\s(\w+)\((\$\w+)\){((?:(\$\w+)\.?="\w+";)+)return\s\8\(\6\);}function\s?(\w+)\(\){((\$\w+)\.?="([\w\/+=]+)";)return\s(\w+)\(\11\);}function\s\13\((\$\w+)\){(\$\w+)=(\w+)\((\w+)\((\w+)\(\14\)\)\);return\s\15;}function\s\17\(\14\){(((\$\w+)\.?="\w+";)+)return\s\21\(\14\);}\1\(\);function\s\16\(\14\){(((\$\w+)\.?="\w+";)+)return\s\24\(\14\);}~msi',
            'fast' => '~function\s?(\w+)\(\){(((\$\w+)\.?="\w+";)+)return\seval\(\4\(\w+\(\)\)\);}function\s(\w+)\((\$\w+)\){((?:(\$\w+)\.?="\w+";)+)return\s\8\(\6\);}function\s?(\w+)\(\){((\$\w+)\.?="([\w\/+=]+)";)return\s(\w+)\(\11\);}function\s\13\((\$\w+)\){(\$\w+)=(\w+)\((\w+)\((\w+)\(\14\)\)\);return\s\15;}function\s\17\(\14\){(((\$\w+)\.?="\w+";)+)return\s\21\(\14\);}\1\(\);function\s\16\(\14\){(((\$\w+)\.?="\w+";)+)return\s\24\(\14\);}~msi',
            'id'   => 'concatVarFuncFunc',
        ],
        [
            'full' => '~(?:(?:\s?\$\w+\s?=\s?strrev\("\w+"\);\s?)|(?:\s?\$\w+\s?=\s?strrev\("\w+"\);\s?)|(?:\s?eval\((?:\$\w+)?\([\'"][\w=]+[\'"]\)\);\s?)|(?:\s?eval\(\$\w+\(\$\w+\(\'[\w\/+=]+\'\)\)\);\s?)){3,4}~msi',
            'fast' => '~(?:(?:\s?\$\w+\s?=\s?strrev\("\w+"\);\s?)|(?:\s?\$\w+\s?=\s?strrev\("\w+"\);\s?)|(?:\s?eval\((?:\$\w+)?\([\'"][\w=]+[\'"]\)\);\s?)|(?:\s?eval\(\$\w+\(\$\w+\(\'[\w\/+=]+\'\)\)\);\s?)){3,4}~msi',
            'id'   => 'evalVarDoubled',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?(\w+)\("([\w+\/=]+)"\);\s?echo\s?\1;~msi',
            'fast' => '~(\$\w+)\s?=\s?(\w+)\("([\w+\/=]+)"\);\s?echo\s?\1;~msi',
            'id'   => 'varFuncsEcho',
        ],
        [
            'full' => '~(\$\w+)="";\s*(?:(?:do\s?{[^}]+}\s?while\s?\(\d+>\d+\);\s*\1=\1\."[^"]+";)?(?:.*?)(\$\w+)=(\d+);\s?(?:.*?)(\$\w+)=((?:\'[\w%]+\'\.?)+);\s?(?:.*?)\s(\$\w+)=((?:\4\[?{?\d+\]?}?\.?)+);\s?)?(?:function\s\w+\(\){(?:.*?);\s}\s?\1=\w+\(\1,"\w+"\);\s?|\$\w+=array\((?:\'\w+\',?)+\);\s?|\1=\w+\(\1,\sjoin\(\'\',\s\$\w+\)\s?\);\s?|\s?\$\w+\+=\d+;\s?|\1=\w+\(\1,\w+\(\)\);\s?|function\s\w+\(\){\s?|do{\s?if\s?\(\d+<\d+\)\s?{\s?|)+(?:.*?)(?:\$\w+\s?=\s?\$\w+\([\'"]{2},\s?\$\w+\(\$\w+(?:\(\1\),\s?(?:\$\w+\[\'\w+\'\]\)\s?)?|\)\s?)\);\s?\$\w+\(\);)(?:\s?function\s\w+\((?:\$\w+,\s?\$\w+)?\)(?:.*?);\s}|\s?class\s\w+\s?{(?:.*?);(?:\s}){1,2})+~msi',
            'fast' => '~function\s+\w+\(\)\{\s*global\s*(\$\w+);\s*return\s*(\1[\[{]\d+[\]}]\.?){15};\s*}~msi',
            'id'   => 'varFuncsMany',
        ],
        [
            'full' => '~((\$(?:GLOBALS|{"[\\\\\w]+"})\[[\'"]\w+["\']\])\s?=\s?[\'"]+([\\\\\w]+)["\'];)\s?(?:(\$GLOBALS\[?(\s?(?:\2|\$GLOBALS\[\'\w+\'\])\[\d+\]\.?)+\])\s?=\s?\g<5>+;\s?)+(?:\g<4>\s?=\s[\$_\w]+;\s)+(?:@\g<4>\(\g<5>+\s?,\s?\w+\s?\);\s?)+@\g<4>\(\d+\);\s{0,50}(?:if\s?\(!\g<4>\s?\(\g<5>+\)\)\s{\s{0,50}\g<4>\(\g<5>+,\s\g<5>*\d*\);\s{0,50}}?\s{0,50})*(?:\$\w+\s?=\s?\w+;\s?)*\g<4>\s?=\s\g<5>+;\s?global\s?\$\w+;\s?function\s\w+\(\$\w+,\s\$\w+\)\s{\s?\$\w+\s?=\s?["\']{2};\s?for\s?\(\$\w+\s?=\d+;\s?\$\w+\s?<\s?\g<4>\(\$\w+\)\s?;\s?\)\s?{\s?for\s?\(\s?\$\w+=\d+;\s?\$\w+\s?<\s?\g<4>\(\$\w+\)\s?&&\s?\$\w+\s?<\g<4>\(\$\w+\);\s?\$\w+\+{2},\s?\$\w+\+{2}\)\s?{\s?\$\w+\s?\.=\s?\g<4>\(\g<4>\(\$\w+\[\$\w+\]\)\s?\^\s?\g<4>\(\$\w+\[\$\w+\]\)\);\s?}\s?}\s?return\s\$\w+;\s?}\s?function\s?\w+\(\$\w+,\s?\$\w+\)\s?{\s?global\s?\$\w+;\s?return\s\g<4>\(\g<4>\(\$\w+,\s?\$\w+\),\s?\$\w+\)\s?;\s?}\s?foreach\s?\(\g<4>\sas\s\$\w+=>\$\w+\)\s?{\s?\$\w+\s?=\s?\$\w+;\s?\$\w+\s?=\s?\$\w+;\s?}\s?if\s?\(!\$\w+\)\s?{\s?foreach\s?\(\g<4>\sas\s\$\w+\s?=>\s?\$\w+\)\s?{\s?\$\w+\s?=\s?\$\w+;\s?\$\w+\s?=\s?\$\w+;\s?}\s?}\s?\$\w+\s?=\s?@\g<4>\(\g<4>\(@?\g<4>\(\$\w+\),\s?\$\w+\)\);\s?if\s?\(isset\(\$\w+\[\g<5>+\]\)\s?&&\s?\$\w+==\$\w+\[\g<5>+\]\)\s?{\s?if\s?\(\$\w+\[\g<5>\]\s?==\s?\g<5>\)\s?{\s?\$\w+\s?=\s?array\(\s?\g<5>+\s?=>\s?@\g<4>\(\),\s?\g<5>+\s?=>\s?\g<5>+,\s?\);\s?echo\s?@\g<4>\(\$\w+\);\s?}\s?elseif\s?\(\$\w+\[\g<5>\]\s?==\s?\g<5>\)\s?{\s?eval\(\$\w+\[\g<5>\]\);\s?}\s?(?:exit\(\);)?\s?}\s?}?~msi',
            'fast' => '~((\$(?:GLOBALS|{"[\\\\\w]+"})\[[\'"]\w+["\']\])\s?=\s?[\'"]+([\\\\\w]+)["\'];)\s?(?:(\$GLOBALS\[?(\s?(?:\2|\$GLOBALS\[\'\w+\'\])\[\d+\]\.?)+\])\s?=\s?\g<5>+;\s?)+(?:\g<4>\s?=\s[\$_\w]+;\s)+(?:@\g<4>\(\g<5>+\s?,\s?\w+\s?\);\s?)+@\g<4>\(\d+\);\s{0,50}(?:if\s?\(!\g<4>\s?\(\g<5>+\)\)\s{\s{0,50}\g<4>\(\g<5>+,\s\g<5>*\d*\);\s{0,50}}?\s{0,50})*(?:\$\w+\s?=\s?\w+;\s?)*\g<4>\s?=\s\g<5>+;\s?global\s?\$\w+;\s?function\s\w+\(\$\w+,\s\$\w+\)\s{\s?\$\w+\s?=\s?["\']{2};\s?for\s?\(\$\w+\s?=\d+;\s?\$\w+\s?<\s?\g<4>\(\$\w+\)\s?;\s?\)\s?{\s?for\s?\(\s?\$\w+=\d+;\s?\$\w+\s?<\s?\g<4>\(\$\w+\)\s?&&\s?\$\w+\s?<\g<4>\(\$\w+\);\s?\$\w+\+{2},\s?\$\w+\+{2}\)\s?{\s?\$\w+\s?\.=\s?\g<4>\(\g<4>\(\$\w+\[\$\w+\]\)\s?\^\s?\g<4>\(\$\w+\[\$\w+\]\)\);\s?}\s?}\s?return\s\$\w+;\s?}\s?function\s?\w+\(\$\w+,\s?\$\w+\)\s?{\s?global\s?\$\w+;\s?return\s\g<4>\(\g<4>\(\$\w+,\s?\$\w+\),\s?\$\w+\)\s?;\s?}\s?foreach\s?\(\g<4>\sas\s\$\w+=>\$\w+\)\s?{\s?\$\w+\s?=\s?\$\w+;\s?\$\w+\s?=\s?\$\w+;\s?}\s?if\s?\(!\$\w+\)\s?{\s?foreach\s?\(\g<4>\sas\s\$\w+\s?=>\s?\$\w+\)\s?{\s?\$\w+\s?=\s?\$\w+;\s?\$\w+\s?=\s?\$\w+;\s?}\s?}\s?\$\w+\s?=\s?@\g<4>\(\g<4>\(@?\g<4>\(\$\w+\),\s?\$\w+\)\);\s?if\s?\(isset\(\$\w+\[\g<5>+\]\)\s?&&\s?\$\w+==\$\w+\[\g<5>+\]\)\s?{\s?if\s?\(\$\w+\[\g<5>\]\s?==\s?\g<5>\)\s?{\s?\$\w+\s?=\s?array\(\s?\g<5>+\s?=>\s?@\g<4>\(\),\s?\g<5>+\s?=>\s?\g<5>+,\s?\);\s?echo\s?@\g<4>\(\$\w+\);\s?}\s?elseif\s?\(\$\w+\[\g<5>\]\s?==\s?\g<5>\)\s?{\s?eval\(\$\w+\[\g<5>\]\);\s?}\s?(?:exit\(\);)?\s?}\s?}?~msi',
            'id'   => 'globalArrayEval',
        ],
        [
            'full' => '~<\?php\s{0,30}(\$\w+)\s{0,30}=\s{0,30}"(.+?)";\s{0,30}((?:\$\w+\s{0,30}=\s{0,30}(?:\1\[\'\w\s{0,30}\'\s{0,30}\+\s{0,30}\d+\s{0,30}\+\s{0,30}\'\s{0,30}\w\'\]\s{0,30}\.?\s{0,30})+;\s{0,30})+)(\$\w+)\s{0,30}=\s{0,30}"(\d+)";\s{0,30}(?:\$\w+\s{0,30}=\s{0,30}\$\w+\(\s{0,30}\$\w+\s{0,30},\s{0,30}\$\w+\(\s{0,30}"\s{0,30}"\)\s{0,30},\s{0,30}"[\w\+]+"\)\s{0,30};\s{0,30})+(?:\$\w+\s{0,30}=\s{0,30}\$\w+\(\s{0,30}\$\w+\(\s{0,30}\$\w+\)\s{0,30},\s{0,30}\$\w+\(\s{0,30}?\$\w+\)\s{0,30}\)\s{0,30};\s{0,30})+\$\w+\((?:\s{0,30}\$\w+\(\s{0,30}"\s{0,20}\w\s{0,20}"\)\s{0,30}\.?\s{0,30})+"\(\\\\"\w+\\\\"\s{0,30},\s{0,30}"\s{0,30}\.\s{0,30}\$\w+\(\s{0,30}\$\w+\(\s{0,30}"\d+"\s{0,30},\s{0,30}\$\w+\(\s{0,30}"\s{0,20}"\)\s{0,30},\s{0,30}"[\d\w=]+"\)\s{0,30}\)\s{0,30}\.\s{0,30}"\s{0,30}\)\s{0,30};"\)\s{0,30};\s{0,30}\$\w+\s{0,30}=\s{0,30}\$\w+\(\w+\)\s{0,30};\s{0,30}\$\w+\(\s{0,30}(?:\$\w+\(\s{0,30}"\s{0,30}[?>]\s{0,30}"\)\s{0,30}\.\s{0,30})+(\$\w+)\(\s{0,30}(\$\w+)\(\s{0,30}(\$\w+),\s{0,30}(\$\w+)\(\s{0,30}"\s{0,30}"\)\s{0,30},\s{0,30}(\$\w+)\(\s{0,30}"([()\w@|*#\[\]&\/\+=]+)"\s{0,30},\s{0,30}(\$\w+),\s{0,30}(\$\w+)\)\s{0,30}\)\)\s{0,30}\)\s{0,30};\s{0,30}\$\w+\s?=\s?\d+\s?;\s{0,30}\?>~msi',
            'fast' => '~<\?php\s{0,30}(\$\w+)\s{0,30}=\s{0,30}"(.+?)";\s{0,30}((?:\$\w+\s{0,30}=\s{0,30}(?:\1\[\'\w\s{0,30}\'\s{0,30}\+\s{0,30}\d+\s{0,30}\+\s{0,30}\'\s{0,30}\w\'\]\s{0,30}\.?\s{0,30})+;\s{0,30})+)(\$\w+)\s{0,30}=\s{0,30}"(\d+)";\s{0,30}(?:\$\w+\s{0,30}=\s{0,30}\$\w+\(\s{0,30}\$\w+\s{0,30},\s{0,30}\$\w+\(\s{0,30}"\s{0,30}"\)\s{0,30},\s{0,30}"[\w\+]+"\)\s{0,30};\s{0,30})+(?:\$\w+\s{0,30}=\s{0,30}\$\w+\(\s{0,30}\$\w+\(\s{0,30}\$\w+\)\s{0,30},\s{0,30}\$\w+\(\s{0,30}?\$\w+\)\s{0,30}\)\s{0,30};\s{0,30})+\$\w+\((?:\s{0,30}\$\w+\(\s{0,30}"\s{0,20}\w\s{0,20}"\)\s{0,30}\.?\s{0,30})+"\(\\\\"\w+\\\\"\s{0,30},\s{0,30}"\s{0,30}\.\s{0,30}\$\w+\(\s{0,30}\$\w+\(\s{0,30}"\d+"\s{0,30},\s{0,30}\$\w+\(\s{0,30}"\s{0,20}"\)\s{0,30},\s{0,30}"[\d\w=]+"\)\s{0,30}\)\s{0,30}\.\s{0,30}"\s{0,30}\)\s{0,30};"\)\s{0,30};\s{0,30}\$\w+\s{0,30}=\s{0,30}\$\w+\(\w+\)\s{0,30};\s{0,30}\$\w+\(\s{0,30}(?:\$\w+\(\s{0,30}"\s{0,30}[?>]\s{0,30}"\)\s{0,30}\.\s{0,30})+(\$\w+)\(\s{0,30}(\$\w+)\(\s{0,30}(\$\w+),\s{0,30}(\$\w+)\(\s{0,30}"\s{0,30}"\)\s{0,30},\s{0,30}(\$\w+)\(\s{0,30}"([()\w@|*#\[\]&\/\+=]+)"\s{0,30},\s{0,30}(\$\w+),\s{0,30}(\$\w+)\)\s{0,30}\)\)\s{0,30}\)\s{0,30};\s{0,30}\$\w+\s?=\s?\d+\s?;\s{0,30}\?>~msi',
            'id'   => 'tinkleShell',
        ],
        [
            'full' => '~(?:\$\w+="\w+";)+(\$\w+)="([\w_)(;\/\.*]+)";\$\w+="\w+";function\s(\w+)\((?:\$\w+,?){3}\){return\s?""(?:\.\$\w+\.""){3};}(?:\$\w+=(?:(?:"\w+")|(?:\3\((?:\1\[\d+\],?\.?)+\))|(?:(?:\3\()+(?:\$\w+\,?(?:\)\,)?)+)(?:(?:(?:\3\()+)*(?:(?:\$\w+,?)+)*(?:\),)*(?:\)*))+);)+\$\w+=\3\((?:\1\[\d+\]\.?)+(?:,"")+\);(?:\$\w+=\3\(\3\(\$\w+,\$\w+,\$\w+\),\3\((?:\$\w+,?)+\),\3\(\$\w+,\3\(\$\w+,\$\w+,""\),\$\w+\)\)\."\'(?<str>[\w\/\+]+)\'")\.\3\((?:\1\[\d+\],?\.?)+\);\$\w+\(\$\w+,array\("","}"\.\$\w+\."\/+"\)\);~msi',
            'fast' => '~(?:\$\w+="\w+";)+(\$\w+)="([\w_)(;\/\.*]+)";\$\w+="\w+";function\s(\w+)\((?:\$\w+,?){3}\){return\s?""(?:\.\$\w+\.""){3};}(?:\$\w+=(?:(?:"\w+")|(?:\3\((?:\1\[\d+\],?\.?)+\))|(?:(?:\3\()+(?:\$\w+\,?(?:\)\,)?)+)(?:(?:(?:\3\()+)*(?:(?:\$\w+,?)+)*(?:\),)*(?:\)*))+);)+\$\w+=\3\((?:\1\[\d+\]\.?)+(?:,"")+\);(?:\$\w+=\3\(\3\(\$\w+,\$\w+,\$\w+\),\3\((?:\$\w+,?)+\),\3\(\$\w+,\3\(\$\w+,\$\w+,""\),\$\w+\)\)\."\'(?<str>[\w\/\+]+)\'")\.\3\((?:\1\[\d+\],?\.?)+\);\$\w+\(\$\w+,array\("","}"\.\$\w+\."\/+"\)\);~msi',
            'id'   => 'wsoFunc',
        ],
        [
            'full' => '~\$\w+\[\'\w+\'\]\s?=\s?"[\w;\/\.*)(]+";\s?\$\w+\[\'\w+\'\]\s?=\s?(?:\$\w+\[\'\w+\'\]\[\d+\]\.?)+;\s?\$\w+\s?=\s?(?:"[\w()]*"\.chr\([\d-]+\)\.?)+"\(";\s?\$\w+\s?=\s?"[)\\\\\w;]+";\s?\$\w+\s?=\s?\$\w+\."\'(?<str>[\w\/\+]+)\'"\.\$\w+;\s?\$\w+\[\'\w+\'\]\((?:\$\w+\[\'\w+\'\]\[\d+\]\.?)+,\s?\$\w+\s?,"\d+"\);~msi',
            'fast' => '~\$\w+\[\'\w+\'\]\s?=\s?"[\w;\/\.*)(]+";\s?\$\w+\[\'\w+\'\]\s?=\s?(?:\$\w+\[\'\w+\'\]\[\d+\]\.?)+;\s?\$\w+\s?=\s?(?:"[\w()]*"\.chr\([\d-]+\)\.?)+"\(";\s?\$\w+\s?=\s?"[)\\\\\w;]+";\s?\$\w+\s?=\s?\$\w+\."\'(?<str>[\w\/\+]+)\'"\.\$\w+;\s?\$\w+\[\'\w+\'\]\((?:\$\w+\[\'\w+\'\]\[\d+\]\.?)+,\s?\$\w+\s?,"\d+"\);~msi',
            'id'   => 'wsoFunc',
        ],
        [
            'full' => '~function\s(\w+)\((\$\w+)\)\s{0,50}{\s{0,50}\2=gzinflate\(base64_decode\(\2\)\);\s{0,50}for\((\$\w+)=\d+;\3<strlen\(\2\);\3\+\+\)\s{0,50}{\s{0,50}\2\[\3\]\s?=\s?chr\(ord\(\2\[\3\]\)-(\d+)\);\s{0,50}}\s{0,50}return\s?\2;\s{0,50}}\s{0,50}eval\(\1\([\'"]([\w\+\/=]+)[\'"]\)\);~msi',
            'fast' => '~function\s(\w+)\((\$\w+)\)\s{0,50}{\s{0,50}\2=gzinflate\(base64_decode\(\2\)\);\s{0,50}for\((\$\w+)=\d+;\3<strlen\(\2\);\3\+\+\)\s{0,50}{\s{0,50}\2\[\3\]\s?=\s?chr\(ord\(\2\[\3\]\)-(\d+)\);\s{0,50}}\s{0,50}return\s?\2;\s{0,50}}\s{0,50}eval\(\1\([\'"]([\w\+\/=]+)[\'"]\)\);~msi',
            'id'   => 'evalWanFunc',
        ],
        [
            'full' => '~(?:(?:if\s?\(file_exists\("\w+"\)\)\s?{\s?}\s?else\s?{\s?)?\$\w+\s?=\s?fopen\([\'"][^\'"]+\.php[\'"],\s?[\'"]w[\'"]\);)?\s?(\$\w+)\s?=\s?(?:base64_decode\()?[\'"]([^\'"]+)[\'"]\)?;\s?(?:\$\w{1,50}\s?=\s?fopen\([\'"][^\'"]+[\'"],\s?[\'"]\w[\'"]\);\s?)?(?:echo\s?)?fwrite\(\$\w{1,50}\s?,(?:base64_decode\()?\$\w{1,50}\)?\);\s?fclose\(\$\w{1,50}\);\s?}?~msi',
            'fast' => '~(?:(?:if\s?\(file_exists\("\w+"\)\)\s?{\s?}\s?else\s?{\s?)?\$\w+\s?=\s?fopen\([\'"][^\'"]+\.php[\'"],\s?[\'"]w[\'"]\);)?\s?(\$\w+)\s?=\s?(?:base64_decode\()?[\'"]([^\'"]+)[\'"]\)?;\s?(?:\$\w{1,50}\s?=\s?fopen\([\'"][^\'"]+[\'"],\s?[\'"]\w[\'"]\);\s?)?(?:echo\s?)?fwrite\(\$\w{1,50}\s?,(?:base64_decode\()?\$\w{1,50}\)?\);\s?fclose\(\$\w{1,50}\);\s?}?~msi',
            'id'   => 'funcFile',
        ],
        [
                'full' => '~(\$(?:GLOBALS\[\')?\w+(?:\'\])?\s{0,100}=\s{0,100}array\(\s{0,100}(?:\s{0,100}\'[^\']+\'\s{0,100}=>\s{0,100}\'?[^\']+\'?,\s{0,100})+\s{0,100}\);\s{0,100}((?:\$\w+=(?:[\'"][^\'"]*[\'"]\.?)+;)+)(?:if\(!\$\w+\((?:\'\w*\'\.?|\$\w+)+\)\){function\s{0,100}\w+\(\$\w+\){.*?else{function\s{0,100}\w+\(\$\w+\){.*?return\s{0,100}\$\w+\(\$\w+\);}}){2})\$\w+=(?:\'\w*\'\.?)+;(\$\w+)\s{0,100}=\s{0,100}@?\$\w+\(\'\$\w+\',\$\w+\.\'\(.\.\$\w+\.(?:\'[\w(\$);]*\'\.?)+\);\3\("([^"]+)"\);~msi',
            'fast' => '~(\$(?:GLOBALS\[\')?\w+(?:\'\])?\s{0,100}=\s{0,100}array\(\s{0,100}(?:\s{0,100}\'[^\']+\'\s{0,100}=>\s{0,100}\'?[^\']+\'?,\s{0,100})+\s{0,100}\);\s{0,100}((?:\$\w+=(?:[\'"][^\'"]*[\'"]\.?)+;)+)(?:if\(!\$\w+\((?:\'\w*\'\.?|\$\w+)+\)\){function\s{0,100}\w+\(\$\w+\){.*?else{function\s{0,100}\w+\(\$\w+\){.*?return\s{0,100}\$\w+\(\$\w+\);}}){2})\$\w+=(?:\'\w*\'\.?)+;(\$\w+)\s{0,100}=\s{0,100}@?\$\w+\(\'\$\w+\',\$\w+\.\'\(.\.\$\w+\.(?:\'[\w(\$);]*\'\.?)+\);\3\("([^"]+)"\);~msi',
            'id'   => 'gulf',
        ],
        [
            'full' => '~(\$\w+)=(\w+);\$\w+="(.+?)";(?:\$\w+=\$\w+;)?(\$\w+)=strlen\(\$\w+\);(\$\w+)=[\'"]{2};for\((\$\w+)=\d+;\6<\4;\6\+\+\)\s?\5\s?\.=\s?chr\(ord\(\$\w+\[\6\]\)\s?\^\s?\1\);eval\("\?>"\.\5\."<\?"\);~msi',
            'fast' => '~(\$\w+)=(\w+);\$\w+="(.+?)";(?:\$\w+=\$\w+;)?(\$\w+)=strlen\(\$\w+\);(\$\w+)=[\'"]{2};for\((\$\w+)=\d+;\6<\4;\6\+\+\)\s?\5\s?\.=\s?chr\(ord\(\$\w+\[\6\]\)\s?\^\s?\1\);eval\("\?>"\.\5\."<\?"\);~msi',
            'id'   => 'evalConcatAsciiChars',
        ],
        [
            'full' => '~(?:\$\w+="[\w=]+";\s?)+(\$\w+)\s?=\s?str_replace\((?:"\w*",?)+\);\s?(\$\w+)\s?=\s?\1\((?:"\w*",?\s?)+\);\s?(\$\w+)\s?=\s?\1\((?:"\w*",?)+\);\s?(\$\w+)\s?=\s?\3\("",\s?(\2\(\2\((\1\("([#;*,\.]+)",\s?"",\s?((?:\$\w+\.?)+)\))\)\))\);\s?\4\(\);~msi',
            'fast' => '~(?:\$\w+="[\w=]+";\s?)+(\$\w+)\s?=\s?str_replace\((?:"\w*",?)+\);\s?(\$\w+)\s?=\s?\1\((?:"\w*",?\s?)+\);\s?(\$\w+)\s?=\s?\1\((?:"\w*",?)+\);\s?(\$\w+)\s?=\s?\3\("",\s?(\2\(\2\((\1\("([#;*,\.]+)",\s?"",\s?((?:\$\w+\.?)+)\))\)\))\);\s?\4\(\);~msi',
            'id'   => 'evalPost',
        ],
        [
            'full' => '~\$\w+\s?=\s?"e\/\*\.\/";\spreg_replace\(strrev\(\$\w+\),"([\\\\\w]+)\'([\w\/\+=]+)\'([\\\\\w]+)","\."\);~msi',
            'fast' => '~\$\w+\s?=\s?"e\/\*\.\/";\spreg_replace\(strrev\(\$\w+\),"([\\\\\w]+)\'([\w\/\+=]+)\'([\\\\\w]+)","\."\);~msi',
            'id'   => 'evalPregStr',
        ],
        [
            'full' => '~\$GLOBALS\[\'\w+\'\]=array\(\'preg_re\'\s?\.\'place\'\);\s?function\s\w+\(\$\w+\)\s?{\$\w+=array\("\/\.\*\/e","([\\\\\w]+)\'([\w\/\+]+)\'([\\\\\w]+)","{2}\);\s?return\s\$\w+\[\$\w+\];}\s?\$GLOBALS\[\'\w+\'\]\[\d+\]\(\w+\(\d+\),\w+\(\d+\),\w+\(\d+\)\);~msi',
            'fast' => '~\$GLOBALS\[\'\w+\'\]=array\(\'preg_re\'\s?\.\'place\'\);\s?function\s\w+\(\$\w+\)\s?{\$\w+=array\("\/\.\*\/e","([\\\\\w]+)\'([\w\/\+]+)\'([\\\\\w]+)","{2}\);\s?return\s\$\w+\[\$\w+\];}\s?\$GLOBALS\[\'\w+\'\]\[\d+\]\(\w+\(\d+\),\w+\(\d+\),\w+\(\d+\)\);~msi',
            'id'   => 'evalPregStr',
        ],
        [
            'full' => '~class\s?\w+{\s?function\s?__destruct\(\){\s?\$this->\w+\(\'([\w&]+)\'\^"([\\\\\w]+)",array\(\(\'([#\w]+)\'\^"([\\\\\w]+)"\)\."\(base64_decode\(\'([\w\+\/=]+)\'\)\);"\)\);\s?}\s?function\s?\w+\(\$\w+,\$\w+\){\s?@array_map\(\$\w+,\$\w+\);\s?}\s?}\s?\$\w+\s?=\s?new\s?\w+\(\);~msi',
            'fast' => '~class\s?\w+{\s?function\s?__destruct\(\){\s?\$this->\w+\(\'([\w&]+)\'\^"([\\\\\w]+)",array\(\(\'([#\w]+)\'\^"([\\\\\w]+)"\)\."\(base64_decode\(\'([\w\+\/=]+)\'\)\);"\)\);\s?}\s?function\s?\w+\(\$\w+,\$\w+\){\s?@array_map\(\$\w+,\$\w+\);\s?}\s?}\s?\$\w+\s?=\s?new\s?\w+\(\);~msi',
            'id'   => 'classDestructFunc',
        ],
        [
            'full' => '~\$\w+="([\\\\\w]+)";\s?\$\w+=\$\w+\(\'([\w\+\/=]+)\'\);\s?\$\w+\s?=\s?"([\\\\\w]+)";\s?\$\w+\s?=\s?\$\w+\([\'"]{2}.\s?eval\(\$\w+\)\);\s?\$\w+\([\'"]{2}\);~msi',
            'fast' => '~\$\w+="([\\\\\w]+)";\s?\$\w+=\$\w+\(\'([\w\+\/=]+)\'\);\s?\$\w+\s?=\s?"([\\\\\w]+)";\s?\$\w+\s?=\s?\$\w+\([\'"]{2}.\s?eval\(\$\w+\)\);\s?\$\w+\([\'"]{2}\);~msi',
            'id'   => 'createFuncEval',
        ],
        [
            'full' => '~((\$\w+)="([\w-]+)";((?:\$\w+=(?:\2{\d+}\.?)+;)+)+)(header\(\'.+?\'\);)\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\'(\$\w+)=[\\\\\']+.\'(\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\$\w+\);\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\$\w+,\w+,\d+\);\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\$\w+\);return\s?\$\w+;)\'\);\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\'\$\w+\',\'\$\w+=substr\(\$\w+,\d+,\d+\);\$\w+=substr\(\$\w+,-\d+\);\$\w+=substr\(\$\w+,7,\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\$\w+\)-\d+\);return\s\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\${"[\\\\\w]+"}\["[\\\\\w]+"\]\((?:\$\w+\.?)+\)\);\'\);\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\'\$\w+=[\\\\\']+,\'\$\w+=(isset\(\${"[\\\\\w]+"}\["[\\\\\w]+"\]\)\?\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\${"[\\\\\w]+"}\["[\\\\\w]+"\]\):[\\\\\']+);\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\\\\\'([\w=]+)\\\\\'\);\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\$\w+\.\$\w+\);eval\(\$\w+\);\'\);\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\);~msi',
            'fast' => '~((\$\w+)="([\w-]+)";((?:\$\w+=(?:\2{\d+}\.?)+;)+)+)(header\(\'.+?\'\);)\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\'(\$\w+)=[\\\\\']+.\'(\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\$\w+\);\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\$\w+,\w+,\d+\);\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\$\w+\);return\s?\$\w+;)\'\);\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\'\$\w+\',\'\$\w+=substr\(\$\w+,\d+,\d+\);\$\w+=substr\(\$\w+,-\d+\);\$\w+=substr\(\$\w+,7,\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\$\w+\)-\d+\);return\s\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\${"[\\\\\w]+"}\["[\\\\\w]+"\]\((?:\$\w+\.?)+\)\);\'\);\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\'\$\w+=[\\\\\']+,\'\$\w+=(isset\(\${"[\\\\\w]+"}\["[\\\\\w]+"\]\)\?\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\${"[\\\\\w]+"}\["[\\\\\w]+"\]\):[\\\\\']+);\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\\\\\'([\w=]+)\\\\\'\);\$\w+=\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\$\w+\.\$\w+\);eval\(\$\w+\);\'\);\${"[\\\\\w]+"}\["[\\\\\w]+"\]\(\);~msi',
            'id'   => 'dictionaryCreateFuncs',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?"([\w\s=]+)";\s?(\$\w+)\s?=\s?array\(((?:\d+,?\s?)+)\);\s?(\$\w+)\s?=\s?array\(((?:"[\w\d\s\/\.]+",?\s?)+)\);\s?(\$\w+)\s?=\s?\'\';\s?(?:\$\w+\s=(?:\s?\5\[\d+\]\s?\.?)+;\s?)+(\$\w+)\s?=\s?\$\w+\("\\\\r\\\\n",\s?\1\);\s?for\((\$\w+)=0;\9\s?<\s?sizeof\(\8\);\9\+\+\){\s?\7\s\.=\s?\$\w+\(\8\[\9\]\);\s?}\s?\1\s?=\s?\7;\s?(\$\w+)\s?=\s?\3;\s?(\$\w+)\s?=\s?"";\s?for\((\$\w+)=0;\s?\12<sizeof\(\10\);\s?\12\+=2\){\s?if\(\12\s?%\s?4\){\s?\11\.=\s?substr\(\1,\10\[\12\],\10\[\12\+1\]\);\s?}else{\s?\11\.=strrev\(substr\(\1,\10\[\12\],\10\[\12\+1\]\)\);\s?}\s?};\s?\1\s?=\s?\$\w+\(\11\);\s(\$\w+)\s?=\s?array\(\);\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?;?)+;\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s?(\$\w+)\s?=\s?\'\';\s?for\((\$\w+)=0;\s?\17<strlen\(\1\);\s?\17\+=32\){\s?\13\[\]\s?=\s?substr\(\1,\s?\17,\s?32\);\s?}\s?(?:\$\w+\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s)+\$\w+\s?=\s?\'\';\s?\$\w+\s?=\s?\(\$\w+\(\$\w+\(\$\w+\)\)\)\s?%\s?sizeof\(\$\w+\);\s?\$\w+\s?=\s?\$\w+\[\$\w+\];\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;(\s?\18\s?=\s?\$_POST\[\18\];\s?(\14\s?=\s?\15\(\$_COOKIE\[\14\]\);)\s?\$\w+\s?=\s?\5\[\d+\]\s?\.\s?\5\[\d+\];\s?(eval\(\$\w+\(\18\)\);)\s?if\(!\16\){\s?((?:\$\w+\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s)+)(\$\w+\(\$\w+\);\s?echo\(\$\w+\);)\s?})~msi',
            'fast' => '~(\$\w+)\s?=\s?"([\w\s=]+)";\s?(\$\w+)\s?=\s?array\(((?:\d+,?\s?)+)\);\s?(\$\w+)\s?=\s?array\(((?:"[\w\d\s\/\.]+",?\s?)+)\);\s?(\$\w+)\s?=\s?\'\';\s?(?:\$\w+\s=(?:\s?\5\[\d+\]\s?\.?)+;\s?)+(\$\w+)\s?=\s?\$\w+\("\\\\r\\\\n",\s?\1\);\s?for\((\$\w+)=0;\9\s?<\s?sizeof\(\8\);\9\+\+\){\s?\7\s\.=\s?\$\w+\(\8\[\9\]\);\s?}\s?\1\s?=\s?\7;\s?(\$\w+)\s?=\s?\3;\s?(\$\w+)\s?=\s?"";\s?for\((\$\w+)=0;\s?\12<sizeof\(\10\);\s?\12\+=2\){\s?if\(\12\s?%\s?4\){\s?\11\.=\s?substr\(\1,\10\[\12\],\10\[\12\+1\]\);\s?}else{\s?\11\.=strrev\(substr\(\1,\10\[\12\],\10\[\12\+1\]\)\);\s?}\s?};\s?\1\s?=\s?\$\w+\(\11\);\s(\$\w+)\s?=\s?array\(\);\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?;?)+;\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s?(\$\w+)\s?=\s?\'\';\s?for\((\$\w+)=0;\s?\17<strlen\(\1\);\s?\17\+=32\){\s?\13\[\]\s?=\s?substr\(\1,\s?\17,\s?32\);\s?}\s?(?:\$\w+\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s)+\$\w+\s?=\s?\'\';\s?\$\w+\s?=\s?\(\$\w+\(\$\w+\(\$\w+\)\)\)\s?%\s?sizeof\(\$\w+\);\s?\$\w+\s?=\s?\$\w+\[\$\w+\];\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;(\s?\18\s?=\s?\$_POST\[\18\];\s?(\14\s?=\s?\15\(\$_COOKIE\[\14\]\);)\s?\$\w+\s?=\s?\5\[\d+\]\s?\.\s?\5\[\d+\];\s?(eval\(\$\w+\(\18\)\);)\s?if\(!\16\){\s?((?:\$\w+\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s)+)(\$\w+\(\$\w+\);\s?echo\(\$\w+\);)\s?})~msi',
            'id'   => 'evalPostDictionary',
        ],
        [
            'full' => '~(\$\w)\s?=\s?str_rot13\("([^"]+)"\);preg_replace\("//e","\1",""\);~msi',
            'fast' => '~(\$\w)\s?=\s?str_rot13\("([^"]+)"\);preg_replace\("//e","\1",""\);~msi',
            'id'   => 'strrotPregReplaceEval',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*[^\']+\'([^\']+)\';\s*(\$\w+)\s*=\s*\'([^\']+)\';\s*if\(!file_exists\(\$file\)+\{\s*@file_put_contents\(\1,base64_decode\(base64_decode\(\3\)+;\s*\}\s*\@include\s*\$file;~msi',
            'fast' => '~(\$\w+)\s*=\s*[^\']+\'([^\']+)\';\s*(\$\w+)\s*=\s*\'([^\']+)\';\s*if\(!file_exists\(\$file\)+\{\s*@file_put_contents\(\1,base64_decode\(base64_decode\(\3\)+;\s*\}\s*\@include\s*\$file;~msi',
            'id'   => 'dropInclude',
        ],
        [
            'full' => '~(?(DEFINE)(?\'c\'(?:/\*[^/]*/?\*/)*))(?&c)@?(eval|echo|(\$\w+)\s*=\s*create_function)(?:\/\*+\/)?\s*(?&c)\((?&c)(\'\',)?\s*([\'"?>.\s]+)?\s*\(?\s*@?\s*((?&c)base64_decode(?&c)\s*\((?&c)|(?&c)pack(?&c)\s*\(\'H\*\',|(?&c)convert_uudecode(?&c)\s*\(|(?&c)htmlspecialchars_decode(?&c)\s*\(|(?&c)stripslashes(?&c)\s*\(|(?&c)gzinflate(?&c)\s*\(|(?&c)strrev(?&c)\s*\(|(?&c)str_rot13(?&c)\s*\(|(?&c)gzuncompress(?&c)\s*\(|(?&c)urldecode(?&c)\s*\(|(?&c)rawurldecode(?&c)\s*\(|(?&c)eval(?&c)\s*\()+.*?[^\'")]+(?&c)(((?&c)\s*(?&c)\.?(?&c)[\'"]((?&c)[^\'";]+(?&c)[\'"](?&c)*\s*)+(?&c))?(?&c)\s*[\'"\);]+(?&c))+(?&c)(\s*\2\(\);(?&c))?~msi',
            'fast' => '~(?(DEFINE)(?\'c\'(?:/\*[^/]*/?\*/)*))(?&c)@?(eval|echo|(\$\w+)\s*=\s*create_function)(?:\/\*+\/)?\s*(?&c)\((?&c)(\'\',)?\s*([\'"?>.\s]+)?\s*\(?\s*@?\s*((?&c)base64_decode(?&c)\s*\((?&c)|(?&c)pack(?&c)\s*\(\'H\*\',|(?&c)convert_uudecode(?&c)\s*\(|(?&c)htmlspecialchars_decode(?&c)\s*\(|(?&c)stripslashes(?&c)\s*\(|(?&c)gzinflate(?&c)\s*\(|(?&c)strrev(?&c)\s*\(|(?&c)str_rot13(?&c)\s*\(|(?&c)gzuncompress(?&c)\s*\(|(?&c)urldecode(?&c)\s*\(|(?&c)rawurldecode(?&c)\s*\(|(?&c)eval(?&c)\s*\()+.*?[^\'")]+(?&c)(((?&c)\s*(?&c)\.?(?&c)[\'"]((?&c)[^\'";]+(?&c)[\'"](?&c)*\s*)+(?&c))?(?&c)\s*[\'"\);]+(?&c))+(?&c)(\s*\2\(\);(?&c))?~msi',
            'id'   => 'evalComments',
        ],
        [
            'full' => '~\@?error_reporting\(0\);\@?set_time_limit\(0\);\s*(\$\w+)="([^"]+)";\s*\1=\@?urldecode\(\1\);\1=\@?strrev\(\1\);\@?eval\(\1\);~msi',
            'fast' => '~\@?error_reporting\(0\);\@?set_time_limit\(0\);\s*(\$\w+)="([^"]+)";\s*\1=\@?urldecode\(\1\);\1=\@?strrev\(\1\);\@?eval\(\1\);~msi',
            'id'   => 'strrevUrldecodeEval',
        ],
        [
            'full' => '~(\$\w+\s*=\s*"\w+";\s*\@?error_reporting\(E_ERROR\);\s*\@?ini_set\(\'display_errors\',\'Off\'\);\s*\@?ini_set\(\'max_execution_time\',\d+\);\s*header\("[^"]+"\);\s*)?(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*pack\("H\*",str_rot13\(\2\)+;\s*eval\(\4\);~msi',
            'fast' => '~(\$\w+\s*=\s*"\w+";\s*\@?error_reporting\(E_ERROR\);\s*\@?ini_set\(\'display_errors\',\'Off\'\);\s*\@?ini_set\(\'max_execution_time\',\d+\);\s*header\("[^"]+"\);\s*)?(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*pack\("H\*",str_rot13\(\2\)+;\s*eval\(\4\);~msi',
            'id'   => 'evalPackStrrot',
        ],
        [
            'full' => '~\$\w+\s*=\s*\d+;\s*function\s*(\w+)\(\$\w+,\s*\$\w+\)\{\$\w+\s*=\s*\'\';\s*for[^{]+\{([^}]+\}){2}\s*\$\w{1,40}\s*=\s*((\'[^\']+\'\s*\.?\s*)+);\s*\$\w+\s*=\s*Array\(((\'\w\'=>\'\w\',?\s*)+)\);\s*eval(?:/\*[^/]\*/)*\(\1\(\$\w+,\s*\$\w+\)+;~msi',
            'fast' => '~\$\w+\s*=\s*\d+;\s*function\s*(\w+)\(\$\w+,\s*\$\w+\)\{\$\w+\s*=\s*\'\';\s*for[^{]+\{([^}]+\}){2}\s*\$\w{1,40}\s*=\s*((\'[^\']+\'\s*\.?\s*)+);\s*\$\w+\s*=\s*Array\(((\'\w\'=>\'\w\',?\s*)+)\);\s*eval(?:/\*[^/]\*/)*\(\1\(\$\w+,\s*\$\w+\)+;~msi',
            'id'   => 'urlDecodeTable',
        ],
        [
            'full' => '~((?:\$\w+=\'\w\';)+)((?:\$\w+=(\$\w+\.?)+;)+)eval\((\$\w+\()+\'([^\']+)\'\)+;~msi',
            'fast' => '~((?:\$\w+=\'\w\';)+)((?:\$\w+=(\$\w+\.?)+;)+)eval\((\$\w+\()+\'([^\']+)\'\)+;~msi',
            'id'   => 'evalVarChar',
        ],
        [
            'full' => '~(\$\w+\s*=\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()+"([^"]+)"\);)\s*eval\("?(\$\w+)"?\);~msi',
            'fast' => '~(\$\w+\s*=\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()+"([^"]+)"\);)\s*eval\("?(\$\w+)"?\);~msi',
            'id'   => 'evalVarFunc',
        ],
        [
            'full' => '~((?:\$\w+\s*=\s*("[\w=+/\\\\]+");\s*)+)(eval\((\$\w+\(+)+(\$\w+)\)+);~msi',
            'fast' => '~((?:\$\w+\s*=\s*("[\w=+/\\\\]+");\s*)+)(eval\((\$\w+\(+)+(\$\w+)\)+);~msi',
            'id'   => 'evalVarsFuncs',
        ],
        [
            'full' => '~<\?php\s*(?:/\*[^=\$\{\}/]{99,499}\bencipher\s*can\s*be\s*obtained\s*from:\s*https?://docs\.google\.com/[^\*\$\(;\}\{=]{1,99}\*/\s*)?(\$[^\w=(,${)}]{0,50})=\'(\w{0,50})\';((?:\$[^\w=(,${)}]{0,50}=(?:\1{\d+}\.?){0,50};){1,20})(\$[^=]{0,50}=\$[^\w=(,${)}]{1,50}\(\$[^\w=(,${)}]{1,50}\(\'\\\\{2}\',\'/\',__FILE__\)\);(?:\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}]{0,50}\);){2}\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}]{0,50}\(\'\',\$[^\w=(,${)}]{0,50}\)\.\$[^\(]{0,50}\(\$[^\w=(,${)}]{0,50},\d+,\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}]{0,50},\'@ev\'\)\);\$[^\w=(,${)}]{0,50}=\$[^\(]{0,50}\(\$[^\w=(,${)}]{0,50}\);\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}=]{0,50}=\$[^\w=(,${)}]{0,50}=NULL;@eval\(\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}(]{0,50}\(\$[^\w=(,${)}]{0,50},\'\',\$[^\w=(,${)}]{0,50}\(\'([^\']{0,500})\',\'([^\']{0,500})\',\'([^\']{0,500})\'\){4};)unset\((?:\$[^,]{0,50},?){0,20};return;\?>.+~msi',
            'fast' => '~<\?php\s*(?:/\*[^=\$\{\}/]{99,499}\bencipher\s*can\s*be\s*obtained\s*from:\s*https?://docs\.google\.com/[^\*\$\(;\}\{=]{1,99}\*/\s*)?(\$[^\w=(,${)}]{0,50})=\'(\w{0,50})\';((?:\$[^\w=(,${)}]{0,50}=(?:\1{\d+}\.?){0,50};){1,20})(\$[^=]{0,50}=\$[^\w=(,${)}]{1,50}\(\$[^\w=(,${)}]{1,50}\(\'\\\\{2}\',\'/\',__FILE__\)\);(?:\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}]{0,50}\);){2}\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}]{0,50}\(\'\',\$[^\w=(,${)}]{0,50}\)\.\$[^\(]{0,50}\(\$[^\w=(,${)}]{0,50},\d+,\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}]{0,50},\'@ev\'\)\);\$[^\w=(,${)}]{0,50}=\$[^\(]{0,50}\(\$[^\w=(,${)}]{0,50}\);\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}=]{0,50}=\$[^\w=(,${)}]{0,50}=NULL;@eval\(\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}(]{0,50}\(\$[^\w=(,${)}]{0,50},\'\',\$[^\w=(,${)}]{0,50}\(\'([^\']{0,500})\',\'([^\']{0,500})\',\'([^\']{0,500})\'\){4};)unset\((?:\$[^,]{0,50},?){0,20};return;\?>.+~msi',
            'id'   => 'evalFileContent',
        ],
        [
            'full' => '~echo\s{0,50}"(\\\\\${\\\\x\d{2}(?:.*?[^\\\\]+)+)";~msi',
            'fast' => '~echo\s{0,50}"(\\\\\${\\\\x\d{2}(?:.*?[^\\\\]+)+)";~msi',
            'id'   => 'echoEscapedStr',
        ],
        [
            'full' => '~file_put_contents\(\$\w+\[[\'"]\w+[\'"]\]\.[\'"][/\w]+\.php[\'"],(base64_decode\([\'"]([\w=]+)[\'"]\))\)~msi',
            'fast' => '~file_put_contents\(\$\w+\[[\'"]\w+[\'"]\]\.[\'"][/\w]+\.php[\'"],(base64_decode\([\'"]([\w=]+)[\'"]\))\)~msi',
            'id'   => 'filePutDecodedContents',
        ],
        [
            'full' => '~eval\(implode\(array_map\([\'"](\w+)[\'"],str_split\([\'"]([^\'"]+)[\'"]\)\)\)\);~msi',
            'fast' => '~eval\(implode\(array_map\([\'"](\w+)[\'"],str_split\([\'"]([^\'"]+)[\'"]\)\)\)\);~msi',
            'id'   => 'evalImplodedArrStr',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?\'(.*?NULL\);)\';\s*(\$\w+)\s?=\s?[\'"]([\w\\\\]+)[\'"];\s?\3\([\'"]/\(\.\*\)/e[\'"],\s?[\'"]([\w\\\\]+)[\'"],\s?NULL\);~msi',
            'fast' => '~(\$\w+)\s?=\s?\'(.*?NULL\);)\';\s*(\$\w+)\s?=\s?[\'"]([\w\\\\]+)[\'"];\s?\3\([\'"]/\(\.\*\)/e[\'"],\s?[\'"]([\w\\\\]+)[\'"],\s?NULL\);~msi',
            'id'   => 'pregReplaceCodeContent',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";(?:\$\w+)\s*=\s*base64_decode\("[^"]+"\);(\$\w+)\s*=\s*gzinflate\(base64_decode\(\1\)\);((\s*\$\w+\s*=\s*\[(\'[^\']+\',?)+\];)+)\s*\3\s*=\s*str_replace\(\$\w+,\$\w+,\3\);\s*eval\(\3\);\$\w+="[^"]+";~msi',
            'fast' => '~(\$\w+)\s*=\s*"([^"]+)";(?:\$\w+)\s*=\s*base64_decode\("[^"]+"\);(\$\w+)\s*=\s*gzinflate\(base64_decode\(\1\)\);((\s*\$\w+\s*=\s*\[(\'[^\']+\',?)+\];)+)\s*\3\s*=\s*str_replace\(\$\w+,\$\w+,\3\);\s*eval\(\3\);\$\w+="[^"]+";~msi',
            'id'   => 'sistemitComEnc',
        ],
        [
            'full' => '~((?:\$\w+\s*\.?=\s*"[^"]*";\s*)+)(\$\w+)\s*=\s*str_replace\(\s*"([^"]+)",\s*"",\s*\$\w+\s*\);\s*(\$\w+)\s*=\s*str_replace\(\s*"([^"]+)",\s*"",\s*"([^"]+)"\s*\);\s*(\$\w+)\s*=\s*\4\(\s*\2\s*\);\s*\7\s*=\s*"[^"]+\7";\s*eval\(\s*\7\s*\);~msi',
            'fast' => '~((?:\$\w+\s*\.?=\s*"[^"]*";\s*)+)(\$\w+)\s*=\s*str_replace\(\s*"([^"]+)",\s*"",\s*\$\w+\s*\);\s*(\$\w+)\s*=\s*str_replace\(\s*"([^"]+)",\s*"",\s*"([^"]+)"\s*\);\s*(\$\w+)\s*=\s*\4\(\s*\2\s*\);\s*\7\s*=\s*"[^"]+\7";\s*eval\(\s*\7\s*\);~msi',
            'id'   => 'concatVarsReplaceEval',
        ],
        [
            'full' => '~(?:(?:\$\w+=(?:chr\(\d+\)[;.])+)+\$\w+="[^"]+";(\$\w+)=(?:\$\w+[.;])+\s*)?(\$\w+)=\'([^\']+)\';((?:\s*\2=str_replace\(\'[^\']+\',\s*\'\w\',\s*\2\);\s*)+)(?(1)\s*\1\s*=\s*str_replace\(\'[^+]\',\s*\'[^\']+\',\s*\1\);\s*(\$\w+)\s*=\s*[^;]+;";\s*@?\1\(\s*str_replace\((?:\s*array\(\'[^\']+\',\s*\'[^\']+\'\),){2}\s*\5\)\s*\);|\s*\2=base64_decode\(\2\);\s*eval\(\2\);)~msi',
            'fast' => '~(?:(?:\$\w+=(?:chr\(\d+\)[;.])+)+\$\w+="[^"]+";(\$\w+)=(?:\$\w+[.;])+\s*)?(\$\w+)=\'([^\']+)\';((?:\s*\2=str_replace\(\'[^\']+\',\s*\'\w\',\s*\2\);\s*)+)(?(1)\s*\1\s*=\s*str_replace\(\'[^+]\',\s*\'[^\']+\',\s*\1\);\s*(\$\w+)\s*=\s*[^;]+;";\s*@?\1\(\s*str_replace\((?:\s*array\(\'[^\']+\',\s*\'[^\']+\'\),){2}\s*\5\)\s*\);|\s*\2=base64_decode\(\2\);\s*eval\(\2\);)~msi',
            'id'   => 'evalVarReplace',
        ],
        [
            'full' => '~((\$\w+\s*=\s*\(?(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()*((?:"([^"]+)";\s*)|(?:\$\w+)\)*;\s*))+)(eval\("?(\$\w+)"?\);)~msi',
            'fast' => '~((\$\w+\s*=\s*\(?(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()*((?:"([^"]+)";\s*)|(?:\$\w+)\)*;\s*))+)(eval\("?(\$\w+)"?\);)~msi',
            'id'   => 'evalVarFunc2',
        ],
        [
            'full' => '~((\$\w+)\s*=\s*"([^"]+)";)\s*((\$\w+)\s*=\s*array\(((\s*\d+,?)+)\);)\s*((\$\w+)\s*=\s*array\(((\s*"[^"]+",?)+)\);)\s*(\$\w+)\s*=\s*\'\';(\s*\$\w+\s*=\s*(?:\9\[\d+\]\s*\.?\s*)+;)+(.+?(\s*\$\w+\s*=\s*\w+\((?:\9\[\d+\]\s*\.?\s*)+)\);\s*eval\(\$\w+\);\s*\})~msi',
            'fast' => '~((\$\w+)\s*=\s*"([^"]+)";)\s*((\$\w+)\s*=\s*array\(((\s*\d+,?)+)\);)\s*((\$\w+)\s*=\s*array\(((\s*"[^"]+",?)+)\);)\s*(\$\w+)\s*=\s*\'\';(\s*\$\w+\s*=\s*(?:\9\[\d+\]\s*\.?\s*)+;)+(.+?(\s*\$\w+\s*=\s*\w+\((?:\9\[\d+\]\s*\.?\s*)+)\);\s*eval\(\$\w+\);\s*\})~msi',
            'id'   => 'evalArrays',
        ],
        [
            'full' => '~\$\w+\s?=\s?preg_replace\([\'"]/([^\'"/]+)/\w{0,2}[\'"],[\'"]([^\'"]+)[\'"],[\'"]{2}\);~msi',
            'fast' => '~\$\w+\s?=\s?preg_replace\([\'"]/([^\'"/]+)/\w{0,2}[\'"],[\'"]([^\'"]+)[\'"],[\'"]{2}\);~msi',
            'id'   => 'pregReplaceVar',
        ],
        [
            'full' => '~function\s(\w+)\((\$\w+),\s?(\$\w+)\){\s?(\$\w+)=[\'"]{2};\s?for\(\$\w+=0;\$\w+<strlen\(\2\);\)\s?for\(\$\w+=0;\$\w+<strlen\(\3\);\$\w+\+\+,\s?\$\w+\+\+\)\s?\4\s?\.=\s?\2{\$\w+}\s?\^\s?\3{\$\w+};\s?return\s?\4;\s?};eval\(\1\(base64_decode\([\'"]([^\'"]+)[\'"]\),[\'"]([^\'"]+)[\'"]\)\);~msi',
            'fast' => '~function\s(\w+)\((\$\w+),\s?(\$\w+)\){\s?(\$\w+)=[\'"]{2};\s?for\(\$\w+=0;\$\w+<strlen\(\2\);\)\s?for\(\$\w+=0;\$\w+<strlen\(\3\);\$\w+\+\+,\s?\$\w+\+\+\)\s?\4\s?\.=\s?\2{\$\w+}\s?\^\s?\3{\$\w+};\s?return\s?\4;\s?};eval\(\1\(base64_decode\([\'"]([^\'"]+)[\'"]\),[\'"]([^\'"]+)[\'"]\)\);~msi',
            'id'   => 'evalFuncTwoArgs',
        ],
        [
            'full' => '~function\s(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?[\'"]{2};\s?unset\(\$\w+\);\s?\$\w+\s?=\s?[\'"]([^\'"]+)[\'"];\s?\$\w+\s?=\s?preg_replace\("/([^"]+)/",\s?[\'"]{2},\s?\$\w+\);\s?\$\w+\s?=\s?(?:(?:[\'"]\w+[\'"]|\$\w+)\.?)+;\s?\$\w+\s?=\s?\$\w+\([\'"]\$\w+[\'"],\s?\$\w+\);\s?@?\$\w+\(\$\w+\);\s?}\s?function\s?(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?[\'"](.*?)[\'"];\s?\$\w+\s?=\s?preg_replace\("/([^\'"]+)/",\s?[\'"]{2},\s?\$\w+\);\s?return\s?\$\w+\(\$\w+\);\s?}\s?\1\(\4\(\s?join\([\'"]([^\'"]+)[\'"],\s?array\(((?:[\'"][^\'"]+[\'"],?)+)\)+;~msi',
            'fast' => '~function\s(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?[\'"]{2};\s?unset\(\$\w+\);\s?\$\w+\s?=\s?[\'"]([^\'"]+)[\'"];\s?\$\w+\s?=\s?preg_replace\("/([^"]+)/",\s?[\'"]{2},\s?\$\w+\);\s?\$\w+\s?=\s?(?:(?:[\'"]\w+[\'"]|\$\w+)\.?)+;\s?\$\w+\s?=\s?\$\w+\([\'"]\$\w+[\'"],\s?\$\w+\);\s?@?\$\w+\(\$\w+\);\s?}\s?function\s?(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?[\'"](.*?)[\'"];\s?\$\w+\s?=\s?preg_replace\("/([^\'"]+)/",\s?[\'"]{2},\s?\$\w+\);\s?return\s?\$\w+\(\$\w+\);\s?}\s?\1\(\4\(\s?join\([\'"]([^\'"]+)[\'"],\s?array\(((?:[\'"][^\'"]+[\'"],?)+)\)+;~msi',
            'id'   => 'evalPregReplaceFuncs',
        ],
        [
            'full' => '~error_reporting\(0\);((?:\$\w+=\'[^;]+;)+)error_reporting\(0\);((?:\$\w+=\$\w+\(\$\w+\(\'([^\']+)\'\)\);)+\$\w+=(?:\$\w+\()+\'([^\']+)\'\)+\.(?:\$\w+\()+\'([^\']+)\'\)+;\$\w+=(?:\$\w+\()+\'([^\']+)\'\)+;\$\w+=(?:\$\w+\()+"\\\\n",\s*\'\',\s*\'([^\']+)\'\)+;(?:[^}]+\})+}\s*echo\s*(?:\$\w+\()+\'([^\']+)\'\)+);exit;~msi',
            'fast' => '~error_reporting\(0\);((?:\$\w+=\'[^;]+;)+)error_reporting\(0\);((?:\$\w+=\$\w+\(\$\w+\(\'([^\']+)\'\)\);)+\$\w+=(?:\$\w+\()+\'([^\']+)\'\)+\.(?:\$\w+\()+\'([^\']+)\'\)+;\$\w+=(?:\$\w+\()+\'([^\']+)\'\)+;\$\w+=(?:\$\w+\()+"\\\\n",\s*\'\',\s*\'([^\']+)\'\)+;(?:[^}]+\})+}\s*echo\s*(?:\$\w+\()+\'([^\']+)\'\)+);exit;~msi',
            'id'   => 'urlMd5Passwd',
        ],
        [
            'full' => '~(\$\w+\s?=\s?[\'"](?:(?:[^\'"]|[\'"])+)[\'"];\s?)+((?:\$\w+\s?=\s?(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+;)+\$\w+\s?=\s?\$\w+\s?\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+\);\s*\$\w+\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?[.,]?\s?)+\);)~msi',
            'fast' => '~(\$\w+\s?=\s?[\'"](?:(?:[^\'"]|[\'"])+)[\'"];\s?)+((?:\$\w+\s?=\s?(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+;)+\$\w+\s?=\s?\$\w+\s?\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+\);\s*\$\w+\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?[.,]?\s?)+\);)~msi',
            'id'   => 'ManyDictionaryVars',
        ],
        [
            'full' => '~function\s(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?(?:[\'"][\\\\\w]+[\'"]\(\d+\s?[-+]\s?\d+\)\s?\.?\s?)+;\s?(?:\$\w+\s?=\s?\$\w+\([\'"](?:edoced_46esab|etalfnizg|ecalper_rts)[\'"]\);\s?)+\$\w+\s?=\s?\$\w+\(array\(((?:\s?"[^"]+",?)+)\),\s?[\'"]{2},\s?\$\w+\);\s?return\s?(?:\$\w+\(){2}\$\w+\)\);\s?}\s?(\$\w+\s?=\s?[\'"]\w+[\'"];)?\s?ob_start\(\);\s?\?>(.*?)<\?php\s?\$\w+\s?=\s?ob_get_clean\(\);\s?eval\(\1\(\$\w+\)\);\s?\?>~msi',
            'fast' => '~function\s(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?(?:[\'"][\\\\\w]+[\'"]\(\d+\s?[-+]\s?\d+\)\s?\.?\s?)+;\s?(?:\$\w+\s?=\s?\$\w+\([\'"](?:edoced_46esab|etalfnizg|ecalper_rts)[\'"]\);\s?)+\$\w+\s?=\s?\$\w+\(array\(((?:\s?"[^"]+",?)+)\),\s?[\'"]{2},\s?\$\w+\);\s?return\s?(?:\$\w+\(){2}\$\w+\)\);\s?}\s?(\$\w+\s?=\s?[\'"]\w+[\'"];)?\s?ob_start\(\);\s?\?>(.*?)<\?php\s?\$\w+\s?=\s?ob_get_clean\(\);\s?eval\(\1\(\$\w+\)\);\s?\?>~msi',
            'id'   => 'evalBuffer',
        ],
        [
            'full' => '~((?:\$\w+\s?=\s?[\'"]\w*[\'"];\s?){0,50}(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];(?:\$\w+\s?\.?=\s?(?:\$\w+{\d+}\.?)+;)+)\s?(eval\((\$\w+)\([\'"]([^\'"]+)[\'"]\)\);)~msi',
            'fast' => '~((?:\$\w+\s?=\s?[\'"]\w*[\'"];\s?){0,50}(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];(?:\$\w+\s?\.?=\s?(?:\$\w+{\d+}\.?)+;)+)\s?(eval\((\$\w+)\([\'"]([^\'"]+)[\'"]\)\);)~msi',
            'id' => 'evalDictionaryVars',
        ],
        [
            'full' => '~\$\w+\s?=\s?[\'"]([^\'"]+)[\'"];(?:\$\w+\s?=\s?base64_decode\([\'"][^\'"]+[\'"]\);)+\$\w+\s?=\s?\$\w+\(\$\w+\(\$\w+\)\);\$\w+\s?=\s?\$\w+\(\$\w+\);(\$\w+)\s?=\s?[\'"]{2};for\(\$\w+\s?=\s?0\s?;\s?\$\w+\s?<\s?\$\w+\s?;\s?\$\w+\+\+\){\2\s?\.=\s?\$\w+\(\(\$\w+\(\$\w+\[\$\w+\]\)\^(\d+)\)\);}eval\(\2\);return;~msi',
            'fast' => '~\$\w+\s?=\s?[\'"]([^\'"]+)[\'"];(?:\$\w+\s?=\s?base64_decode\([\'"][^\'"]+[\'"]\);)+\$\w+\s?=\s?\$\w+\(\$\w+\(\$\w+\)\);\$\w+\s?=\s?\$\w+\(\$\w+\);(\$\w+)\s?=\s?[\'"]{2};for\(\$\w+\s?=\s?0\s?;\s?\$\w+\s?<\s?\$\w+\s?;\s?\$\w+\+\+\){\2\s?\.=\s?\$\w+\(\(\$\w+\(\$\w+\[\$\w+\]\)\^(\d+)\)\);}eval\(\2\);return;~msi',
            'id' => 'evalFuncXored',
        ],
        [
            'full' => '~[\'"]-;-[\'"];(.*?\(\'\\\\\\\\\',\'/\',__FILE__\)\);.*?,[\'"];[\'"]\),[\'"]"[\'"]\);.*?)[\'"]-;-[\'"];((\$\w+)=[\'"]([^\'"]+)[\'"];.*?\$\w+\s?\.\s?\3,\s?[\'"]([^\'"]+)[\'"],\s?[\'"]([^\'"]+)[\'"]\)\)\).*?)[\'"]-;-[\'"];(.*?)[\'"]-;-[\'"];~msi',
            'fast' => '~[\'"]-;-[\'"];(.*?\(\'\\\\\\\\\',\'/\',__FILE__\)\);.*?,[\'"];[\'"]\),[\'"]"[\'"]\);.*?)[\'"]-;-[\'"];((\$\w+)=[\'"]([^\'"]+)[\'"];.*?\$\w+\s?\.\s?\3,\s?[\'"]([^\'"]+)[\'"],\s?[\'"]([^\'"]+)[\'"]\)\)\).*?)[\'"]-;-[\'"];(.*?)[\'"]-;-[\'"];~msi',
            'id' => 'evalFuncExplodedContent',
        ],
        [
            'full' => '~(\$\w{0,100}\s?=\s?(?:chr\(\w{1,10}\)\s?\.?){1,100};\s?(?:\$\w{0,100}\s?=\s?(?:\s?(?:[\'"][\\\\\\\\\w]{1,10}[\'"]|[\d\.]{1,5}\s[*\+\-\.]\s\d{1,5})\s?\.?)+?;\s?){1,10}\$\w{0,100}\s?=\s?(?:chr\(\w{1,10}\)\s?\.?){1,100};\s?\$\w{1,50}\s?=\s?\$\w{1,50}\(\$\w{1,50}\((?:[\'"][^\'"]{1,500}[\'"]\s?\.?\s?)+\),\s?(?:[\'"][^\'"]{1,500}[\'"]\s?\.?\s?)+,\s?substr\(hash\([\'"]SHA256[\'"],(?:\s?[\'"]\d{1,15}[\'"]\s?\.?){2},\s?true\),\s?(\d{1,10}),\s?(\d{1,10})\),\s?OPENSSL_RAW_DATA,\s?\$\w{1,50}\);.*?)(\$\w{1,50})\s?=\s?\$\w{1,50}\([\'"]([^\'"]+)[\'"],[\'"]{2},[\'"]([^\'"]+)[\'"]\);\s?return\s?@eval\(((?:\$\w{1,50}\s?\()+\$\w{1,50}(?:\)\s?)+);\s?exit;~msi',
            'fast' => '~\$\w{0,100}\s?=\s?(?:chr\(\w{1,10}\)\s?\.?){1,100};\s?(?:\$\w{0,100}\s?=\s?(?:\s?(?:[\'"][\\\\\\\\\w]{1,10}[\'"]|[\d\.]{1,5}\s[*\+\-\.]\s\d{1,5})\s?\.?)+?;\s?){1,10}\$\w{0,100}\s?=\s?(?:chr\(\w{1,10}\)\s?\.?){1,100};\s?\$\w{1,50}\s?=\s?\$\w{1,50}\(\$\w{1,50}\((?:[\'"][^\'"]{1,500}[\'"]\s?\.?\s?)+\),\s?(?:[\'"][^\'"]{1,500}[\'"]\s?\.?\s?)+,\s?substr\(hash\([\'"]SHA256[\'"],(?:\s?[\'"]\d{1,15}[\'"]\s?\.?){2},\s?true\),\s?(\d{1,10}),\s?(\d{1,10})\),\s?OPENSSL_RAW_DATA,\s?\$\w{1,50}\);.*?\$\w{1,50}\s?=\s?\$\w{1,50}\([\'"]([^\'"]+)[\'"],[\'"]{2},[\'"]([^\'"]+)[\'"]\);\s?return\s?@eval\(((?:\$\w{1,50}\s?\()+\$\w{1,50}(?:\)\s?)+);\s?exit;~msi',
            'id' => 'evalEncryptedVars',
        ],
        [
            'full' => '~function\s(\w+)\((\$\w+),\s*(\$\w+)[^)]+\)\s*\{\s*\$\w+\s*=\s*\2;\s*\$\w+\s*=\s*\'\';\s*for\s*\(\$\w+\s*=\s*0;\$\w+\s*<\s*strlen\(\$\w+\);\)\s*{\s*for\s*\(\$\w+\s*=\s*0;\$\w+\s*<\s*strlen\(\3\)\s*&&\s*\$\w+\s*<\s*strlen\(\$\w+\);\$\w+\+\+,\s*\$\w+\+\+\)\s*{\s*\$\w+\.=\s*\$\w+\[\$\w+\]\s*\^\s*\3\[\$\w+\];\s*}\s*}\s*return \$\w+;\s*}\s*\$\w+\s*=\s*"[^"]+";\s*\$\w+\s*=\s*"([^"]+)";\s*(?:\$\w+\s*=\s*"";\s*)+(?:foreach[^{]+{[^}]+}\s*)+(\$\w+)\s*=\s*\$\w+\([create_funion\'. ]+\);\s*(\$\w+)\s*=\s*\5\("[^"]*",\s*\$\w+\(\1\(\$\w+\(\$\w+\),\s*"([^"]+)"\)+;\s*\6\(\);~msi',
            'fast' => '~function\s(\w+)\((\$\w+),\s*(\$\w+)[^)]+\)\s*\{\s*\$\w+\s*=\s*\2;\s*\$\w+\s*=\s*\'\';\s*for\s*\(\$\w+\s*=\s*0;\$\w+\s*<\s*strlen\(\$\w+\);\)\s*{\s*for\s*\(\$\w+\s*=\s*0;\$\w+\s*<\s*strlen\(\3\)\s*&&\s*\$\w+\s*<\s*strlen\(\$\w+\);\$\w+\+\+,\s*\$\w+\+\+\)\s*{\s*\$\w+\.=\s*\$\w+\[\$\w+\]\s*\^\s*\3\[\$\w+\];\s*}\s*}\s*return \$\w+;\s*}\s*\$\w+\s*=\s*"[^"]+";\s*\$\w+\s*=\s*"([^"]+)";\s*(?:\$\w+\s*=\s*"";\s*)+(?:foreach[^{]+{[^}]+}\s*)+(\$\w+)\s*=\s*\$\w+\([create_funion\'. ]+\);\s*(\$\w+)\s*=\s*\5\("[^"]*",\s*\$\w+\(\1\(\$\w+\(\$\w+\),\s*"([^"]+)"\)+;\s*\6\(\);~msi',
            'id' => 'xoredKey',
        ],
        [
            'full' => '~(\$\w+)=str_rot13\(\'[^\']+\'\);(\$\w+)=str_rot13\(strrev\(\'[^\']+\'\)\);(\s*eval\(\1\(\2\(\'([^\']+)\'\)+;)+~msi',
            'fast' => '~(\$\w+)=str_rot13\(\'[^\']+\'\);(\$\w+)=str_rot13\(strrev\(\'[^\']+\'\)\);(\s*eval\(\1\(\2\(\'([^\']+)\'\)+;)+~msi',
            'id' => 'evalGzB64',
        ],
        [
            'full' => '~(function\s*(_\d+)\((\$\w+)\)\s*{(\$\w+)=Array\(\'[^)]+\'\);return\s*base64_decode\(\4\[\3\]\);\})(.+?\2\(\d+\))+[^;]+;exit;~msi',
            'fast' => '~(function\s*(_\d+)\((\$\w+)\)\s*{(\$\w+)=Array\(\'[^)]+\'\);return\s*base64_decode\(\4\[\3\]\);\})(.+?\2\(\d+\))+[^;]+;exit;~msi',
            'id' => 'evalArrayB64',
        ],
        [
            'full' => '~http_response_code\(\d{1,3}\);function\s?(\w{1,100})\(\$\w{1,50}\){if\s?\(empty\(\$\w{1,50}\)\)\s?return;\$\w{1,50}\s?=\s?"[^"]{1,500}";(?:(?:\$\w{1,50}\s?=\s?[\'"]{0,2}){1,4};){1,2}\$\w{1,50}\s?=\s?0;\$\w{1,50}\s?=\s?"";\$\w{1,50}\s?=\s?preg_replace\("[^"]{1,50}",\s?"",\s?\$\w{1,50}\);do{.*?while\s?\(\$\w{1,50}\s?<\s?strlen\(\$\w{1,50}\)\);return\s?\$\w{1,50};}eval\(\1\(hex2bin\("(\w{1,30000})"\)\)\);~msi',
            'fast' => '~http_response_code\(\d{1,3}\);function\s?(\w{1,100})\(\$\w{1,50}\){if\s?\(empty\(\$\w{1,50}\)\)\s?return;\$\w{1,50}\s?=\s?"[^"]{1,500}";(?:(?:\$\w{1,50}\s?=\s?[\'"]{0,2}){1,4};){1,2}\$\w{1,50}\s?=\s?0;\$\w{1,50}\s?=\s?"";\$\w{1,50}\s?=\s?preg_replace\("[^"]{1,50}",\s?"",\s?\$\w{1,50}\);do{.*?while\s?\(\$\w{1,50}\s?<\s?strlen\(\$\w{1,50}\)\);return\s?\$\w{1,50};}eval\(\1\(hex2bin\("(\w{1,30000})"\)\)\);~msi',
            'id' => 'evalFuncBinary',
        ],
        [
            'full' => '~(\$\w{1,50}\s?=\s?\'\w{1,500}\';){1,5}\$\w{1,50}\s?=\s?(?:\$\w{1,50}\.?){1,10};\$\w{1,50}=\$\w{1,50}\([\'"]H\*[\'"],[\'"](\w{1,200})[\'"]\);\s?\$\w{1,50}\("[^"]{1,100}","(\\\\x[^\']{1,500})(\'[^\']{1,50000}\')\\\\x[^"]{1,50}",[\'"]{2}\);~msi',
            'fast' => '~(\$\w{1,50}\s?=\s?\'\w{1,500}\';){1,5}\$\w{1,50}\s?=\s?(?:\$\w{1,50}\.?){1,10};\$\w{1,50}=\$\w{1,50}\([\'"]H\*[\'"],[\'"](\w{1,200})[\'"]\);\s?\$\w{1,50}\("[^"]{1,100}","(\\\\x[^\']{1,500})(\'[^\']{1,50000}\')\\\\x[^"]{1,50}",[\'"]{2}\);~msi',
            'id' => 'evalPackFuncs',
        ],
        [
            'full' => '~parse_str\(((?:\s?\'[^\']\'\s?\.?\s?){1,500}),\s?(\$\w{1,50})\s?\);@?\2\[\d{1,5}\]\(\2\s?\[\d{1,5}\],array\(\),array\s?\(\s?\'([^\']{1,10})\'\s?\.(\$\w{1,50}\[\d\]\s?\(\$\w{1,50}\[\d\]\s?\(\$\w{1,50}\[\s?\d{1,2}\]\()(\'[^\']{1,50000}\')\)\)\)\.\'([^\']{1,10})\'\)\);~msi',
            'fast' => '~parse_str\(((?:\s?\'[^\']\'\s?\.?\s?){1,500}),\s?(\$\w{1,50})\s?\);@?\2\[\d{1,5}\]\(\2\s?\[\d{1,5}\],array\(\),array\s?\(\s?\'([^\']{1,10})\'\s?\.(\$\w{1,50}\[\d\]\s?\(\$\w{1,50}\[\d\]\s?\(\$\w{1,50}\[\s?\d{1,2}\]\()(\'[^\']{1,50000}\')\)\)\)\.\'([^\']{1,10})\'\)\);~msi',
            'id' => 'parseStrFunc',
        ],
        [
            'full' => '~eval\("\\\\(\$\w+)=(gz[^\)]+\)\);)"\);eval\("\?>"\.\1\);~msi',
            'fast' => '~eval\("\\\\(\$\w+)=(gz[^\)]+\)\);)"\);eval\("\?>"\.\1\);~msi',
            'id' => 'evalGzinflate',
        ],
        [
            'full' => '~function\s?(\w{1,50})\(\$\w{1,50}\)\s?{\s?(\$\w{1,50})\s?=\s?\("([^"]{1,500})"\);\s?(?:\$\w{1,50}\s?=\s?(?:"[^"]+"|\$\w{1,50}|[\'"]{2});\s?)+for\(\$\w{1,50}\s?=\s?0;\s?\$\w{1,50}<strlen\(\$\w{1,50}\);\s?\)\s?{\s?for\(\$\w{1,50}\s?=\s?0;\s?\(\$\w{1,50}<strlen\(\2\)\s?&&\s?\$\w{1,50}<strlen\(\$\w{1,50}\)\);\s?\$\w{1,50}\+\+,\$\w{1,50}\+\+\){\s?(?:\$\w{1,50}\s?=\s?"[^"]+";\s?){1,2}\$\w{1,50}\s?\.=\s?\$\w{1,50}{\$\w{1,50}}\s?\^\s?\$\w{1,50}{\$\w{1,50}};\s?\$\w{1,50}\s?=\s?"[^"]+";\s?}\s?}\s?return\s?\$\w{1,50};\s?}\s?(\$\w{1,50})\s?=\s?preg_replace\("([^"]+)",\s?"",\s?"([^"]+)"\);\s?(?:\s?\$\w{1,50}\s?=\s?(?:"[^"]+"|\w{1,50}\(\$\w{1,50}\("[^"]+"\)\)|\$\w{1,50}\(\)\.\s?\w{1,50}\(\$\w{1,50}\("[^"]+"\)\)|"[^"]+"\s*\.\s*\w+\(\$\w+\("[^"]+"\)\));\s?){1,50}(\$\w{1,50}\(\$\w{1,50},(?:\$\w{1,50}\.?)+\);)\s?(?:\$\w{1,50}\s?=\s?"[^"]+";\s?|include\s?\$\w{1,50};\s){1,50}~msi',
            'fast' => '~function\s?(\w{1,50})\(\$\w{1,50}\)\s?{\s?(\$\w{1,50})\s?=\s?\("([^"]{1,500})"\);\s?(?:\$\w{1,50}\s?=\s?(?:"[^"]+"|\$\w{1,50}|[\'"]{2});\s?)+for\(\$\w{1,50}\s?=\s?0;\s?\$\w{1,50}<strlen\(\$\w{1,50}\);\s?\)\s?{\s?for\(\$\w{1,50}\s?=\s?0;\s?\(\$\w{1,50}<strlen\(\2\)\s?&&\s?\$\w{1,50}<strlen\(\$\w{1,50}\)\);\s?\$\w{1,50}\+\+,\$\w{1,50}\+\+\){\s?(?:\$\w{1,50}\s?=\s?"[^"]+";\s?){1,2}\$\w{1,50}\s?\.=\s?\$\w{1,50}{\$\w{1,50}}\s?\^\s?\$\w{1,50}{\$\w{1,50}};\s?\$\w{1,50}\s?=\s?"[^"]+";\s?}\s?}\s?return\s?\$\w{1,50};\s?}\s?(\$\w{1,50})\s?=\s?preg_replace\("([^"]+)",\s?"",\s?"([^"]+)"\);\s?(?:\s?\$\w{1,50}\s?=\s?(?:"[^"]+"|\w{1,50}\(\$\w{1,50}\("[^"]+"\)\)|\$\w{1,50}\(\)\.\s?\w{1,50}\(\$\w{1,50}\("[^"]+"\)\)|"[^"]+"\s*\.\s*\w+\(\$\w+\("[^"]+"\)\));\s?){1,50}(\$\w{1,50}\(\$\w{1,50},(?:\$\w{1,50}\.?)+\);)\s?(?:\$\w{1,50}\s?=\s?"[^"]+";\s?|include\s?\$\w{1,50};\s){1,50}~msi',
            'id' => 'funcVars',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";(?:\$\w+\s*=\s*(?:\1\[\d+\][\.;])+)+@?(?:\$\w+[\(,])+((?:\1\[\d+\][\.;\)])+)\)\),\$\w+\[\d+\],\$\w+\[\d+\]\);~msi',
            'fast' => '~(\$\w+)\s*=\s*"([^"]+)";(?:\$\w+\s*=\s*(?:\1\[\d+\][\.;])+)+@?(?:\$\w+[\(,])+((?:\1\[\d+\][\.;\)])+)\)\),\$\w+\[\d+\],\$\w+\[\d+\]\);~msi',
            'id' => 'dictVars',
        ],
        /*[
            'full' => '~goto \w+;\s*(\w+:\s*(\w+:\s*)?.*?goto\s*\w+;\s*(}\s*goto\s*\w+;)?(goto\s*\w+;)?\s*)+\w+:\s*[^;]+;(\s*goto\s*\w+;\s*\w+:\s*\w+:)?~msi',
            'fast' => '~goto \w+;\s*(\w+:\s*(\w+:\s*)?.*?goto\s*\w+;\s*(}\s*goto\s*\w+;)?(goto\s*\w+;)?\s*)+\w+:\s*[^;]+;(\s*goto\s*\w+;\s*\w+:\s*\w+:)?~msi',
            'id' => 'goto',
        ],*/

        /*[
            'full' => '~if\(isset\(\$_POST\[\'\w+\'\]\)\){echo[\s\'\w]+;\s*exit\(\);}\s*if\(isset\(\$_COOKIE\)\){(\$\w+)=\$_COOKIE;\(count\(\1\)==\d+&&in_array\(gettype\(\1\)\.count\(\1\),\1\)\)\?\(\(\1\[\d+\]=\1\[\d+\]\.\1\[\d+\]\)&&\(\1\[\d+\]=\1\[\d+\]\(\1\[\d+\]\)\)&&\(\1=\1\[\d+\]\(\1\[\d+\],\1\[\d+\]\(\1\[\d+\]\)\)\)&&\1\(\)\):\1;}\s*if\(!isset\(\$_POST\[\'\w+\'\]\)&&!isset\(\$_GET\[\'\w+\'\]\)\){exit\(\);}\s*(?:(\$\w+)\[\d+\]=\'\w+\';)+\s*if\(isset\(\$_POST\[\'\w+\'\]\)\){\$\w+=\$_POST\[\'\w+\'\];}else{\$\w+=\$_GET\[\'\w+\'\];}\s*\$\w+\s*=\s*array_flip\(str_split\(\'(\w+)\'\)\);\$\w+\s*=\s*str_split\(md5\(\$\w+\)\.md5\(\$\w+\)\);\$\w+\s*=\s*array\(\);\$\w+\s*=\s*\'\';\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{while\s*\(1\)\s*{if\(isset\(\$\w+\[\$\w+\[\$\w+\]\]\)\){\$\w+\[\$\w+\]\+\+;}else\{\$\w+\[\$\w+\[\$\w+\]\]=\'\';break;}}}\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{\$\w+\s*\.=\s*\$\w+\[\$\w+\];}\s*eval\(trim\(base64_decode\(base64_decode\(\$\w+\)\)\)\);~mis',
            'fast' => '~if\(isset\(\$_POST\[\'\w+\'\]\)\){echo[\s\'\w]+;\s*exit\(\);}\s*if\(isset\(\$_COOKIE\)\){(\$\w+)=\$_COOKIE;\(count\(\1\)==\d+&&in_array\(gettype\(\1\)\.count\(\1\),\1\)\)\?\(\(\1\[\d+\]=\1\[\d+\]\.\1\[\d+\]\)&&\(\1\[\d+\]=\1\[\d+\]\(\1\[\d+\]\)\)&&\(\1=\1\[\d+\]\(\1\[\d+\],\1\[\d+\]\(\1\[\d+\]\)\)\)&&\1\(\)\):\1;}\s*if\(!isset\(\$_POST\[\'\w+\'\]\)&&!isset\(\$_GET\[\'\w+\'\]\)\){exit\(\);}\s*(?:(\$\w+)\[\d+\]=\'\w+\';)+\s*if\(isset\(\$_POST\[\'\w+\'\]\)\){\$\w+=\$_POST\[\'\w+\'\];}else{\$\w+=\$_GET\[\'\w+\'\];}\s*\$\w+\s*=\s*array_flip\(str_split\(\'(\w+)\'\)\);\$\w+\s*=\s*str_split\(md5\(\$\w+\)\.md5\(\$\w+\)\);\$\w+\s*=\s*array\(\);\$\w+\s*=\s*\'\';\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{while\s*\(1\)\s*{if\(isset\(\$\w+\[\$\w+\[\$\w+\]\]\)\){\$\w+\[\$\w+\]\+\+;}else\{\$\w+\[\$\w+\[\$\w+\]\]=\'\';break;}}}\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{\$\w+\s*\.=\s*\$\w+\[\$\w+\];}\s*eval\(trim\(base64_decode\(base64_decode\(\$\w+\)\)\)\);~mis',
            'id' => 'scriptWithPass',
        ],*/

        /*************************************************************************************************************/
        /*                                          JS patterns                                                      */
        /*************************************************************************************************************/

        [
            'full' => '~(?:eval\()?String\.fromCharCode\(([\d,\s]+)\)+;~msi',
            'fast' => '~String\.fromCharCode\([\d,\s]+\)+;~msi',
            'id'   => 'JS_fromCharCode',
        ],
        [
            'full' => '~(?:eval\()?unescape\(\'([^\']+)\'\)\);\s{0,50}eval\(unescape\(\'([^\']+)\'\)\s{0,50}\+\s{0,50}\'([^\']+)\'\s{0,50}\+\s{0,50}unescape\(\'[^\']+\'\)\);~msi',
            'fast' => '~unescape\(\'([^\']+)\'\)\);\s{0,50}eval\(unescape\(\'([^\']+)\'\)\s{0,50}\+\s{0,50}\'([^\']+)\'\s{0,50}\+\s{0,50}unescape\(\'[^\']+\'\)\);~msi',
            'id'   => 'JS_unescapeContentFuncWrapped',
        ],

        /*************************************************************************************************************/
        /*                                          PYTHON patterns                                                 */
        /*************************************************************************************************************/

        [
            'full' => '~eval\(compile\(zlib\.decompress\(base64\.b64decode\([\'"]([^\'"]+)[\'"]\)\),[\'"]<string>[\'"],[\'"]exec[\'"]\)\)~msi',
            'fast' => '~eval\(compile\(zlib\.decompress\(base64\.b64decode\([\'"]([^\'"]+)[\'"]\)\),[\'"]<string>[\'"],[\'"]exec[\'"]\)\)~msi',
            'id'   => 'PY_evalCompileStr',
        ],
    ];

    private $full_source;
    private $prev_step;
    private $cur;
    private $obfuscated;
    private $max_level;
    private $max_time;
    private $run_time;
    private $fragments;
    private $grabed_signature_ids;

    public function __construct($text, $text2 = '', $max_level = 30, $max_time = 5)
    {
        $temp = str_replace(' ', '', $text);
        if (
            (strpos($temp, '=file(__FILE__);eval(base64_decode(')   //zeura hack
             && strpos($temp, '1)));__halt_compiler();'))
            || (strpos($temp, 'define(\'__LOCALFILE__\',__FILE__);')   //obf_20200527_1
                && strpos($temp, '__halt_compiler();'))
            || (strpos($text2, '0=__FILE__;')
                && strpos($text2, ';return;?>')) //lockit1
            || (strpos($temp, '");$cvsu=$gg')) //TinkleShell
            || (strpos($text2, 'The latest version of Encipher can be obtained from')
                && strpos($text2, '\'@ev\'));')) //EvalFileContent
            || (strpos($text2, 'substr(file_get_contents(__FILE__),')
                && strpos($text2, '__halt_compiler();')) //EvalFileContentOffset
        ) {
            $this->text = $text2;
            $this->full_source = $text2;
        } else {
            $this->text = $text;
            $this->full_source = $text;
        }
        $this->max_level = $max_level;
        $this->max_time = $max_time;
        $this->fragments = [];
        $this->grabed_signature_ids = [];
    }

    public function getObfuscateType($str)
    {
        $str = preg_replace('~\s+~', ' ', $str);
        $l_UnicodeContent = Helpers::detect_utf_encoding($str);
        if ($l_UnicodeContent !== false) {
            if (function_exists('iconv')) {
                $str = iconv($l_UnicodeContent, "CP1251//IGNORE", $str);
            }
        }
        if(strpos($str, '# Malware list detected by AI-Bolit (http') !== false) {
            return '';
        }
        if(strpos($str, '#Malware list detected by AI-Bolit(http') !== false) {
            return '';
        }
        if(strpos($str, '<div class="header">Отчет сканера AI-Bolit</div>') !== false) {
            return '';
        }
        if (strpos($str, '$default_action="FilesMan"') !== false) {
            return '';
        }
        foreach ($this->signatures as $signature) {
            if (preg_match($signature['fast'], $str, $matches)) {
                if ($signature['id'] === 'echo') {
                    if (preg_match('~\$_(POST|GET|REQUEST|COOKIE)~ms', $matches[0])) {
                        return '';
                    }
                    if (!isset($matches[5]) || $matches[5] === '') {
                        return '';
                    }
                }
                if ($signature['id'] === 'eval') {
                    if (strpos($matches[0], 'file_get_contents') !== false) {
                        return '';
                    }
                    if (preg_match('~\$_(POST|GET|REQUEST|COOKIE)~ms', $matches[0])) {
                        return '';
                    }
                    if (strpos($matches[0], '=> array(\'eval(base64_decode(\')') !== false) {
                        return '';
                    }
                    if (@$matches[6] == '\'";') {
                        return '';
                    }
                }
                return $signature['id'];
            }
        }
        return '';
    }

    private function getObfuscateFragment($str)
    {
        foreach ($this->signatures as $signature) {
            if (preg_match($signature['full'], $str, $matches)) {
                return $matches;
            }
        }
        return '';
    }

    public function getFragments()
    {
        if (count($this->fragments) > 0) {
            return $this->fragments;
        }
        return false;
    }

    public function getGrabedSignatureIDs()
    {
        return array_keys($this->grabed_signature_ids);
    }

    private function grabFragments()
    {
        if ($this->cur == null) {
            $this->cur = $this->text;
        }
        $str = $this->cur;
        reset($this->signatures);
        while ($sign = current($this->signatures)) {
            $regex = $sign['full'];
            if (preg_match($regex, $str, $matches)) {
                $this->grabed_signature_ids[$sign['id']] = 1;
                $this->fragments[$matches[0]] = $matches[0];
                $str = str_replace($matches[0], '', $str);
            } else {
                next($this->signatures);
            }
        }
    }

    private function deobfuscateFragments()
    {
        $prev_step = '';
        if (count($this->fragments) > 0) {
            $i = 0;
            foreach ($this->fragments as $frag => $value) {
                if ($frag !== $value) {
                    continue;
                }
                $type = $this->getObfuscateType($value);
                while ($type !== '' && $i < 50) {
                    $match = $this->getObfuscateFragment($value);
                    $find = $match[0] ?? '';
                    $func = 'deobfuscate' . ucfirst($type);
                    $temp = @$this->$func($find, $match);
                    $value = str_replace($find, $temp, $value);
                    $this->fragments[$frag] = $value;
                    $type = $this->getObfuscateType($value);
                    if ($prev_step == hash('sha256', $value)) {
                        break;
                    } else {
                        $prev_step = hash('sha256', $value);
                    }
                    $i++;
                }
            }
        }
    }

    public function deobfuscate($hangs = 0, $prev_step = '')
    {
        $deobfuscated = '';
        $this->run_time = microtime(true);
        $this->cur = $this->text;
        $this->grabFragments();
        $this->deobfuscateFragments();
        $deobfuscated = $this->cur;
        if (count($this->fragments) > 0 ) {
            foreach ($this->fragments as $fragment => $text) {
                $deobfuscated = str_replace($fragment, $text, $deobfuscated);
            }
        }

        $deobfuscated = preg_replace_callback('~"[\w\\\\\s=;_<>&/\.-]+"~msi', function ($matches) {
            return preg_match('~\\\\x[2-7][0-9a-f]|\\\\1[0-2][0-9]|\\\\[3-9][0-9]|\\\\0[0-4][0-9]|\\\\1[0-7][0-9]~msi', $matches[0]) ? stripcslashes($matches[0]) : $matches[0];
        }, $deobfuscated);

        $deobfuscated = preg_replace_callback('~echo\s*"((.*?[^\\\\])??((\\\\\\\\)+)?+)"~msi', function ($matches) {
            return preg_match('~\\\\x[2-7][0-9a-f]|\\\\1[0-2][0-9]|\\\\[3-9][0-9]|\\\\0[0-4][0-9]|\\\\1[0-7][0-9]~msi', $matches[0]) ? stripcslashes($matches[0]) : $matches[0];
        }, $deobfuscated);

        preg_match_all('~(global\s*(\$[\w_]+);)\2\s*=\s*"[^"]+";~msi', $deobfuscated, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $deobfuscated = str_replace($match[0], '', $deobfuscated);
            $deobfuscated = str_replace($match[1], '', $deobfuscated);
        }

        preg_match_all('~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];~msi', $deobfuscated, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $deobfuscated = preg_replace_callback('~\$\{\$\{"GLOBALS"\}\[[\'"]' . $match[1] . '[\'"]\]\}~msi', function ($matches) use ($match) {
                return '$' . $match[2];
            }, $deobfuscated);
            $deobfuscated = str_replace($match[0], '', $deobfuscated);
        }

        $deobfuscated = preg_replace_callback('~\$\{(\$\w+)\}~msi', function ($matches) use ($deobfuscated) {
            if (isset($matches[1])) {
                preg_match('~\\' . $matches[1] . '\s*=\s*["\'](\w+)[\'"];~msi', $deobfuscated, $matches2);
                if (isset($matches2[1])) {
                    return '$' . $matches2[1];
                }
                return $matches[0];
            }
        }, $deobfuscated);

        if (strpos($deobfuscated, 'chr(')) {
            $deobfuscated = preg_replace_callback('~chr\((\d+)\)~msi', function ($matches) {
                return "'" . chr($matches[1]) . "'";
            }, $deobfuscated);
        }

        if (substr_count(substr($deobfuscated, 0, 200), 'base64_decode(\'') > 3) {
            $deobfuscated = preg_replace_callback('~base64_decode\(\'([^\']+)\'\)~msi', function ($matches) {
                return "'" . base64_decode($matches[1]) . "'";
            }, $deobfuscated);
        }

        if ($this->getObfuscateType($deobfuscated) !== '' && $hangs < 6) {
            $this->text = $deobfuscated;
            if ($prev_step == hash('sha256', $deobfuscated)) {
                return $deobfuscated;
            }
            $deobfuscated = $this->deobfuscate(++$hangs, hash('sha256', $deobfuscated));
        }
        return $deobfuscated;
    }

    private function deobfuscateStrrotPregReplaceEval($str, $matches)
    {
        $find = $matches[0];
        $res = str_rot13($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200618_1($str)
    {
        preg_match('~(\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\]="[\w\\\\]+";(\$\w+="\w+";)?)+.+\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\].+}+~msi', $str, $matches);
        $find = $matches[0];
        $res = stripcslashes($str);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateBypass($str, $matches)
    {
        $find = $matches[0];
        $bypass = stripcslashes($matches[2]);
        $eval = $matches[3] . $bypass . $matches[4];
        $res = str_replace($find, $eval, $str);
        return $res;
    }

    private function deobfuscateObf_20200720_1($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }



    private function deobfuscateGoto($str)
    {
        preg_match('~goto \w+;\s*(\w+:\s*(\w+:\s*)?.*?goto\s*\w+;\s*(}\s*goto\s*\w+;)?(goto\s*\w+;)?\s*)+\w+:\s*[^;]+;(\s*goto\s*\w+;\s*\w+:\s*\w+:)?~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $labels = [];
        preg_match_all('~((\w+):\s*((\w+):\s*)?(.*?goto\s*\w+;))(\s*goto\s*\w+;)?~msi', $str, $matches, PREG_SET_ORDER);
        foreach($matches as $item) {
            if (isset($item[4]) && $item[4] != '') {
                $labels[$item[4]] = $item[5];
            }
            $labels[$item[2]] = $item[5];
            $res = str_replace($item[1], '', $res);
        }
        while(preg_match('~goto\s*(\w+);~msi', $res, $matches) && isset($labels[$matches[1]])) {
            $res = str_replace($matches[0], PHP_EOL . $labels[$matches[1]] . PHP_EOL, $res);
        }

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200527_1($str)
    {
        preg_match('~error_reporting\(0\);define\(\'\w+\',\s*__FILE__\);define\(\'\w+\',\s*fopen\(__FILE__,\s*\'r\'\)\);fseek\(\w+,\s*__COMPILER_HALT_OFFSET__\);((\$\w+="\\\\x[0-9a-f]+";)+(\$\w+="[^"]+";)+eval\("\?>"\.(\$\w+\()+"([^"]+)"\)+;)+(?:/\*\w+\*/)?__halt_compiler\(\);([\w#|>^%\[\.\]\\\\/=]+)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $encoded = $matches[6];
        $res = preg_replace_callback('~(\$\w+="\\\\x[0-9a-f]+";)+(\$\w+="[^"]+";)+eval\("\?>"\.(\$\w+\()+"([^"]+)"\)+;~msi', function ($m) use ($str) {
            $layer1 = hex2bin(str_rot13(gzinflate(str_rot13(base64_decode($m[4])))));
            if (preg_match('~(\$\w+="[^"]+";)+eval\(\$\w\.(\$\w+\()+"([^"]+)"\)+;~msi', $layer1, $matches)) {
                $temp = "?>" . hex2bin(str_rot13(gzinflate(str_rot13(base64_decode($matches[3])))));
                while (preg_match('~(\$\w+)=strrev\(\1\);(\1=\s*str_replace\([\'"]([^"\']+)[\'"],"[^"]+",\1\);)+@?eval\("\?\>"\.\$\w+\(\1\)+;~msi', $temp, $matches)) {
                    if (preg_match('~\\' . $matches[1] . '="([^"]+)";~msi', $layer1, $matches1)) {
                        $code = $matches1[1];
                        $code = strrev($code);
                        if (preg_match_all('~str_replace\([\'"]([^"\']+)[\'"],"([^"]+)"~msi', $temp, $m, PREG_SET_ORDER)) {
                            foreach($m as $item) {
                                $code = str_replace($item[1], $item[2], $code);
                            }
                            $temp = base64_decode($code);
                        }
                    }
                }
                return $temp;
            }
        }, $res);
        if (preg_match_all('~str_replace\([\'"]([^"\']+)[\'"],[\'"]([^"\']+)[\'"]~msi', $res, $m, PREG_SET_ORDER)) {
            foreach($m as $item) {
                $encoded = str_replace($item[1], $item[2], $encoded);
            }
            $res = base64_decode($encoded);
        }

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200602_1($str)
    {
        preg_match('~(\$\w+)=strrev\("[base64_decode]+"\)\.str_replace\(\'(\w+)\',\'\',\'\w+\'\);\s*eval\(\1\((\$\w+)\)\);~msi', $str, $matches);
        $find = $matches[0];
        $res = 'eval(base64_decode(' . $matches[3] . '));';
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200526_1($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200522_1($str, $matches)
    {
        $find = $matches[0];
        $res = strrev(gzinflate(base64_decode(substr($matches[9], (int)hex2bin($matches[3]), (int)hex2bin($matches[5])))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_5($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[1]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_4($str, $matches)
    {
        $find = $matches[0];
        $ar = $matches[2];
        $ar = explode(",\n", $ar);
        $array = [];
        foreach ($ar as $v) {
            $array[substr(trim($v),1,1)] = substr(trim($v), -2, 1);
        }
        unset($ar);
        $res = '';
        $split = str_split($matches[5]);
        foreach ($split as $x) {
            foreach ($array as $main => $val) {
                if ($x == (string)$val) {
                    $res .= $main;
                    break;
                }
            }
        }
        $res = gzinflate(base64_decode($res));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200513_1($str, $matches)
    {
        $find = $matches[0];
        $res = gzuncompress(base64_decode(strrev($matches[5])));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_3($str, $matches)
    {
        $find = $matches[0];
        $decode = htmlspecialchars_decode(gzinflate(base64_decode($matches[2])));
        $res = str_replace('$An0n_3xPloiTeR', "'" . $matches[3] . "'", $decode);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_2($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[4]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_1($str)
    {
        preg_match('~(\$\w+)=base64_decode\(\'([^\']+)\'\);\s*eval\(\1\);~mis', $str, $matches);
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200504_1($str)
    {
        preg_match('~(\$\w+)\s*=\s*\("\?>"\.gzuncompress\(base64_decode\("([^"]+)"\)\)\);\s*@?eval\(\1\);~msi', $str, $matches);
        $find = $matches[0];
        $res = ' ?>' . gzuncompress(base64_decode($matches[2]));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSmartToolsShop($str, $matches)
    {
        $find = $matches[0];
        $res = str_rot13(gzinflate(str_rot13(base64_decode($matches[2]))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200421_1($str)
    {
        preg_match('~(?:\$\w+\s*=\s*\'\w+\';)?\s*(\$\w+)\s*=\s*urldecode\(\'[%0-9a-f]+\'\);(\s*(\$\w+)\s*=(\s*\1\{\d+\}\.?)+;)+\s*(\$\w+)\s*=\s*"[^"]+"\.\3\("([^"]+)"\);\s*eval\(\5\);~msi', $str, $matches);
        $find = $matches[0];
        $res = ' ?>' . base64_decode($matches[6]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200414_1($str, $matches)
    {
        $data = $matches[1];
        $key = $matches[2];
        $res = Helpers::obf20200414_1_decrypt($data, $key);
        return $res;
    }

    private function deobfuscateObf_20200402_2($str, $matches)
    {
        $find = $matches[0];
        $code = $matches[15];
        $code = preg_replace_callback('~\s*"\s*\.((?:min|max|round)?\(\s*\d+[\.\,\|\s\|+\|\-\|\*\|\/]([\d\s\.\,\+\-\*\/]+)?\))\s*\.\s*"~msi', function($m) {
            return substr(Helpers::calc($m[1]), 1, -1);
        }, $code);
        $res = gzinflate(base64_decode($code)) ?:base64_decode($code);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200402_1($str, $matches)
    {
        $find = $matches[0];
        $res = gzinflate(hex2bin(pack('H*',$matches[6])));
        $res = preg_replace('~//.+$~m', '', $res);
        preg_match('~\$\w+\(\$\w+,\$\w+\("",\s*\$\w+\(\$\w+\(\$\w+\(\$\w+\(\$\w+,\s*"(\d+)"\)+,\$\w+\);.+function \w+\((\$\w+),\s*\$\w+,\s(\$\w+)\)\s{\3\s=\s\3\s\.\s\3;.+return \2;}~msi', $res, $matches);
        $res = gzinflate(hex2bin(pack('H*',$matches[1])));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateOELove($str)
    {
        preg_match('~<\?php\s*defined\(\'[^\']+\'\)\s*\|\|\s*define\(\'[^\']+\',__FILE__\);(global\s*\$[^;]+;)+\s*(if\(!function_exists\(\'([^\']+)\'\)\){\s*function\s*[^\)]+\(\$[^,]+,\$[^=]+=\'\'\){\s*if\(empty\(\$[^\)]+\)\)\s*return\s*\'\';\s*\$[^=]+=base64_decode\(\$[^\)]+\);\s*if\(\$[^=]+==\'\'\)\s*return\s*\~\$[^;]+;\s*if\(\$[^=]+==\'-1\'\)\s*@[^\(]+\(\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^\)]+\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^,]+,\$[^,]+,\$[^\)]+\);\s*return\s*\$[^^]+\^\$[^;]+;\s*}}\s*)+(\$[^\[]+\["[^"]+"]=[^\(]+\(\'[^\']+\',\'[^\']*\'\);\s*)+(\$[^\[]+\[\'[^\']+\'\]=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\([^\)]*\)+;\s*)+return\(eval\(\$[^\[]+\[\'[^\']+\'\]\)+;\s*\?>\s*#!/usr/bin/php\s*-q\s*((\s*[^\s]+)+)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $code = $matches[6];
        $res = iconv('UTF-8', 'ASCII//IGNORE', $res);

        preg_match('~\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\'([\da-f]{32})\'\);~msi', $res, $hash);
        $hash = strrev($hash[1]);
        preg_match_all('~\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\'([\d]{10})\'\)~msi', $res, $substr_offsets);
        $substr_offsets = $substr_offsets[1];
        $substr_offsets = array_map('strrev', $substr_offsets);
        $substr_offsets = array_map('intval', $substr_offsets);

        preg_match_all('~if\s*\(\!function_exists\(\'([^\']+)\'\)~msi', $res, $decoders);
        $decoders = $decoders[1];
        $var_array = [];
        preg_match_all('~\$([^\[]{3,20})\["([^"]+)"\]=(?:' . $decoders[0] . '|' . $decoders[1] . ')\(\'([^\']*)\',\'([^\']*)\'\);~msi', $res, $vars, PREG_SET_ORDER);
        $var_name = $vars[0][1];
        foreach ($vars as $var) {
            $var_array[$var[2]] = Helpers::OELoveDecoder($var[3], $var[4]);
            $res = str_replace($var[0], '', $res);
        }
        $layer1 = substr($code, 0, $substr_offsets[3] + 96);
        $layer1_dec = iconv('UTF-8', 'ASCII//IGNORE', gzuncompress(base64_decode($layer1)));
        $code = str_replace($layer1, $layer1_dec, $code);
        preg_match_all('~\$([^\[]{3,20})\["([^"]+)"\]=(?:' . $decoders[0] . '|' . $decoders[1] . ')\(\'([^\']*)\',\'([^\']*)\'\);~msi', $code, $vars, PREG_SET_ORDER);
        foreach ($vars as $var) {
            $var_array[$var[2]] = Helpers::OELoveDecoder($var[3], $var[4]);
            $code = str_replace($var[0], '', $code);
        }
        $layer2_start = strpos($code, '?>') + 2;
        $layer2 = substr($code, $layer2_start + $substr_offsets[2]);
        $layer2_dec = iconv('UTF-8', 'ASCII//IGNORE', gzuncompress(base64_decode(str_rot13($layer2))));
        $res = $layer2_dec;
        foreach($var_array as $k => $v) {
            $res = str_replace('$GLOBALS[\'' . $var_name . '\'][\'' . $k . '\'](', $v . '(', $res);
            $res = str_replace('$GLOBALS[\'' . $var_name . '\'][\'' . $k . '\']', '\'' . $v . '\'', $res);
        }

        $res = preg_replace_callback('~(?:' . $decoders[0] . '|' . $decoders[1] . ')\(\'([^\']*)\',\'([^\']*)\'\)~msi', function ($m) {
            return '\'' . Helpers::OELoveDecoder($m[1], $m[2]) . '\'';
        }, $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalConcatVars($str)
    {
        preg_match('~((\$\w+="";\$\w+\s*\.=\s*"[^;]+;\s*)+)(?:="";)?(eval\((\s*(\$\w+)\s*\.)+\s*"([^"]+)(?:"\);)+)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $parts = [];
        preg_match_all('~(\$\w+)="";\1\s*\.=\s*"([^"]+)"~msi', $matches[1], $matches1, PREG_SET_ORDER);
        foreach($matches1 as $match) {
            $parts[$match[1]] = stripcslashes(stripcslashes($match[2]));
        }
        $res = stripcslashes(stripcslashes($matches[3]));
        foreach($parts as $k => $v) {
            $res = str_replace($k, "'" . $v . "'", $res);
        }
        $res = preg_replace_callback('/[\'"]\s*?\.+\s*?[\'"]/smi', function($m) {
            return '';
        }, $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalAssignedVars($str, $matches)
    {
        $res = $str;

        $vars = [$matches[1] => $matches[2]];

        $res = preg_replace_callback('~(\$\w{1,3000})=(base64_decode|gzinflate|convert_uudecode|str_rot13)\((\$\w{1,3000})\);~msi',
            function ($match) use (&$vars) {
                $func = $match[2];
                if (Helpers::isSafeFunc($func) && isset($vars[$match[3]])) {
                    $vars[$match[1]] = @$func($vars[$match[3]]);
                    return '';
                }
                return $match[1] . '=' . $match[2] . '(\'' . $match[3] . '\';';
            }, $res);

        $res = $vars[$matches[4]] ?? Helpers::replaceVarsFromArray($vars, $res);

        return $res;
    }

    private function deobfuscateVarFuncsEval($str)
    {
        preg_match('~((\$\w+)\s*=\s*)(base64_decode\s*\(+|gzinflate\s*\(+|strrev\s*\(+|str_rot13\s*\(+|gzuncompress\s*\(+|convert_uudecode\s*\(+|urldecode\s*\(+|rawurldecode\s*\(+|htmlspecialchars_decode\s*\(+)+"([^"]+)"\)+(;\s*@?eval\(([\'"?>.\s]+)?\2\);)~', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = str_replace($matches[5], ');', $res);
        $res = str_replace($matches[1], 'eval(', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateComments($str, $matches)
    {
        $find = $matches[0];
        $res = preg_replace('~/\*\w+\*/~msi', '', $str);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrrevVarEval($str)
    {
        preg_match('~(\$\w+=strrev\("[^"]+"\);)+eval\((\$\w+\()+"([^"]+)"\)+;~mis', $str, $matches);
        $find = $matches[0];
        $res = gzinflate(base64_decode($matches[3]));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateAanKFM($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $key = Helpers::aanKFMDigitsDecode($matches[3]);
        $res = Helpers::Xtea_decrypt($matches[4], $key);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalChars($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        while(preg_match_all('~(?:@eval((?:\(\$[0O]+\[[\'"]\w+[\'"]\])+)\("([^"]+)"\)+;)|("\)\?\$[O0]+)~msi', $res, $matches, PREG_SET_ORDER)) {
            $match = $matches[0];
            if (isset($matches[1])) $match = $matches[1];
            $count = ($match[1] !== '') ? substr_count($match[1], '(') : 0;
            if ($count == 2) {
                $res = gzinflate(base64_decode($match[2]));
            } else if ($count == 3) {
                $res = gzinflate(base64_decode(str_rot13($match[2])));
            }
            if (isset($match[3]) && ($match[3] !== '')) {
                $res = preg_replace_callback('~(\$[0O]+\["\w+"\]\()+"([^"]+)"\)+;?~msi', function($m) {
                    return gzinflate(base64_decode(str_rot13($m[2])));
                }, $res);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateGlobalsBase64($str)
    {
        preg_match('~<\?php\s+((\$GLOBALS\[\s*[\'"]\w+[\'"]\s*\])\s*=\s*base64_decode\("([^"]*)"\);)+\s*\?>(<\?php\s.+\2.+exit;\s}\sfunction\s\w+\(\)\s{\sreturn\sarray\(\s\'favicon\'\s=>\s\'[^\']+\',\s+\'sprites\'\s=>\s\'[^\']+\',\s\);\s})~msi', $str, $matches);
        $find = $matches[0];
        $vars = [];
        preg_match_all('~(\$GLOBALS\[\s*[\'"]\w+[\'"]\s*\])\s*=\s*base64_decode\("([^"]*)"\);~msi', $matches[0], $matches1, PREG_SET_ORDER);
        foreach($matches1 as $match) {
            $vars[$match[1]] = base64_decode($match[2]);
        }
        $code = $matches[4];
        foreach ($vars as $var => $value) {
            $code = str_replace($var . '(', $value . '(', $code);
            $code = str_replace($var, "'" . $value . "'", $code);
        }
        $res = $code;
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalReturn($str, $matches)
    {
        $find = $matches[0];
        $res = stripcslashes(base64_decode($matches[2]));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateQibosoft($str)
    {
        preg_match('~\$\w+=__FILE__;\$\w+=fopen\(\$\w+,\'rb\'\);fread\(\$\w+,(\d+)\);\$\w+=explode\("\\\\t",base64_decode\(fread\(\$\w+,(\d+)\)+;\$\w+=\$\w+\[[\d+]\];[\$l1=\d{}\.;\(\)\[\]]+eval\(\$\w+\(\'([^\']+)\'\)+;\s*return\s*;\?>[\w=\+]+~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $hangs = 15;
        $obfPHP = explode('?>', $str);
        $obfPHP = $obfPHP[1];
        preg_match('~eval\(\$\w+\(\'([^\']+)\'\)+;~msi', $res, $temp);
        $res = str_replace($temp[0], base64_decode($temp[1]), $res);
        $offset = $matches[2];
        while (preg_match('~\$\w+\(\$\w+,(\d+)\);\s*eval\(\$\w+\(\$\w+\(\$\w+,(\d+)\)+;~msi', $res, $temp2) && $hangs--) {
            $offset += $temp2[1];
            $decode_loop = base64_decode(substr($obfPHP, $offset, $temp2[2]));
            $offset += $temp2[2];
            if (preg_match('~eval\(\$\w+\(\'([^\']+)\'\)+;~msi', $decode_loop, $temp)) {
                $res = str_replace($temp2[0], base64_decode($temp[1]), $res);
            } else {
                $res = $decode_loop;
            }

        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUd64($str)
    {
        preg_match('~(\$ud64_c[o0]m="[\\\\0-9a-z\."]+;)+\$\w+=(\$ud64_c[o0]m\()+"([^"]+)"\)+;@eval\(\$ud64_c[o0]m\(\'[^\']+\'\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = gzinflate(convert_uudecode(base64_decode(gzinflate(base64_decode(str_rot13($matches[3]))))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateCustom1($str)
    {
        preg_match('~\$\w+="([^"]+)";\$l+=0;\$l+=\'base64_decode\';\$l+=0;eval\(.+?;eval\(\$l+\);return;~msi', $str, $matches);
        $find = $matches[0];
        $res = Helpers::someDecoder3($matches[1]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateCustom2($str, $matches)
    {
        $find = $matches[0];
        $key = $matches[2];
        $var = $matches[3];
        preg_match_all('~\\' . $var . '\[\d+\]\s*=\s*"([^"]+)";~msi', $str, $matches);
        $res = base64_decode(Helpers::someDecoder4($matches[1], $key));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateLockIt2($str, $matches)
    {
        $find = $matches[0];
        $res = $matches[1];

        if(strpos($str, '$_X="') !== false && strpos($res, '\\x') !== false) {
            $res = stripcslashes($res);
        }
        if (preg_match_all('~\$[_\w]+\.=[\'"]([\w\+\/=]+)[\'"];~', $matches[0], $concatVars)) {
            foreach ($concatVars[1] as $concatVar) {
                $res .= $concatVar;
            }
        }
        $res = base64_decode($res);
        $res = strtr($res, $matches[2], $matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateAnaski($str, $matches)
    {
        $find = $matches[0];

        $res = gzinflate(str_rot13(base64_decode($matches[2])));
        $res = strtr($res, $matches[5], $matches[6]);

        return $res;
    }

    private function deobfuscateFuncs($str, $matches)
    {
        $find = $matches[0];
        $funcs = [];
        $payload = $matches[7];
        $var = $matches[6];
        $res = $str;
        $res = preg_replace_callback('~function\s*(\w+)\((\$\w+)\){\s*return\s*(\w+)\(\2(,\d+)?\);}\s*~msi', function($matches2) use (&$funcs){
            $funcs[$matches2[1]] = $matches2[3];
            return '';
        }, $res);
        foreach ($funcs as $k => $v) {
            $res = str_replace($k . '(', $v . '(', $res);
        }
        $res = str_replace($var . '="' . $payload . '";', '', $res);
        $res = str_replace($var, '"' . $payload . '"', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSubstr($str)
    {
        preg_match('~\$\w+=0;(\$GLOBALS\[\'\w+\'\])\s*=\s*\'([^\']+)\';\s*(\$\w+)=pack\(\'H\*\',substr\(\1,\s*([-\d]+)\)\);if\s*\(!function_exists\(\'(\w+)\'\)\){function\s*\5\(\$\w+,\s*\$\w+\){\$\w+=\1;\s*\$d=pack\(\'H\*\',substr\(\1,\s*\4\)\);\s*return\s*\$\w+\(substr\(\$\w+,\s*\$\w+,\s*\$\w+\)\);}};eval\(\3\(\'([^\']+)\'\)\);~msi', $str, $matches);
        $find = $matches[0];
        $substr_array = $matches[2];
        $offset = intval($matches[4]);
        $func = $matches[5];
        $eval = pack('H*',substr($substr_array, $offset));
        $res = Helpers::isSafeFunc($eval) ? @$eval($matches[6]) : $matches[6];
        $res = preg_replace_callback('~' . $func . '\(([-\d]+),\s*([-\d]+)\)~mis', function ($matches) use ($eval, $substr_array) {
            $res = Helpers::isSafeFunc($eval) ? @$eval(substr($substr_array, $matches[1], $matches[2])) : $matches[0];
            return '\'' . $res . '\'';
        }, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscatePHPJiaMi($str, $matches)
    {
        $find = $matches[0];
        $bin = bin2hex($str);
        preg_match('~6257513127293b24[a-z0-9]{2,30}3d24[a-z0-9]{2,30}2827([a-z0-9]{2,30})27293b~', $bin, $hash);
        preg_match('~2827([a-z0-9]{2})27293a24~', $bin, $rand);
        $hash = hex2bin($hash[1]);
        $rand = hex2bin($rand[1]);
        $res = Helpers::PHPJiaMi_decoder(substr($matches[3], 0, -45), $hash, $rand);

        $res = str_rot13(@gzuncompress($res) ? @gzuncompress($res) : $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalIReplace($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $res = base64_decode($matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateErrorHandler($str)
    {
        preg_match('~(\$\w+)="[^"]+";\s*(\$\w+)=str_ireplace\("[^"]+","",\1\);(\$\w+)\s*=\s*"([^"]+)";\s*function\s*(\w+)\((\$\w+,?)+\){\s*(\$\w+)=\s*create_function\(\'\',\$\w+\);\s*array_map\(\7,array\(\'\'\)+;\s*}\s*set_error_handler\(\'\5\'\);(\$\w+)=\2\(\3\);user_error\(\8,E_USER_ERROR\);\s*if\s*.+?}~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = base64_decode($matches[4]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrtoupper($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $alph = $matches[2];
        $var = $matches[1];
        $res = str_replace("{$var}=\"{$alph}\";", '', $res);
        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        $res = str_replace("' . '", '', $res);
        $res = str_replace("' '", '', $res);
        preg_match('~(\$\w+)\s*=\s*strtoupper\s*\(\s*\'(\w+)\'\s*\)\s*;~msi', $res, $matches);
        $matches[2] = strtoupper($matches[2]);
        $res = str_replace($matches[0], '', $res);
        $res = preg_replace_callback('~\${\s*\\'. $matches[1] .'\s*}~msi', function ($params) use ($matches) {
            return '$' . $matches[2];
        }, $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEval2($str)
    {
        preg_match('~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)")*)";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."([^"]+)"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi', $str, $matches);
        $res = $str;
        $find = $matches[0];
        $alph = $matches[2];
        $var = $matches[1];
        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        $res = gzinflate(base64_decode(substr($matches[7], 1, -1)));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalEregReplace($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        preg_match_all('~(\$\w+)\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);~smi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $res = preg_replace('/' . $match[2] . '/', $match[3], $res);
        }
        $res = base64_decode($res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrreplace($str, $matches)
    {
        $find = $matches[0];
        $res = $str;

        $str_replace = '';
        $base64_decode = '';
        $layer = '';

        preg_match_all('~(\$\w+)\s*=\s*[\'"](?|([^\']+)\'|([^"]+)");~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $i => $match) {
            $vars[$match[1]] = $match[2];
        }

        $res = preg_replace_callback('~(\$\w+)\s*=\s*str_replace\([\'"](\w+)[\'"],\s*[\'"]{2},\s*[\'"](\w+)[\'"]\)~msi',
            function ($matches) use (&$vars, &$str_replace) {
                $vars[$matches[1]] = str_replace($matches[2], "", $matches[3]);
                if ($vars[$matches[1]] == 'str_replace') {
                    $str_replace = $matches[1];
                }
                $tmp = $matches[1] . ' = "' . $vars[$matches[1]] . '"';

                return $tmp;
            }, $res);

        if ($str_replace !== '') {
            $res = preg_replace_callback('~(\$\w+)\s*=\s*\\' . $str_replace . '\("(\w+)",\s*"",\s*"(\w+)"\)~msi',
                function ($matches) use (&$vars, &$base64_decode) {
                    $vars[$matches[1]] = str_replace($matches[2], "", $matches[3]);
                    if ($vars[$matches[1]] == 'base64_decode') {
                        $base64_decode = $matches[1];
                    }
                    $tmp = $matches[1] . ' = "' . $vars[$matches[1]] . '"';

                    return $tmp;
                }, $res);

            $res = preg_replace_callback('~\\' . $base64_decode . '\(\\' . $str_replace . '\("(\w+)",\s*"",\s*([\$\w\.]+)\)~msi',
                function ($matches) use (&$vars, &$layer) {
                    $tmp = explode('.', $matches[2]);
                    foreach ($tmp as &$item) {
                        $item = $vars[$item];
                    }
                    $tmp = implode('', $tmp);
                    $layer = base64_decode(str_replace($matches[1], "", $tmp));

                    return $matches[0];
                }, $res);
        }


        if ($base64_decode !== '') {
            $regex = '~\\' . $base64_decode . '\(\\' . $str_replace . '\("(\w+)",\s*"",\s*([\$\w\.]+)\)~msi';
        } else {
            $regex = '~str_replace\([\'"]([^\'"]+)[\'"],\s*[\'"]{2},\s*([\$\w\.]+)\);\s?(\$\w+)=\$\w+\([\'"]{2},\$\w+\);\3\(\);~msi';
        }

        $res = preg_replace_callback($regex,
            function ($matches) use (&$vars, &$layer, $base64_decode) {
                $tmp = explode('.', $matches[2]);
                foreach ($tmp as &$item) {
                    $item = $vars[$item];
                }
                $tmp = implode('', $tmp);
                $layer = str_replace($matches[1], "", $tmp);
                if ($base64_decode !== '') {
                    $layer = base64_decode($layer);
                }

                return $matches[0];
            }, $res);

        $res = $layer;
        $res = str_replace($find, $res, $str);

        return $res;
    }

    private function deobfuscateSeolyzer($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $vars = [];
        $base64_decode = '';
        $layer = '';
        $gzuncompress = '';
        preg_match_all('~(\$\w+)\s*=\s*\'([^\']+)\'\s*;~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $i => $match) {
            $vars[$match[1]] = $match[2];
            if ($match[2] == 'base64_decode') {
                $base64_decode = $match[1];
            }
        }

        $res = preg_replace_callback('~\s*=\s*\\' . $base64_decode . '\((\$\w+)\)~msi', function ($matches) use (&$vars, &$gzuncompress, &$layer) {
            if (isset($vars[$matches[1]])) {
                $tmp = base64_decode($vars[$matches[1]]);
                if ($tmp == 'gzuncompress') {
                    $gzuncompress = $matches[1];
                }
                $vars[$matches[1]] = $tmp;
                $tmp = " = '{$tmp}'";
            } else {
                $tmp = $matches[1];
            }
            return $tmp;
        }, $res);

        if ($gzuncompress !== '') {
            $res = preg_replace_callback('~\\' . $gzuncompress . '\(\s*\\' . $base64_decode . '\((\$\w+)\)~msi',
                function ($matches) use (&$vars, $gzuncompress, &$layer) {
                    if (isset($vars[$matches[1]])) {
                        $tmp = gzuncompress(base64_decode($vars[$matches[1]]));
                        $layer = $matches[1];
                        $vars[$matches[1]] = $tmp;
                        $tmp = "'{$tmp}'";
                    } else {
                        $tmp = $matches[1];
                    }
                    return $tmp;
                }, $res);
            $res = $vars[$layer];
        } else if (preg_match('~\$\w+\(\s*\\' . $base64_decode . '\((\$\w+)\)~msi', $res)) {
            $res = preg_replace_callback('~\$\w+\(\s*\\' . $base64_decode . '\((\$\w+)\)~msi',
                function ($matches) use (&$vars, &$layer) {
                    if (isset($vars[$matches[1]])) {
                        $tmp = base64_decode($vars[$matches[1]]);
                        $layer = $matches[1];
                        $vars[$matches[1]] = $tmp;
                        $tmp = "'{$tmp}'";
                    } else {
                        $tmp = $matches[1];
                    }
                    return $tmp;
                }, $res);
            $res = $vars[$layer];
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateCreateFunc($str, $matches)
    {
        $result = $str;
        $funcs = str_replace($matches[4], '', $matches[3]);

        if (Helpers::concatStr($matches[1]) === 'create_function'
            && Helpers::concatStr($matches[2]) === 'eval') {
            $funcs = explode('(', $funcs);
            $iMax = count($funcs) - 2;
            $final_code = $matches[5];

            for ($i = $iMax; $i >= 0; $i--) {
                if ($funcs[$i][0] !== '\'' && $funcs[$i][0] !== '"') {
                    $funcs[$i] = '\'' . $funcs[$i];
                }
                $func = Helpers::concatStr($funcs[$i] . '"');
                if (Helpers::isSafeFunc($func)) {
                    $final_code = @$func($final_code);
                }
            }
            $result = $final_code;
        }
        $result = ' ?>' . $result;

        return $result;
    }

    private function deobfuscateCreateFuncConcat($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $vars = [];
        $res = preg_replace_callback('~(?|(\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));)~', function($matches) use (&$vars) {
            $tmp = str_replace("' . '", '', $matches[0]);
            $tmp = str_replace("'.'", '', $tmp);
            $value = str_replace("' . '", '', $matches[2]);
            $value = str_replace("'.'", '', $value);
            $vars[$matches[1]] = substr($value, 1, -1);
            return $tmp;
        }, $res);
        foreach($vars as $key => $var) {
            $res = str_replace($key, $var, $res);
            $res = str_replace($var . " = '" . $var . "';", '', $res);
            $res = str_replace($var . ' = "";', '', $res);
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalWrapVar($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $vars = [];
        $res = preg_replace_callback('~(?|(\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));)~msi', function($matches) use (&$vars) {
            $tmp = str_replace(["' . '", "\" . \""], '', $matches[0]);
            $tmp = str_replace(["'.'", "\".\""], '', $tmp);
            $value = str_replace(["' . '", "\" . \""], '', $matches[2]);
            $value = str_replace(["'.'", "\".\""], '', $value);
            $vars[$matches[1]] = substr($value, 1, -1);
            return $tmp;
        }, $res);
        $temp = substr($res, strpos($res, '@eval'));
        $temp1 = $temp;
        foreach($vars as $key => $var) {
            $temp = str_replace($key, $var, $temp);
        }
        $res = str_replace($temp1, $temp, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateForEach($str, $matches)
    {
        $find = $matches[0];
        $alph = $matches[3];
        $vars = [];
        $res = $str;

        preg_replace('~\s*/\*\w+\*/\s*~msi', '', $res);

        $res = preg_replace_callback('~foreach\(\[([\d,]+)\]\s*as\s*\$\w+\)\s*\{\s*(\$\w+)\s*\.=\s*\$\w+\[\$\w+\];\s*\}~mis', function($matches) use ($alph, &$vars) {
            $chars = explode(',', $matches[1]);
            $value = '';
            foreach ($chars as $char) {
                $value .= $alph[$char];
            }
            $vars[$matches[2]] = $value;
            return "{$matches[2]} = '{$value}';";
        }, $res);

        foreach($vars as $key => $var) {
            $res = str_replace($key, $var, $res);
            $res = str_replace($var . " = '" . $var . "';", '', $res);
            $res = str_replace($var . ' = "";', '', $res);
        }

        preg_match('~(\$\w+)\s*=\s*strrev\([create_function\.\']+\);~ms', $res, $matches);
        $res = str_replace($matches[0], '', $res);
        $res = str_replace($matches[1], 'create_function', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSubst2($str)
    {
        preg_match('~(\$\w+)="([^"])+(.{0,70}\1.{0,400})+;\s*}~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        preg_match('~(\$\w+)="(.+?)";~msi', $str, $matches);
        $alph = stripcslashes($matches[2]);
        $var = $matches[1];
        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        preg_match_all('~(\$GLOBALS\[\'\w{1,40}\'\])\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);

        foreach ($matches as $index => $var) {
            $res = str_replace($var[1], $var[2], $res);
            $res = str_replace($var[2] . " = '" . $var[2] . "';", '', $res);
        }

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateAssert($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrlDecode2($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        if (isset($matches[10])) {
            $res = base64_decode($matches[10]);
        }
        if (preg_match('~\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*,\s]+;~msi', $res, $match)) {
            $res = base64_decode(strtr(substr($match[1], 52*2), substr($match[1], 52, 52), substr($match[1], 0, 52)));
        }

        if (preg_match('~function\s*(\w+)\(\$\w+\)[\w{\$=\s*();<+\[\]\-]+\}\s+return[\$\s\w;]+}eval\(\1\("([\w\/+=]+)?"\)\);~', $res, $matchEval)) {
            $res = gzinflate(base64_decode($matchEval[2]));
            for ($i=0; $i < strlen($res); $i++)
            {
                $res[$i] = chr(ord($res[$i])-1);
            }
            $res = str_replace($find, $res, $str);
            return $res;
        }

        if (preg_match('~header\(\'[^\']+\'\);(?:\$\w+=\${[^}]+}\[[^\]]+\]\(\'.*?\'?;}?\'\);)+\${[^}]+}\[[^\]]+\]\(\);~msi',
            $matches[6], $match)) {
            $res = stripcslashes($match[0]);
            $dictionaryName = $matches[1];
            $dictionaryValue = urldecode($matches[3]);
            $vars = Helpers::getVarsFromDictionary($dictionaryValue, $str);
            $res = Helpers::replaceVarsFromArray($vars, $res);
            $res = Helpers::replaceCreateFunction($res);

            preg_match('~\$([0_O]+)\s*=\s*function\s*\((\$\w+)\)\s*\{\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),(\d+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,([\d-]+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),strlen\s*\(\2\)-(\d+)\);\s*return\s*gzinflate\s*\(base64_decode\s*\(\$[O_0]+\s*\.\s*\$[O_0]+\s*\.\s*\$[O_0]+\)+;~msi', $res, $m);
            $res = preg_replace_callback('~\$\{"GLOBALS"}\["' . $m[1] . '"\]\s*\(\'([^\']+)\'\)~msi', function ($calls) use ($m) {
                $temp1 = substr($calls[1], $m[3], $m[4]);
                $temp2 = substr($calls[1], $m[5]);
                $temp3 = substr($calls[1], $m[6],strlen($calls[1]) - $m[7]);
                return "'" . gzinflate(base64_decode($temp1 . $temp3 . $temp2)) . "'";
            }, $res);
            return $res;
        }


        $res = str_replace($find, ' ?>' . $res, $str);
        return $res;
    }

    private function deobfuscatePHPMyLicense($str)
    {
        preg_match('~\$\w+\s*=\s*base64_decode\s*\([\'"][^\'"]+[\'"]\);\s*if\s*\(!function_exists\s*\("rotencode"\)\).{0,1000}eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"]([^"\']+)[\'"]\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $hang = 10;
        while(preg_match('~eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"]([^"\']+)[\'"]\)+;~msi', $res, $matches) && $hang--) {
            $res = gzinflate(base64_decode($matches[1]));
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEdoced_46esab($str)
    {
        preg_match('~(\$\w+)=[\'"]([^"\']+)[\'"];(\$\w+)=strrev\(\'edoced_46esab\'\);eval\(\3\([\'"]([^\'"]+)[\'"]\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = '';
        $decoder = base64_decode($matches[4]);
        preg_match('~(\$\w+)=base64_decode\(\$\w+\);\1=strtr\(\1,[\'"]([^\'"]+)[\'"],[\'"]([^\'"]+)[\'"]\);~msi', $decoder, $matches2);
        $res = base64_decode($matches[2]);
        $res = strtr($res, $matches2[2], $matches2[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEdoced_46esab_etalfnizg($str, $matches)
    {
        return gzinflate(base64_decode($matches[3]));
    }

    private function deobfuscateEvalVarVar($str)
    {
        preg_match('~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\']\2[\'"];(\${\$\{"GLOBALS"\}\[[\'"]\3[\'"]\]})=[\'"]([^\'"]+)[\'"];eval.{10,50}?(\$\{\$\{"GLOBALS"\}\[[\'"]\1[\'"]\]\})\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = str_replace($matches[4], '$' . $matches[2], $str);
        $res = str_replace($matches[6], '$' . $matches[2], $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEscapes($str, $matches)
    {
        $find = $matches[0];
        $res = stripcslashes($str);
        $res = str_replace($find, $res, $str);
        preg_match_all('~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $res = preg_replace_callback('~\$\{\$\{"GLOBALS"\}\[[\'"]' . $match[1] . '[\'"]\]\}~msi', function ($matches) use ($match) {
                return '$' . $match[2];
            }, $res);
            $res = str_replace($match[0], '', $res);
        }
        return $res;
    }


    private function deobfuscateparenthesesString($str)
    {
        $hangs = 5;
        $res = $str;
        $find = '';
        while (preg_match('~for\((\$\w+)=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);(if\(isset\(\$_(GET|REQUEST|POST|COOKIE)\[[\'"][^\'"]+[\'"]\]\)\)\{[^}]+;\})?~msi', $res, $matches) && $hangs--) {
            if($hangs == 4) {
                $find = $matches[0];
            }
            $res = '';
            $temp = [];
            $matches[3] = stripcslashes($matches[3]);
            for($i=0, $iMax = strlen($matches[3]); $i < $iMax; $i++)
            {
                if($i < 16) $temp[$matches[3][$i]] = $i;
                else $res .= @chr(($temp[$matches[3][$i]]<<4) + ($temp[$matches[3][++$i]]));
            }
        }
        if(!isset($matches[6])) {
            //$xor_key = 'SjJVkE6rkRYj';
            $xor_key = $res^"\n//adjust sy"; //\n//adjust system variables";
            $res = $res ^ substr(str_repeat($xor_key, (strlen($res) / strlen($xor_key)) + 1), 0, strlen($res));
        }
        if(substr($res,0,12)=="\n//adjust sy") {
            $res = str_replace($find, $res, $str);
            return $res;
        } else return $str;
    }

    private function deobfuscateEvalInject($str, $matches)
    {
        $res = $str;
        $find = $matches[0];
        $alph = $matches[2];

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($matches[1] . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[1] . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }

        $res = str_replace("''", '', $res);
        $res = str_replace("' '", '', $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateWebshellObf($str)
    {
        $res = $str;
        preg_match('~function\s*(\w{1,40})\s*\(\s*(\$\w{1,40})\s*,\s*(\$\w{1,40})\s*\)\s*\{\s*(\$\w{1,40})\s*=\s*str_rot13\s*\(\s*gzinflate\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(\s*[\'"]([^\'"]*)[\'"]\s*\)\s*\)\s*\)\s*\)\s*;\s*(if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*(\$\w{1,40})\s*=(\$\w+[\{\[]\d+[\}\]]\.?)+;return\s*(\$\w+)\(\3\);\s*\}\s*else\s*)+\s*if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*return\s*eval\(\3\);\s*\}\s*\};\s*(\$\w{1,40})\s*=\s*[\'"][^\'"]*[\'"];(\s*\10\([\'"][^\'"]*[\'"],)+\s*[\'"]([^\'"]*)[\'"]\s*\)+;~msi',$str, $matches);
        $find = $matches[0];

        $alph = str_rot13(gzinflate(str_rot13(base64_decode($matches[5]))));

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($matches[4] . '{' . $i . '}.', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[4] . '{' . $i . '}', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);

        $res = base64_decode(gzinflate(str_rot13(convert_uudecode(gzinflate(base64_decode(strrev($matches[12])))))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateXorFName($str, $matches, $xor_key = null)
    {
        if (!isset($matches)) {
            preg_match('~(?(DEFINE)(?\'c\'(?:/\*\w+\*/)*))(\$\w+)\s*=\s*basename(?&c)\((?&c)trim(?&c)\((?&c)preg_replace(?&c)\((?&c)rawurldecode(?&c)\((?&c)"[%0-9A-F\.]+"(?&c)\)(?&c),\s*\'\',\s*__FILE__(?&c)\)(?&c)\)(?&c)\)(?&c);(\$\w+)\s*=\s*"([%\w\.\-\~]+)";(?:(\$\w+)=[^;]+;\5(?&c)\((?&c)\'\',\s*\'};\'\s*\.\s*(?&c)\()?(?:eval(?&c)\()?(?&c)rawurldecode(?&c)\((?&c)\3(?&c)\)(?&c)\s*\^\s*substr(?&c)\((?&c)str_repeat(?&c)\((?&c)\2,\s*(?&c)\((?&c)strlen(?&c)\((?&c)\3(?&c)\)(?&c)/strlen(?&c)\((?&c)\2(?&c)\)(?&c)\)(?&c)\s*\+\s*1(?&c)\)(?&c),\s*0,(?&c)\s*strlen(?&c)\((?&c)\3(?&c)\)(?&c)\)(?&c)\)(?:(?&c)\s*\.\s*\'{\'(?&c)\))?(?&c);~msi', $str, $matches);
        }
        $encrypted = rawurldecode($matches[4]);
        if (!isset($xor_key)) {
            $plain_text = '@ini_set(\'error_log\', NULL);';
            $plain_text2 = 'if (!defined(';
            $xor_key = substr($encrypted, 0, strlen($plain_text)) ^ $plain_text;
            if (preg_match('~\.?[a-z0-9-_]{8,}\.\w{3}~', $xor_key, $m)) {
                $xor_key = $m[0];
            } else {
                $xor_key = substr($encrypted, 0, strlen($plain_text2)) ^ $plain_text2;
                if (preg_match('~\.?[a-z0-9-_]{8,}\.\w{3}~', $xor_key, $m)) {
                    $xor_key = $m[0];
                }
            }
        }
        $result = $encrypted ^ substr(str_repeat($xor_key, (strlen($encrypted) / strlen($xor_key)) + 1), 0, strlen($encrypted));
        return $result;
    }

    private function deobfuscateSubstCreateFunc($str)
    {
        preg_match('~(\$\w{1,40})=\'(([^\'\\\\]|\\\\.)*)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';\s*(\$\w{1,40})\(\7,\$\w{1,40}\.\"([^\"]+)\"\.\$\w{1,40}\.\5\);~msi', $str, $matches);
        $find = $matches[0];
        $php = base64_decode($matches[9]);
        preg_match('~(\$\w{1,40})=(\$\w{1,40})\("([^\']+)"\)~msi', $php, $matches);
        $matches[3] = base64_decode($matches[3]);
        $php = '';
        for ($i = 1, $iMax = strlen($matches[3]); $i < $iMax; $i++) {
            if ($i % 2) {
                $php .= substr($matches[3], $i, 1);
            }
        }
        $php = str_replace($find, $php, $str);
        return $php;
    }

    private function deobfuscateZeura($str, $matches)
    {
        $offset = intval($matches[8]) + intval($matches[9]);
        $obfPHP = explode('__halt_compiler();', $str);
        $obfPHP = end($obfPHP);
        $php = gzinflate(base64_decode(substr(trim($obfPHP), $offset)));
        $php = stripcslashes($php);
        $php = str_replace($matches[0], $php, $str);
        return $php;
    }

    private function deobfuscateSourceCop($str, $matches)
    {
        $key = $matches[2];
        $obfPHP = $matches[1];
        $res = '';
        $index = 0;
        $len = strlen($key);
        $temp = hexdec('&H' . substr($obfPHP, 0, 2));
        for ($i = 2, $iMax = strlen($obfPHP); $i < $iMax; $i += 2) {
            $bytes = hexdec(trim(substr($obfPHP, $i, 2)));
            $index = (($index < $len) ? $index + 1 : 1);
            $decoded = $bytes ^ ord(substr($key, $index - 1, 1));
            if ($decoded <= $temp) {
                $decoded = 255 + $decoded - $temp;
            } else {
                $decoded = $decoded - $temp;
            }
            $res = $res . chr($decoded);
            $temp = $bytes;
        }
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateGlobalsArray($str, $matches)
    {
        $res = $str;
        $alph = stripcslashes($matches[3]);
        $res = preg_replace('~\${"[\\\\x0-9a-f]+"}\[\'\w+\'\]\s*=\s*"[\\\\x0-9a-f]+";~msi', '', $res);

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($matches[1] .'[' . $matches[2] . ']' . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[1] .'[' . $matches[2] . ']' . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);

        preg_match_all('~\\' . $matches[1] . '\[(\'\w+\')]\s*=\s*\'(\w+)\';~msi', $res, $funcs);

        $vars = $funcs[1];
        $func = $funcs[2];

        foreach ($vars as $index => $var) {
            $res = str_replace($matches[1] . '[' . $var . ']', $func[$index], $res);
        }

        foreach ($func as $remove) {
            $res = str_replace($remove . " = '" . $remove . "';", '', $res);
            $res = str_replace($remove . "='" . $remove . "';", '', $res);
        }
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateXbrangwolf($str, $match)
    {
        return $match[0];
    }

    private function deobfuscateObfB64($str, $matches)
    {
        $res = base64_decode($matches[3]);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateArrayOffsets($str)
    {
        $vars = [];
        preg_match('~(\$\w{1,40})\s*=\s*\'([^\']*)\';\s*(\$\w{1,40})\s*=\s*explode\s*\((chr\s*\(\s*\(\d+\-\d+\)\)),substr\s*\(\1,\s*\((\d+\-\d+)\),\s*\(\s*(\d+\-\d+)\)\)\);.+\1\s*=\s*\$\w+[+\-\*]\d+;~msi', $str, $matches);

        $find = $matches[0];
        $obfPHP = $matches[2];
        $matches[4] = Helpers::calc($matches[4]);
        $matches[5] = intval(Helpers::calc($matches[5]));
        $matches[6] = intval(Helpers::calc($matches[6]));

        $func = explode($matches[4], strtolower(substr($obfPHP, $matches[5], $matches[6])));
        $func[1] = strrev($func[1]);
        $func[2] = strrev($func[2]);

        preg_match('~\$\w{1,40}\s=\sexplode\((chr\(\(\d+\-\d+\)\)),\'([^\']+)\'\);~msi', $str, $matches);
        $matches[1] = Helpers::calc($matches[1]);
        $offsets = explode($matches[1], $matches[2]);

        $res = '';
        for ($i = 0; $i < (sizeof($offsets) / 2); $i++) {
            $res .= substr($obfPHP, $offsets[$i * 2], $offsets[($i * 2) + 1]);
        }

        preg_match('~return\s*\$\w{1,40}\((chr\(\(\d+\-\d+\)\)),(chr\(\(\d+\-\d+\)\)),\$\w{1,40}\);~msi', $str, $matches);
        $matches[1] = Helpers::calc($matches[1]);
        $matches[2] = Helpers::calc($matches[2]);

        $res = Helpers::stripsquoteslashes(str_replace($matches[1], $matches[2], $res));
        $res = "<?php\n" . $res . "?>";

        preg_match('~(\$\w{1,40})\s=\simplode\(array_map\(\"[^\"]+\",str_split\(\"(([^\"\\\\]++|\\\\.)*)\"\)\)\);(\$\w{1,40})\s=\s\$\w{1,40}\(\"\",\s\1\);\s\4\(\);~msi', $res, $matches);

        $matches[2] = stripcslashes($matches[2]);
        for ($i=0, $iMax = strlen($matches[2]); $i < $iMax; $i++) {
            $matches[2][$i] = chr(ord($matches[2][$i])-1);
        }

        $res = str_replace($matches[0], $matches[2], $res);

        preg_match_all('~(\$\w{1,40})\s*=\s*\"(([^\"\\\\]++|\\\\.)*)\";~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = stripcslashes($match[2]);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = Helpers::stripsquoteslashes($match[2]);
        }

        preg_match('~(\$\w{1,40})\s*=\s*\"\\\\x73\\\\164\\\\x72\\\\137\\\\x72\\\\145\\\\x70\\\\154\\\\x61\\\\143\\\\x65";\s(\$\w{1,40})\s=\s\'(([^\'\\\\]++|\\\\.)*)\';\seval\(\1\(\"(([^\"\\\\]++|\\\\.)*)\",\s\"(([^\"\\\\]++|\\\\.)*)\",\s\2\)\);~msi', $res, $matches);

        $matches[7] = stripcslashes($matches[7]);
        $matches[3] = Helpers::stripsquoteslashes(str_replace($matches[5], $matches[7], $matches[3]));


        $res = str_replace($matches[0], $matches[3], $res);

        preg_match_all('~(\$\w{1,40})\s*=\s*\"(([^\"\\\\]++|\\\\.)*)\";~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = stripcslashes($match[2]);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = Helpers::stripsquoteslashes($match[2]);
        }

        preg_match('~\$\w{1,40}\s=\sarray\(((\'(([^\'\\\\]++|\\\\.)*)\',?(\.(\$\w{1,40})\.)?)+)\);~msi', $res, $matches);

        foreach ($vars as $var => $value) {
            $matches[1] = str_replace("'." . $var . ".'", $value, $matches[1]);
        }

        $array2 = explode("','", substr($matches[1], 1, -1));
        preg_match('~eval\(\$\w{1,40}\(array\((((\"[^\"]\"+),?+)+)\),\s(\$\w{1,40}),\s(\$\w{1,40})\)\);~msi', $res, $matches);

        $array1 = explode('","', substr($matches[1], 1, -1));

        $temp = array_keys($vars);
        $temp = $temp[9];

        $arr = explode('|', $vars[$temp]);
        $off=0;
        $funcs=[];

        for ($i = 0, $iMax = sizeof($arr); $i < $iMax; $i++) {
            if ($i == 0) {
                $off = 0;
            } else {
                $off = $arr[$i - 1] + $off;
            }
            $len = $arr[$i];
            $temp = array_keys($vars);
            $temp = $temp[7];

            $funcs[]= substr($vars[$temp], $off, $len);
        }

        for ($i = 0; $i < 5; $i++) {
            if ($i % 2 == 0) {
                $funcs[$i] = strrev($funcs[$i]);
                $g = substr($funcs[$i], strpos($funcs[$i], "9") + 1);
                $g = stripcslashes($g);
                $v = explode(":", substr($funcs[$i], 0, strpos($funcs[$i], "9")));
                for ($j = 0, $jMax = sizeof($v); $j < $jMax; $j++) {
                    $q = explode("|", $v[$j]);
                    $g = str_replace($q[0], $q[1], $g);
                }
                $funcs[$i] = $g;
            } else {
                $h = explode("|", strrev($funcs[$i]));
                $d = explode("*", $h[0]);
                $b = $h[1];
                for ($j = 0, $jMax = sizeof($d); $j < $jMax; $j++) {
                    $b = str_replace($j, $d[$j], $b);
                }
                $funcs[$i] = $b;
            }
        }
        $temp = array_keys($vars);
        $temp = $temp[8];
        $funcs[] = str_replace('9', ' ', strrev($vars[$temp]));
        $funcs = implode("\n", $funcs);
        preg_match('~\$\w{1,40}\s=\s\'.+?eval\([^;]+;~msi', $res, $matches);
        $res = str_replace($matches[0], $funcs, $res);
        $res = stripcslashes($res);
        $res = str_replace('}//}}', '}}', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateArrayOffsetsEval($str, $matches)
    {
        $arg1 = explode(chr(Helpers::calculateMathStr($matches[4])), $matches[5]);
        $arg2 = $matches[2];
        $code = null;

        for ($enqvlelpmr = 0; $enqvlelpmr < (sizeof($arg1) / 2); $enqvlelpmr++) {
            $code .= substr($arg2, $arg1[($enqvlelpmr * 2)], $arg1[($enqvlelpmr * 2) + 1]);
        }

        $res = str_replace(
            chr(Helpers::calculateMathStr($matches[20])),
            chr(Helpers::calculateMathStr($matches[21])),
            $code
        );

        $arg1 = substr(
            $matches[2],
            Helpers::calculateMathStr($matches[7]),
            Helpers::calculateMathStr($matches[8])
        );

        $func = substr(
            $matches[2],
            Helpers::calculateMathStr($matches[23]),
            Helpers::calculateMathStr($matches[24])
        );

        return $res;
    }

    private function deobfuscateXoredVar($str, $matches)
    {
        $res = $str;
        $find = $matches[0];
        preg_match_all('~(\$\w{1,40})\s*=\s*\'((?:\\\\.|[^\'])*)\'(?:\^\s*\'((?:\\\\.|[^\'])*)\')?;~msi', $str, $matches, PREG_SET_ORDER);
        $vars = [];
        foreach ($matches as $match) {
            $vars[$match[1]] = $match[2];
            if (isset($match[3])) {
                $vars[$match[1]] ^= $match[3];
            }
            $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*(\w+);~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = $match[2];
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'((\\\\.|[^\'])*)\'\^(\$\w+);~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[4]])) {
                $vars[$match[1]] = $match[2] ^ $vars[$match[4]];
                $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
            }
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*(\$\w+)\^\'((\\\\.|[^\'])*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[2]])) {
                $vars[$match[1]] = $match[4] ^ $vars[$match[2]];
                $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
            }
        }
        preg_match_all('~\'((\\\\.|[^\'])*)\'\^(\$\w+)~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[3]])) {
                $res = str_replace($match[0], "'" . addcslashes($match[1] ^ $vars[$match[3]], '\\\'') . "'", $res);
            }
        }
        preg_match_all('~(\$\w+)\^\'((\\\\.|[^\'])*)\'~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[1]])) {
                $res = str_replace($match[0], "'" . addcslashes($vars[$match[1]] ^ $match[2], '\\\'') . "'", $res);
            }
        }

        preg_match_all('~(\$\w+)(\.)?=(\$\w+)?(?:\'((?:\\\\.|[^\'])*)\')?\.?(\$\w+)?(?:\'((?:\\\\.|[^\'])*)\')?(?:\^(\$\w+))?(?:\.\'((?:\\\\.|[^\'])*)\')?;~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $val = '';

            //var
            if (isset($match[2]) && $match[2] !== '') {
                if (isset($vars[$match[1]])) {
                    $val .= $vars[$match[1]];
                } else {
                    continue;
                }
            }

            //var
            if (isset($match[3]) && $match[3] !== '') {
                if (isset($vars[$match[3]])) {
                    $val .= $vars[$match[3]];
                } else {
                    continue;
                }
            }

            //str
            if (isset($match[4]) && $match[4] !== '') {
                $val .= $match[4];
            }

            //var
            if (isset($match[5]) && $match[5] !== '') {
                if (isset($vars[$match[5]])) {
                    $val .= $vars[$match[5]];
                } else {
                    continue;
                }
            }

            //str
            if (isset($match[6]) && $match[6] !== '') {
                $val .= $match[6];
            }

            //var and str
            if (isset($match[7]) && $match[7] !== '') {
                if (isset($vars[$match[7]])) {
                    $additionalStr = '';
                    if (isset($match[8]) && $match[8] !== '') {
                        $additionalStr = $match[8];
                    }
                    $val ^= $vars[$match[7]] . $additionalStr;
                } else {
                    continue;
                }
            } else {
                if (isset($match[8]) && $match[8] !== '') {
                    $val .= $match[8];
                }
            }

            $vars[$match[1]] = $val;
            $res = str_replace($match[0], '', $res);
        }

        $res = preg_replace_callback('~(\$\w+)([()]|==)~msi', function ($match) use ($vars) {
            $res = $vars[$match[1]] ?? $match[1];
            if (isset($vars[$match[1]]) && ($match[2] === ')' || $match[2] === '==')) {
                $res = "'$res'";
            }

            return $res . $match[2];
        }, $res);

        foreach ($vars as $var => $value) {
            $res = str_replace($var, $value, $res);
            $res = str_replace($value . "='" . $value . "';", '', $res);
        }
        $res = str_replace($find, $res, $str);

        if (preg_match('~((\$\w+)=\${\'(\w+)\'};)(?:.*?)((\$\w+)=\2(\[\'[^\']+\'\]);)~msi', $res, $matches)) {
            $res = str_replace($matches[1], '', $res);
            $res = str_replace($matches[4], '', $res);
            $cookieVar = sprintf('$%s%s', $matches[3], $matches[6]);
            $res = str_replace($matches[5], $cookieVar, $res);
        }

        return $res;
    }

    private function deobfuscatePhpMess($str, $matches)
    {
        $res = base64_decode(gzuncompress(base64_decode(base64_decode($matches[4]))));
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscatePregReplaceSample05($str)
    {
        $res = '';
        preg_match('~(\$\w{1,40})\s*=\s*\"([^\"]+)\";\s*\$\w+\s*=\s*\$\w+\(\1,\"([^\"]+)\",\"([^\"]+)\"\);\s*\$\w+\(\"[^\"]+\",\"[^\"]+\",\"\.\"\);~msi', $str, $matches);
        $res = strtr($matches[2], $matches[3], $matches[4]);
        $res = base64_decode($res);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscatePregReplaceB64($str, $matches)
    {
        $find = $matches[0];
        $res = str_replace($find, base64_decode($matches[4]), $str);
        $res = stripcslashes($res);
        preg_match('~eval\(\${\$\{"GLOBALS"\}\[\"\w+\"\]}\(\${\$\{"GLOBALS"\}\[\"\w+\"]}\(\"([^\"]+)\"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match('~eval\(\$\w+\(\$\w+\("([^"]+)"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match('~eval\(\$\w+\(\$\w+\("([^"]+)"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match_all('~\$(\w+)\s*(\.)?=\s*("[^"]*"|\$\w+);~msi', $res, $matches, PREG_SET_ORDER);
        $var = $matches[0][1];
        $vars = [];
        foreach ($matches as $match) {
            if($match[2]!=='.') {
                $vars[$match[1]] = substr($match[3], 1, -1);
            }
            else {
                $vars[$match[1]] .= $vars[substr($match[3], 1)];
            }
        }
        $res = str_replace("srrKePJUwrMZ", "=", $vars[$var]);
        $res = gzuncompress(base64_decode($res));
        preg_match_all('~function\s*(\w+)\(\$\w+,\$\w+\)\{.+?}\s*};\s*eval\(((\1\(\'(\w+)\',)+)\s*"([\w/\+]+)"\)\)\)\)\)\)\)\);~msi', $res, $matches);
        $decode = array_reverse(explode("',", str_replace($matches[1][0] . "('", '', $matches[2][0])));
        array_shift($decode);
        $arg = $matches[5][0];
        foreach ($decode as $val) {
            $arg = Helpers::someDecoder2($val, $arg);
        }
        $res = $arg;
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateDecoder($str)
    {
        preg_match('~if\(!function_exists\(\"(\w+)\"\)\){function \1\(.+eval\(\1\(\"([^\"]+)\"\)\);~msi', $str, $matches);
        $res = Helpers::someDecoder($matches[2]);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateGBE($str)
    {
        preg_match('~(\$\w{1,40})=\'([^\']+)\';\1=gzinflate\(base64_decode\(\1\)\);\1=str_replace\(\"__FILE__\",\"\'\$\w+\'\",\1\);eval\(\1\);~msi', $str, $matches);
        $res = str_replace($matches[0], gzinflate(base64_decode($matches[2])), $str);
        return $res;
    }

    private function deobfuscateGBZ($str, $matches)
    {
        $res = str_replace($matches[0], base64_decode(str_rot13($matches[4])), $str);
        return $res;
    }

    private function deobfuscateBitrix($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $funclist = [];
        $strlist = [];
        $res = preg_replace("|[\"']\s*\.\s*['\"]|smi", '', $res);
        $hangs = 0;
        while (preg_match('~(?:min|max|round)?\(\s*\d+[\.\,\|\s\|+\|\-\|\*\|\/]([\d\s\.\,\+\-\*\/]+)?\)~msi', $res) && $hangs < 15) {
            $res = preg_replace_callback('~(?:min|max|round)?\(\s*\d+[\.\,\|\s\|+\|\-\|\*\|\/]([\d\s\.\,\+\-\*\/]+)?\)~msi', ['Helpers','calc'], $res);
            $hangs++;
        }

        while (preg_match('~(?:min|max|round)\(\s*\d+\s*\)~msi', $res) && $hangs < 15) {
            $res = preg_replace_callback('~(?:min|max|round)\(\s*\d+\s*\)~msi', ['Helpers','calc'], $res);
            $hangs++;
        }

        $res = preg_replace_callback(
            '|base64_decode\(["\'](.*?)["\']\)|smi',
            function ($matches) {
                return '"' . base64_decode($matches[1]) . '"';
            },
            $res
        );

        if (preg_match_all('|\$GLOBALS\[[\'"](.+?)[\'"]\]\s*=\s*Array\((.+?)\);|smi', $res, $founds, PREG_SET_ORDER)) {
            foreach ($founds as $found) {
                $varname = $found[1];
                $funclist[$varname] = explode(',', $found[2]);
                $funclist[$varname] = array_map(function ($value) {
                    return trim($value, "'\"");
                }, $funclist[$varname]);

                $res = preg_replace_callback(
                    '|\$GLOBALS\[[\'"]' . $varname . '[\'"]\]\[(\d+)\]|smi',
                    function ($matches) use ($varname, $funclist) {
                        return str_replace(['"', "'"], '', $funclist[$varname][$matches[1]]);
                    },
                    $res
                );
                $res = str_replace($found[0], '', $res);
            }
        }

        $array_temp = [];
        while (preg_match('~function\s*(\w{1,60})\(\$\w+\){\$\w{1,60}\s*=\s*Array\((.{1,30000}?)\);\s*return\s*base64_decode[^}]+}~msi', $res, $found)) {
            $strlist = explode(',', $found[2]);
            $array_temp[$found[1]] = array_map('base64_decode', $strlist);
            $res = preg_replace_callback(
                '|' . $found[1] . '\((\d+)\)|smi',
                function ($matches) use ($array_temp, $found) {
                    return "'" . $array_temp[$found[1]][$matches[1]] . "'";
                },
                $res
            );
            $res = str_replace($found[0], '', $res);
        }

        $res = preg_replace('~\'\s*\.\s*\'~', '', $res);
        if (preg_match_all('~\s*function\s*(_+(.{1,60}?))\(\$[_0-9]+\)\s*\{\s*static\s*\$([_0-9]+)\s*=\s*(true|false);.{1,30000}?\$\3\s*=\s*array\((.*?)\);\s*return\s*base64_decode\(\$\3~smi', $res, $founds, PREG_SET_ORDER)) {
            foreach ($founds as $found) {
                $strlist = explode('",', $found[5]);
                $strlist = implode("',", $strlist);
                $strlist = explode("',", $strlist);
                $res = preg_replace_callback(
                    '|' . $found[1] . '\((\d+(\.\d+)?)\)|sm',
                    function ($matches) use ($strlist) {
                        $ret = base64_decode($strlist[$matches[1]]);
                        if (!$ret) {
                            $ret = $strlist[$matches[1]];
                        }
                        return  '\'' . $ret . '\'';
                    },
                    $res
                );
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateLockIt($str, $matches)
    {
        $phpcode = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($str)));
        $result = $str;
        $offset = 0;
        $dictName = $matches[1];
        $dictVal = urldecode($matches[2]);
        $vars = [$dictName => $dictVal];

        $vars = Helpers::getVarsFromDictionaryDynamically($vars, $str);

        if (preg_match('~eval\(~msi', $matches[15])) {
            $phpcode = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($matches[15])));
        }

        if ($matches[7] !== '' && preg_match('~eval\(~msi', $matches[7])) {
            $phpcode2 = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($matches[7])));
            $vars = Helpers::collectVars($phpcode2, "'", $vars);
        }

        if (preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches)) {
            $needles = Helpers::getNeedles($phpcode);
            $needle        = $needles[0];
            $before_needle = $needles[1];
            $strToDecode = base64_decode($matches[1]);
            return '<?php ' . strtr($strToDecode, $needle, $before_needle);
        }

        $count = 0;
        preg_match_all('~,(\d+|0x\w+)\)~msi', $phpcode, $offsetMatches, PREG_SET_ORDER);
        if (count($offsetMatches) === 2) {
            foreach ($offsetMatches as $offsetMatch) {
                if (strpos($offsetMatch[1], '0x') !== false && isset($str[$offset + hexdec($offsetMatch[1])])) {
                    $count++;
                    $offset += hexdec($offsetMatch[1]);
                } else if (isset($str[$offset + (int)$offsetMatch[1]])) {
                    $count++;
                    $offset += (int)$offsetMatch[1];
                }
            }
        }

        $finalOffset = 0;
        if (preg_match('~(\$[O0]*)=(\d+|0x\w+);~msi', $str, $match) && $count === 2) {
            if (strpos($match[2], '0x') !== false) {
                $finalOffset = hexdec($match[2]);
            } else {
                $finalOffset = (int)$match[2];
            }
        }

        $result = substr($str, $offset);
        if ($finalOffset > 0) {
            $result = substr($result, 0, $finalOffset);
        }

        if (preg_match('~[\'"]([^\'"]+)[\'"],[\'"]([^\'"]+)[\'"]~msi', $phpcode, $needleMatches)) {
            $result = strtr($result, $needleMatches[1], $needleMatches[2]);
        }

        $result = base64_decode($result);

        $result = Helpers::replaceVarsFromArray($vars, $result, true);

        for ($i = 0; $i < 2; $i++) {
            $result = preg_replace_callback('~eval\s?\(((?:(?:str_rot13|gzinflate|str_rot13|base64_decode)\()+\'[^\']+\'\)+);~msi',
                function ($match) {
                    return $this->unwrapFuncs($match[1]);
                }, $result);

            $result = preg_replace_callback('~eval\s?\((?:str_rot13\()+\'((?|\\\\\'|[^\'])+\')\)\);~msi',
                function ($match) {
                    return str_rot13($match[1]);
                }, $result);
        }

        $result = preg_replace_callback(
            '~(echo\s*)?base64_decode\(\'([\w=\+\/]+)\'\)~',
            function ($match) {
                if ($match[1] != "") {
                    return 'echo \'' . base64_decode($match[2]) . '\'';
                }
                return '\'' . str_replace('\'', '\\\'', base64_decode($match[2])) . '\'';
            },
            $result
        );

        $result = Helpers::replaceVarsFromArray($vars, $result, true);

        return '<?php ' . $result;
    }

    private function deobfuscateB64inHTML($str, $matches)
    {
        $obfPHP        = $str;
        $phpcode       = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($obfPHP)));
        $needles       = Helpers::getNeedles($phpcode);
        $needle        = $needles[count($needles) - 2];
        $before_needle = end($needles);
        $pointer1 = $matches[2];
        $temp = strtr($obfPHP, $needle, $before_needle);
        $end = 8;
        for ($i = strlen($temp) - 1; $i > strlen($temp) - 15; $i--) {
            if ($temp[$i] == '=') {
                $end = strlen($temp) - 1 - $i;
            }
        }

        $phpcode = base64_decode(substr($temp, strlen($temp) - $pointer1 - ($end-1), $pointer1));
        $phpcode = str_replace($matches[0], $phpcode, $str);
        return $phpcode;
    }

    private function deobfuscateStrtrFread($str, $layer2)
    {
        $str = explode('?>', $str);
        $str = end($str);
        $res = substr($str, $layer2[1], strlen($str));
        $res = base64_decode(strtr($res, $layer2[2], $layer2[3]));
        $res = str_replace($layer2[0], $res, $str);
        return $res;
    }

    private function deobfuscateStrtrBase64($str, $matches)
    {
        $str = strtr($matches[2], $matches[3], $matches[4]);
        $res = base64_decode($str);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateByteRun($str)
    {
        preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches);
        $res = base64_decode($matches[1]);
        $res = strtr($res, '123456aouie', 'aouie123456');
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateExplodeSubst($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        preg_match_all('~function ([\w_]+)\(~msi', $res, $funcs);
        preg_match('~(\$_\w+\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\1\[[a-fx\d]+\])\(\);~msi', $res, $matches);
        $subst_array = explode($matches[2], $matches[3]);
        $subst_var = $matches[1];
        $res = preg_replace_callback('~((\$_GET\[[O0]+\])|(\$[O0]+))\[([a-fx\d]+)\]~msi', function ($matches) use ($subst_array, $funcs) {
            if (function_exists($subst_array[hexdec($matches[4])]) || in_array($subst_array[hexdec($matches[4])], $funcs[1])) {
                return $subst_array[hexdec($matches[4])];
            } else {
                return "'" . $subst_array[hexdec($matches[4])] . "'";
            }
        }, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSubst($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $alph = stripcslashes($matches[2]);
        $funcs = $matches[4];

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($matches[1] . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[1] . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        $var = $matches[3];

        preg_match_all('~\\' . $var . '\[\]\s*=\s*\'([\w\*\-\#]+)\'~msi', $res, $matches);

        for ($i = 0, $iMax = count($matches[1]); $i <= $iMax; $i++) {
            if (@function_exists($matches[1][$i])) {
                $res = str_replace($var . '[' . $i . ']', $matches[1][$i], $res);
            } else {
                $res = @str_replace($var . '[' . $i . ']', "'" . $matches[1][$i] . "'", $res);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrldecode($str)
    {
        preg_match('~(\$\w+=\'[^\']+\';\s*)+(\$[\w{1,40}]+)=(urldecode|base64_decode)?\(?[\'"]([\w+%=-]+)[\'"]\)?;(\$[\w+]+=(\$(\w+\[\')?[O_0]*(\'\])?([\{\[]\d+[\}\]])?\.?)+;)+[^\?]+(\?\>[\w\~\=\/\+]+|.+\\\\x[^;]+;)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = stripcslashes($res);
        if ($matches[3] == "urldecode") {
            $alph = urldecode($matches[4]);
            $res = str_replace('urldecode(\'' . $matches[4] . '\')', "'" . $alph . "'", $res);
        } elseif ($matches[3] == 'base64_decode') {
            $alph = base64_decode($matches[4]);
            $res = str_replace('base64_decode(\'' . $matches[4] . '\')', "'" . $alph . "'", $res);
        } else {
            $alph = $matches[4];
        }

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($matches[2] . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[2] . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[2] . '{' . $i . '}.', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[2] . '{' . $i . '}', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);

        preg_match_all('~\$(\w+)\s*=\s*\'([\w\*\-\#]+)\'~msi', $res, $matches, PREG_SET_ORDER);
        for ($i = 0, $iMax = count($matches); $i < $iMax; $i++) {
            if (@function_exists($matches[$i][2])) {
                $res = str_replace('$' . $matches[$i][1], $matches[$i][2], $res);
                $res = str_replace('${"GLOBALS"}["' . $matches[$i][1] . '"]', $matches[$i][2], $res);
            } else {
                $res = str_replace('$' . $matches[$i][1], "'" . $matches[$i][2] . "'", $res);
                $res = str_replace('${"GLOBALS"}["' . $matches[$i][1] . '"]', "'" . $matches[$i][2] . "'", $res);
            }
            $res = str_replace("'" . $matches[$i][2] . "'='" . $matches[$i][2] . "';", '', $res);
            $res = str_replace($matches[$i][2] . "='" . $matches[$i][2] . "';", '', $res);
            $res = str_replace($matches[$i][2] . "=" . $matches[$i][2] . ';', '', $res);
        }
        $res = Helpers::replaceCreateFunction($res);
        preg_match('~\$([0_O]+)\s*=\s*function\s*\((\$\w+)\)\s*\{\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),(\d+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,([\d-]+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),strlen\s*\(\2\)-(\d+)\);\s*return\s*gzinflate\s*\(base64_decode\s*\(\$[O_0]+\s*\.\s*\$[O_0]+\s*\.\s*\$[O_0]+\)+;~msi', $res, $matches);
        $res = preg_replace_callback('~\$\{"GLOBALS"}\["' . $matches[1] . '"\]\s*\(\'([^\']+)\'\)~msi', function ($calls) use ($matches) {
            $temp1 = substr($calls[1], $matches[3], $matches[4]);
            $temp2 = substr($calls[1], $matches[5]);
            $temp3 = substr($calls[1], $matches[6],strlen($calls[1]) - $matches[7]);
            return "'" . gzinflate(base64_decode($temp1 . $temp3 . $temp2)) . "'";
        }, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrlDecode3($str, $matches)
    {
        $dictionaryKey = $matches[4];
        $dictionaryVal = urldecode($matches[3]);

        $result = Helpers::replaceVarsFromDictionary($dictionaryKey, $dictionaryVal, $str);

        return $result;
    }

    public function unwrapFuncs($string, $level = 0)
    {
        $close_tag = false;
        $res = '';

        if (trim($string) == '') {
            return '';
        }
        if ($level > 100) {
            return '';
        }

        if ((($string[0] == '\'') || ($string[0] == '"')) && (substr($string, 1, 2) != '?>')) {
            if($string[0] == '"' && preg_match('~\\\\x\d+~', $string)) {
                return stripcslashes($string);
            } else {
                return substr($string, 1, -2);
            }
        } elseif ($string[0] == '$') {
            preg_match('~\$\w{1,40}~', $string, $string);
            $string = $string[0];
            $matches = [];
            if (@preg_match_all('~\\' . $string . '\s*=\s*(\(*(base64_decode\s*\(|pack\s*\(\'H\*\',|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+((?:"((.*?[^\\\\])??((\\\\\\\\)+)?+)"[^;]+;)|(?:\$\w+)\)*;*))~msi', $this->full_source, $matches)
                || @preg_match_all('~\\' . $string . '\s*=\s*(\(*(base64_decode\s*\(|pack\s*\(\'H\*\',|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+((?:\'((.*?[^\\\\])??((\\\\\\\\)+)?+)\'[^;]+;)|(?:\$\w+)\)*;*))~msi', $this->full_source, $matches)
            ) {
                $str = $this->unwrapFuncs($matches[1][0], $level + 1);
            }

            if (@preg_match_all('~\\' . $string . '\s*=\s*("((.*?[^\\\\])??((\\\\\\\\)+)?+)");~msi', $this->full_source, $matches)
                || @preg_match_all('~\\' . $string . '\s*=\s*(\'((.*?[^\\\\])??((\\\\\\\\)+)?+)\');~msi', $this->full_source, $matches)
            ) {
                $str = substr(@$matches[1][0], 1, -1);
            }
            $this->cur = str_replace($matches[0][0], '', $this->cur);
            $this->text = str_replace($matches[0][0], '', $this->text);
            return $str;
        } else {
            $pos      = strpos($string, '(');
            $function = substr($string, 0, $pos);
            $arg      = $this->unwrapFuncs(substr($string, $pos + 1), $level + 1);
            if (strpos($function, '?>') !== false) {
                $function = str_replace("'?>'.", "", $function);
                $function = str_replace('"?>".', "", $function);
                $function = str_replace("'?>' .", "", $function);
                $function = str_replace('"?>" .', "", $function);
                $close_tag = true;
            }
            $function = str_replace(['@', ' '], '', $function);
            $safe = Helpers::isSafeFunc($function);
            if ($safe) {
                if ($function === 'pack') {
                    $args = explode(',', $arg);
                    $args[0] = substr(trim($args[0]), 0, -1 );
                    $args[1] = substr(trim($args[1]), 1);
                    $res = @$function($args[0], $args[1]);
                } elseif ($function === 'str_replace') {
                    $args = explode(',', $arg);
                    $args[0] = substr(trim($args[0]), 0, -1 );
                    $args[1] = substr(trim($args[1]), 0);
                    if (trim($args[1]) === 'null') {
                        $args[1] = null;
                    }
                    $args[2] = $this->unwrapFuncs(trim($args[2]), $level + 1) ?? $args[2];
                    $res = @$function($args[0], $args[1], $args[2]);
                } else {
                    $res = @$function($arg);
                }
            } else {
                $res = $arg;
            }
            if ($close_tag) {
                $res = "?> " . $res;
                $close_tag = false;
            }
            return $res;
        }
    }

    private function deobfuscateEvalFunc($str)
    {
        $res = $str;
        $res = stripcslashes($res);
        preg_match('~function\s*(\w{1,40})\((\$\w{1,40})\)\s*\{\s*(\$\w{1,40})\s*=\s*\"base64_decode\";\s*(\$\w{1,40})\s*=\s*\"gzinflate\";\s*return\s*\4\(\3\(\2\)\);\s*\}\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*eval\(\1\(\"([^\"]*)\"\)\);~msi', $res, $matches);
        $res = gzinflate(base64_decode($matches[5]));
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEvalConcatFunc($str, $matches)
    {
        $res = $matches[2];

        if (str_replace('"."', '', $matches[6]) === '"create_function"') {
            $brackets = '';
            $res = preg_replace_callback('~[\w."]+\(~', function ($match) use (&$brackets) {
                $replace = strtolower(str_replace('"."', '', $match[0]));
                if (strpos($replace, 'eval') === false) {
                    $brackets .= ')';
                    return $replace;
                }
                return "";
            }, $res);

            $res .= "'$matches[4]'" . $brackets . ';';
            $res = $this->unwrapFuncs($res);
        }

        return $res;
    }

    private function deobfuscateEvalHex($str)
    {
        preg_match('~eval\s*\("(\\\\x?\d+[^"]+)"\);~msi', $str, $matches);
        $res = stripcslashes($matches[1]);
        $res = str_replace($matches[1], $res, $res);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateEvalVarConcat($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        preg_match_all('~(\$\w+)\s*\.=\s*"([^"]+)";~msi', $str, $matches, PREG_SET_ORDER);
        $vars = [];
        foreach ($matches as $match) {
            $res = str_replace($match[0], '', $res);
            $res = str_replace($match[1], '"' . $match[2] . '"', $res);
        }
        $res = preg_replace('/[\'"]\s*?\.+\s*?[\'"]/smi', '', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalVar($str, $matches)
    {
        $find = $matches[0];
        $evalVar = $matches[7];
        if (!$evalVar) {
            $evalVar = $matches[6];
            $pregVal = '\$\w+';
            $pregStr = '[\'"]?([\/\w\+=]+)[\'"]?';
            $pregFunc = '(?:base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()+(?:["\']([\/\w\+=]+)["\'])';
            while (preg_match('~str_replace\(["\']([\/\w]+)["\'],\s?["\']([\/\w\+=]+)["\'],\s?(?|(' . $pregVal . ')|(?:' . $pregStr . ')|(' . $pregFunc . '))\)~msi', $evalVar, $match)) {
                $result = $match[0];
                if (preg_match('~' . $pregVal . '~', $match[3], $arg)) {
                    $result = str_replace($match[1], $match[2], $matches[3]);
                } elseif (preg_match('~' . $pregFunc . '~', $match[3], $arg)) {
                    $unwrappedVar = $this->unwrapFuncs($arg[0]);
                    $result = str_replace($match[1], $match[2], $unwrappedVar);
                } elseif (preg_match('~' . $pregStr . '~', $match[3], $arg)) {
                    $result = str_replace($match[1], $match[2], $match[3]);
                }

                $evalVar = str_replace($match[0], "\"$result\"" . ')', $evalVar);
            }
            return $this->unwrapFuncs($matches[5] . $evalVar);
        }
        $str = str_replace('\\\'', '@@slaquote@@', $str);
        $str = str_replace('\\"', '@@sladquote@@', $str);
        $val = '';
        if (!@preg_match_all('~\\' . $evalVar . '\s*=\s*("[^"]+");~msi', $str, $matches)) {
            @preg_match_all('~\\' . $evalVar . '\s*=\s*(\'[^\']+\');~msi', $str, $matches);
            $val = @$matches[1][count($matches[1])  - 1];
        } else {
            $val = $matches[1][count($matches[1])  - 1];
        }
        $res = str_replace($matches[0], '', $str);
        $val = substr($val, 1, -1);
        $text = "'" . addcslashes(stripcslashes($val), "\\'") . "'";
        $string = preg_replace('~\\' . $evalVar . '(?=[^a-zA-Z0-9])~ms', $text, $res);
        $string = preg_replace('~\(\s*\\' . $evalVar . '~msi', '(' . $text, $string);
        $string = str_replace('@@slaquote@@', '\\\'', $string);
        $string = str_replace('@@sladquote@@', '\\"', $string);
        $res = str_replace($find, $string, $str);
        return $res;
    }

    private function deobfuscateEval($str, $matches)
    {
        if (preg_match('~\)+\..{0,30}base64_decode~msi', $str)) {
            $res = explode(').', $str);
            $res = implode(')); eval(', $res);
            return $res;
        }
        $res = $str;
        if (preg_match('~(preg_replace\(["\']/\.\*?/[^"\']+["\']\s*,\s*)[^\),]+(?:[\)\\\\0-5]+;[\'"])?(,\s*["\'][^"\']*["\'])\)+;~msi', $res, $matches)) {
            $res = str_replace($matches[1], 'eval(', $res);
            $res = str_replace($matches[2], '', $res);
            return $res;
        }

        if (strpos($res, 'e\x76al') !== false
            || strpos($res, '\x29') !== false
            || strpos($res, 'base64_decode("\\x') !== false
        ) {
            $res = stripcslashes($res);
        }
        if (strpos($res, '"."') !== false) {
            $res = str_replace('"."', '', $res);
        }

        if (preg_match('~((\$\w+)\s*=\s*create_function\(\'\',\s*)[^\)]+\)+;\s*(\2\(\);)~msi', $res, $matches)) {
            $res = str_replace($matches[1], 'eval(', $res);
            $res = str_replace($matches[3], '', $res);
            return $res;
        }

        if (preg_match('~eval\s*/\*[\w\s\.:,]+\*/\s*\(~msi', $res, $matches)) {
            $res = str_replace($matches[0], 'eval(', $res);
            return $res;
        }
        if (preg_match('~\$_(POST|GET|REQUEST|COOKIE)~ms', $res)) {
            return $res;
        }
        $string = substr($res, 5, strlen($res) - 7);
        $res = $this->unwrapFuncs($string);
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEvalCodeFunc($str, $matches)
    {
        $res = substr($str, 5, strlen($str) - 7);
        $res = $this->unwrapFuncs($res);
        $res = stripcslashes($res);
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEcho($str, $matches)
    {
        $res = $str;
        $string = $matches[0];
        if (preg_match('~\$_(POST|GET|REQUEST|COOKIE)~ms', $res)) {
            return $res;
        }
        $string = substr($string, 5, strlen($string) - 7);
        $res = $this->unwrapFuncs($string);
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateFOPO($str, $matches)
    {
        $phpcode = Helpers::formatPHP($str);
        $phpcode = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode)));


        if (preg_match('~eval\s*\(\s*\$[\w|]+\s*\(\s*\$[\w|]+\s*\(~msi', $phpcode)) {
            preg_match_all('~\$\w+\(\$\w+\(\$\w+\("[^"]+"\)+~msi', $phpcode, $matches2);
            @$phpcode = gzinflate(base64_decode(str_rot13(Helpers::getTextInsideQuotes(end(end($matches2))))));
            $old = '';
            $hangs = 0;
            while (($old != $phpcode) && (strlen(strstr($phpcode, 'eval($')) > 0)
                   && (strlen(strstr($phpcode, '__FILE__')) === 0) && $hangs < 30) {
                $old = $phpcode;
                $funcs = explode(';', $phpcode);
                if (count($funcs) == 5) {
                    $phpcode = gzinflate(base64_decode(str_rot13(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode)))));
                } elseif (count($funcs) == 4) {
                    $phpcode = gzinflate(base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode))));
                }
                $hangs++;
            }
            $res = str_replace($matches[0], substr($phpcode, 2), $str);
        } else {
            $res = str_replace($matches[0], $phpcode, $str);
        }

        return $res;
    }

    private function deobfuscateFakeIonCube($str, $matches)
    {
        $subst_value = 0;
        $matches[1] = Helpers::calc($matches[1]);
        $subst_value = intval($matches[1])-21;
        $code = @pack("H*", preg_replace("/[A-Z,\r,\n]/", "", substr($str, $subst_value)));
        $res = str_replace($matches[0], $code, $str);
        return $res;
    }

    private function deobfuscateCobra($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $res = preg_replace_callback(
            '~eval\(\"return strrev\(base64_decode\(\'([^\']+)\'\)\);\"\)~msi',
            function ($matches) {
                return strrev(base64_decode($matches[1]));
            },
            $res
        );

        $res = preg_replace_callback(
            '~eval\(gzinflate\(base64_decode\(\.\"\'([^\']+)\'\)\)\)\;~msi',
            function ($matches) {
                return gzinflate(base64_decode($matches[1]));
            },
            $res
        );

        preg_match('~(\$\w{1,40})\s*=\s*\"([^\"]+)\"\;\s*\1\s*=\s*explode\(\"([^\"]+)\",\s*\s*\1\);~msi', $res, $matches);
        $var = $matches[1];
        $decrypt = base64_decode(current(explode($matches[3], $matches[2])));
        $decrypt = preg_replace_callback(
            '~eval\(\"return strrev\(base64_decode\(\'([^\']+)\'\)\);\"\)~msi',
            function ($matches) {
                return strrev(base64_decode($matches[1]));
            },
            $decrypt
        );

        $decrypt = preg_replace_callback(
            '~eval\(gzinflate\(base64_decode\(\.\"\'([^\']+)\'\)\)\)\;~msi',
            function ($matches) {
                return gzinflate(base64_decode($matches[1]));
            },
            $decrypt
        );

        preg_match('~if\(\!function_exists\(\"(\w+)\"\)\)\s*\{\s*function\s*\1\(\$string\)\s*\{\s*\$string\s*=\s*base64_decode\(\$string\)\;\s*\$key\s*=\s*\"(\w+)\"\;~msi', $decrypt, $matches);

        $decrypt_func = $matches[1];
        $xor_key = $matches[2];

        $res = preg_replace_callback(
            '~\\' . $var . '\s*=\s*.*?eval\(' . $decrypt_func . '\(\"([^\"]+)\"\)\)\;\"\)\;~msi',
            function ($matches) use ($xor_key) {
                $string = base64_decode($matches[1]);
                $key = $xor_key;
                $xor = "";
                for ($i = 0, $iMax = strlen($string); $i < $iMax;) {
                    for ($j = 0, $jMax = strlen($key); $j < $jMax; $j++,$i++) {
                        if (isset($string[$i])) {
                            $xor .= $string[$i] ^ $key[$j];
                        }
                    }
                }
                return $xor;
            },
            $res
        );
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateFlamux($str, $matches)
    {
        $str = $matches[0];

        $vars = [];
        preg_match_all('~(\$\w+=[\'"]\w+[\'"];)~', $str, $match);
        foreach ($match[0] as $var) {
            $split = explode('=', str_replace(';', '', $var));
            $vars[$split[0]] = $split[1];
        }

        $res = '';
        preg_match_all('~(\$\w+=\$\w+[\'.]+\$\w+;)~', $str, $match);
        for ($i = 0, $iMax = count($match[0]); $i < $iMax; $i++) {

            $split = explode('=', str_replace(';', '', $match[0][$i]));
            $concats = explode('.', $split[1]);
            $str_to_concat = '';
            foreach ($concats as $concat) {
                $str_to_concat .= $vars[$concat] ?? '';
            }

            $vars[$split[0]] = $str_to_concat;

            if ($i === ($iMax - 1)) {
                $res = gzinflate(base64_decode(base64_decode(str_rot13($str_to_concat))));
            }
        }

        return $res;
    }

    private function deobfuscateDarkShell($str, $matches)
    {
        $str = stripcslashes($matches[0]);

        return $str;
    }

    private function deobfuscateWso($str, $matches)
    {
        $result = $matches[0];
        $contentVar = $matches[8];
        $variables = [];

        preg_match_all('~(\[([-+\(\d*\/\)]+)\])+~', $result, $mathMatches);
        foreach ($mathMatches[0] as $index => $match) {
            $search = $mathMatches[2][$index];
            $mathResult = Helpers::calculateMathStr($search);

            $result = str_replace("[$search]", "[$mathResult]", $result);
        }

        $dictionary = $matches[2];

        $variables = Helpers::getVarsFromDictionary($dictionary, $result);
        $variables[$matches[6]] = $matches[7];

        preg_match_all('~(\$\w+)\.=(\$\w+)~', $result, $matches);
        foreach ($matches as $index => $match) {
            $var = $matches[1][$index];
            $value = $matches[2][$index];
            if (!isset($variables[$var])) {
                $variables[$var] = (string)$variables[$value] ?? '';
            } else {
                $variables[$var] .= (string)$variables[$value] ?? '';
            }
        }

        if (isset($variables[$contentVar])) {
            $result = $variables[$contentVar];
        }

        if (preg_match('~(\$\w+)\s+=\s+(["\'\w\/+]+);(\$\w+)=base64_decode\(\1\);(\$\w+)=gzinflate\(\3\);eval\(\4\);~msi', $result, $match)) {
            $result = gzinflate(base64_decode($match[2]));
        }

        $result = str_replace('<?php', '', $result);

        return $result;
    }

    private function deobfuscateAnonymousFox($str, $matches)
    {
        $result = $matches[0];

        $string = $matches[7];
        $array = strlen(trim($string));
        $debuger = '';
        for ($one = 0; $one < $array; $one += 2) {
            $debuger .= pack("C", hexdec(substr($string, $one, 2)));
        }
        $string = $debuger;

        $result = $string . $matches[8] . "';";

        return $result;
    }

    private function deobfuscateWsoEval($str, $matches)
    {
        $result = base64_decode($matches[2]);

        preg_match('~data:image/png;(.*)">~im', $result, $match);
        $result = str_replace( array ('%', '#'), array ('/', '+'), $match[1]);
        $result = gzinflate(base64_decode($result));

        return $result;
    }

    private function deobfuscateAssertStr($str, $matches)
    {
        $result = $matches[1];
        $result = str_rot13($result);

        return $result;
    }

    private function deobfuscateEvalFuncFunc($str, $matches)
    {
        $result = $matches[15];
        $result = base64_decode($result);
        $result = Helpers::decrypt_T_func($result);

        return $result;
    }

    private function deobfuscateFuncVar($str, $matches)
    {
        $arg1 = str_replace($matches[5], '', $matches[3]);
        $funcName = str_replace($matches[8], '', $matches[7]);
        $insidefuncName = str_replace($matches[11], '', $matches[10]);

        if ($funcName === 'create_function') {
            $result = sprintf('%s(%s(\'%s\');', $insidefuncName, $arg1, $matches[15]);
        } else {
            $result = sprintf(
                '%s = %s(\'%s\',\'%s(%s(%s));\');%s(\'%s\');',
                $matches[14],
                $funcName,
                $matches[13],
                $insidefuncName,
                $arg1,
                $matches[13],
                $matches[14],
                $matches[15]
            );
        }

        return $result;
    }

    private function deobfuscateEchoEval($str, $matches)
    {
        $content = $matches[4];
        $content = str_replace($matches[1], $matches[2], $content);
        $result = str_replace($matches[3], $content, $matches[5]);

        return $result;
    }

    private function deobfuscateDictionaryVars($str, $matches)
    {
        $dictionary = $matches[2];
        $dictionary = str_replace("\'", "'", $dictionary);
        $dictionary = str_replace('\"', '"', $dictionary);
        $content = $matches[4];
        $vars = Helpers::getVarsFromDictionary($dictionary, $matches[0]);

        if (isset($vars[$matches[6]]) && $vars[$matches[6]] === 'create_function') {
            $content = str_replace($matches[5], 'eval(' . $matches[7] . ');', $content);
        }

        $content = Helpers::replaceVarsFromDictionary($matches[1], $dictionary, $content);

        foreach ($vars as $key => $value) {
            $content = str_replace($key, $value, $content);
        }

        $content = preg_replace_callback('~\${[\'"](\w+)[\'"]}~msi', function ($m) {
            return '$' . $m[1];
        }, $content);

        $content = str_replace("''}", "\''}", $content);

        return $content;
    }

    private function deobfuscateConcatVarFunc($str, $matches)
    {
        $strVar = "";
        if ($matches['concatVar'] !== "") {
            $strVar = Helpers::concatVariableValues($matches[2], false);
        } else {
            if ($matches['strVal'] !== "") {
                $strVar = $matches['strVal'];
            }
        }

        $result = "";
        $iMax = strlen($strVar) / 2;
        for ($i = 0; $i < $iMax; $i++) {
            $result .= chr(base_convert(substr($strVar, $i * 2, 2), 16, 10));
        }
        return $result;
    }

    private function deobfuscateConcatVarFuncFunc($str, $matches)
    {
        $result = $matches[12];

        $func1 = Helpers::concatVariableValues($matches[2]);
        $func2 = Helpers::concatVariableValues($matches[22]);
        $func3 = Helpers::concatVariableValues($matches[19]);
        $func4 = Helpers::concatVariableValues($matches[7]);

        $result = sprintf('eval(%s(%s(%s(%s("%s")))));', $func1, $func2, $func3, $func4, $result);

        return $result;
    }

    private function deobfuscateEvalVarDoubled($str)
    {
        $result = $str;

        preg_match_all('~(\$\w+)\s?=\s?(\w+)\("(\w+)"\);~', $str, $varMatches);

        foreach ($varMatches[0] as $index => $varMatch) {
            $var_name = $varMatches[1][$index];
            $func_name = $varMatches[2][$index];
            $str = $varMatches[3][$index];

            if (Helpers::isSafeFunc($func_name)) {
                $str = @$func_name($str);
            }
            $result = str_replace($varMatch, '', $result);
            $result = str_replace($var_name, $str, $result);
        }

        return $result;
    }

    private function deobfuscateVarFuncsEcho($str, $matches)
    {
        $result = $str;
        $func = $matches[2];

        if (Helpers::isSafeFunc($matches[2])) {
            $result = @$func($matches[3]);
            $result = str_replace('<?php', '', $result);
        }

        return $result;
    }

    private function deobfuscateVarFuncsMany($str, $matches)
    {
        if (!isset($matches[4]) && preg_match('~(\$\w+)=((?:\'[\w%]+\'\.?)+);\s?(?:.*?)\s(\$\w+)=((?:\1\[?{?\d+\]?}?\.?)+);~msi', $matches[0], $m)) {
            $matches[4] = $m[1];
            $matches[5] = $m[2];
            $matches[6] = $m[3];
            $matches[7] = $m[4];
        }
        $result = $matches[0];
        $strName = $matches[1];
        $dictionaryName = $matches[4];
        $dictionaryValue = Helpers::collectStr("$matches[5]", "'");
        $vars = Helpers::getVarsFromDictionary($dictionaryValue, "$matches[6]=$matches[7]");
        $funcs = [];

        $result = str_replace("$matches[6]=$matches[7];", "", $result);

        $vars = array_merge($vars, Helpers::getVarsFromDictionary($dictionaryValue, $result));

        $result = preg_replace_callback(
            '~(\$\w+)\s?=\s?array\([\'"]([\w+\/]+)[\'"]\s?,\s?[\'"]([\w+\/]+)[\'"](?:\s?,[\'"]([\w+\/]+)[\'"]\s?)?\);\s?((?:(?:\$\w+=\s?\w+\(\$\w+,\s?)|(?:return\s?))(join\([\'"]{2},\s?\1\))\s?\)?\s?;)~msi',
            function ($match) {
                $joinedVars = join("", [$match[2], $match[3], $match[4]]);
                $replace = str_replace($match[6], "'$joinedVars'", $match[5]);

                return $replace;
            },
            $result
        );

        $result = preg_replace_callback(
            '~global\s(\$\w+);\s?((\$\w+)\s?=\s?[\'"]([\w\/+]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([\w\/+]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([\w\/+]+)[\'"];\s?\1\s?\.=\s?"({\3}{\5}{\7})");~',
            function ($match) {
                $concatedVars = $match[4] . $match[6] . $match[8];
                $replace = str_replace($match[2], sprintf('%s.="%s"', $match[1], $concatedVars), $match[0]);

                return $replace;
            },
            $result
        );

        $result = preg_replace_callback(
            '~((\$\w+)\s?=\s?[\'"]([\w\/+=]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([\w\/+=]+)[\'"];\s?return\s?"({\2}{\4})");~msi',
            function ($match) {
                $concatedVars = $match[3] . $match[5];
                $replace = str_replace($match[1], sprintf('return "%s"', $concatedVars), $match[0]);

                return $replace;
            },
            $result
        );

        $result = preg_replace_callback(
            '~(?:class\s(?<className>\w+)\s?{\s?)?(?:public\s)?function\s(?<methodName>\w+\(\)){\s?(?<codeBlock>.*?;)\s}\s?(?:}\s?)?~msi',
            function ($match) use (&$funcs, $strName, $dictionaryName, $dictionaryValue) {
                $str = "";
                $isConcat = false;

                if (preg_match(
                    '~return\s[\'"]([\w+\/+=]+)[\'"];~msi',
                    $match[0],
                    $returnCode
                )) {
                    $str = $returnCode[1];
                } else {
                    if (preg_match(
                        '~global\s(\$\w+);\s?\1\s?\.=\s?["\']([\w+\/+]+)["\'];?~msi',
                        $match[0],
                        $concatCode
                    )) {
                        $str = $concatCode[2];
                        $isConcat = true;
                    } else {
                        if (preg_match(
                            '~global\s(\$' . substr(
                                $dictionaryName,
                                1
                            ) . ');\s*return\s*((?:\s?\1\[?{?\d+\]?}?\s?\.?\s?)+);?~msi',
                            $match[0],
                            $returnCode
                        )) {
                            $str = Helpers::getVarsFromDictionary(
                                $dictionaryValue,
                                sprintf('%s=%s', $dictionaryName, $returnCode[2])
                            );
                            $str = $str[$dictionaryName];
                            $isConcat = false;
                        }
                    }
                }
                $funcs[$match['methodName']]['str'] = $str;
                $funcs[$match['methodName']]['concat'] = $isConcat;

                return "";
            },
            $result
        );

        $result = preg_replace_callback(
            '~(\$[^' . substr($strName, 1) . ']\w+)\s?=\s?(\w+\(\));~ms',
            function ($match) use ($funcs, &$vars) {
                if (isset($funcs[$match[2]]) && !$funcs[$match[2]]['concat']) {
                    $vars[$match[1]] = $funcs[$match[2]]['str'];
                }
                return "";
            },
            $result
        );

        foreach ($vars as $name => $var) {
            $result = str_replace($name, $var, $result);
        }

        $result = preg_replace_callback(
            '~([\w_]+)\s?\(\s?([\w_]+)\s?\(\s?((?:\$' . substr($matches[4], 1) . '[{\[]\d+[\]}]\s?\.?)+)\s?,\s?(\d+)\s?\),\s?((?:\d+,?)+)\);~msi',
            function ($match) use ($dictionaryValue, $dictionaryName) {
                $str = Helpers::getVarsFromDictionary(
                    $dictionaryValue,
                    sprintf('%s=%s', $dictionaryName, $match[3])
                );
                $res = "";
                if (Helpers::isSafeFunc($match[2])) {
                    $res = @$match[2]($str[$dictionaryName], $match[4]);
                }

                if (Helpers::isSafeFunc($match[1])) {
                    $args = [$res];
                    $digits = explode(',', $match[5]);
                    foreach ($digits as $digit) {
                        $args[] = (int)$digit;
                    }
                    $reflectionMethod = new ReflectionFunction($match[1]);
                    $res = $reflectionMethod->invokeArgs($args);
                }
                return "\"$res\";";
            },
            $result
        );

        $strToDecode = "";

        $regexFinal = str_replace('mainVar', $strName, '~(?:\mainVar\s?=\s?\w+\(\s?\mainVar\s*,\s?["\'](?<concat>[\w+\/]+)[\'"]\s?\)\s?;)|(?:\mainVar\s?=\s?\w+\(\s?\mainVar\s?,\s?(?<concatFunc>\w+\(\))\)\s?;)|(?:\mainVar\s?\.?=\s?(?:\mainVar\.)?\s?["\'](?<concatStr>[\w+\/=]+)[\'"]\s?;)|(?:\mainVar\s?\.?=\s?(?<concatFuncSingle>\w+\(\))\s?;)|(\$\w+\s?=\s?new\s\w+\(\)\s?;\s?\mainVar\s?\.?=\s?\mainVar\s?\.\s?\$\w+->(?<concatFuncClass>\w+\(\)\s?))|(?:(?<func>[^,\s]\w+\(\)))~msi');

        $result = preg_replace_callback(
            $regexFinal,
            function ($match) use (&$strToDecode, $funcs) {
                if (isset($match['concat']) && $match['concat'] !== "") {
                    $strToDecode .= $match['concat'];
                    return;
                }
                if (isset($match['concatStr']) && $match['concatStr'] !== "") {
                    $strToDecode .= $match['concatStr'];
                    return;
                }
                if (isset($match['concatFunc']) && $match['concatFunc'] !== "") {
                    $strToDecode .= $funcs[$match['concatFunc']]['str'];
                    return;
                }
                if (isset($match['concatFuncSingle']) && $match['concatFuncSingle'] !== "") {
                    $strToDecode .= $funcs[$match['concatFuncSingle']]['str'];
                    return;
                }
                if (isset($match['concatFuncClass']) && $match['concatFuncClass'] !== "") {
                    $strToDecode .= $funcs[$match['concatFuncClass']]['str'];
                    return;
                }
                if (isset($match['func']) && $match['func'] !== "") {
                    $strToDecode .= $funcs[$match['func']]['str'];
                    return;
                }
            },
            $result
        );

        $code = $result;
        $result = base64_decode($strToDecode);

        if (preg_match('~((\$\w+)="";).*?((\$\w+)=create_function\(\'(\$\w+,\$\w+)\',\s?(base64_decode\(((?:"[\w+=]+"\.?)+)\))\);).*?(\$\w+\s?=\s?create_function\("",\s?\4\(base64_decode\(\2\),\s?(\$_COOKIE\[\'\w+\'\])\)\s?\);)~msi',
            $code, $codeMatch)) {
            $initialCode = base64_decode(Helpers::collectStr($codeMatch[7]));

            $result = sprintf("function %s(%s){%s}%s='%s';%s(%s,%s);",
                substr($codeMatch[4], 1), $codeMatch[5], $initialCode, $codeMatch[2], $result,
                substr($codeMatch[4], 1), $codeMatch[2], $codeMatch[9]);
        }

        return $result;
    }

    private function deobfuscateGlobalArrayEval($str, $matches)
    {
        $result = str_replace($matches[1], "", $str);

        $dictionary = stripcslashes($matches[3]);
        $dictionaryVar = stripcslashes($matches[2]);
        $dictionaryVar = str_replace('{"GLOBALS"}', 'GLOBALS', $dictionaryVar);

        $result = Helpers::replaceVarsFromDictionary($dictionaryVar, $dictionary, $result);

        preg_match_all('~(\$GLOBALS\[[\'\w]+\])\s?=\s?[\'"]?([\w\-\_\$]+)["\']?;\s?~msi', $result, $varMatch);

        foreach ($varMatch[1] as $index => $var) {
            $result = str_replace($varMatch[0][$index], "", $result);
            $result = str_replace($varMatch[1][$index], $varMatch[2][$index], $result);
        }

        return $result;
    }

    private function deobfuscateTinkleShell($str, $matches)
    {
        $result = $str;
        $dictionaryStr = $matches[2];
        $decodeKey = Helpers::getDecryptKeyForTinkleShell(strlen($str));
        $vars = [
            $matches[4] => $matches[5],
        ];

        $result = str_replace(' ', '', $result);
        $matches[3] = str_replace(' ', '', $matches[3]);

        preg_match_all('~(\$\w+)=(?:\$\w+\[\'\w\'\+\d+\+\'\w\'\]\.?)+;~msi', $matches[3], $matchVars);
        foreach ($matchVars[0] as $index => $match) {
            preg_match_all('~\$\w+\[\'\w\'\+(\d+)\+\'\w\'\]\.?~msi', $match, $values);
            foreach ($values[1] as $value) {
                if (!isset($vars[$matchVars[1][$index]])) {
                    $vars[$matchVars[1][$index]] = $dictionaryStr[$value] ?? $value;
                } else {
                    $vars[$matchVars[1][$index]] .= $dictionaryStr[$value] ?? $value;
                }
            }
        }

        $result = str_replace($matches[3], "", $result);

        preg_match_all('~(\$\w+)=(\$\w+)\((\$\w+),(\$\w+)\(""\),"([\w\+]+)"\);~msi', $result, $matchVars);
        foreach ($matchVars[1] as $index => $varName) {
            $func = $vars[$matchVars[2][$index]] ?? $matchVars[2][$index];
            $arg1 = $vars[$matchVars[3][$index]] ?? $matchVars[3][$index];
            $arg2 = $vars[$matchVars[4][$index]] ?? $matchVars[4][$index];
            $argStr = $matchVars[5][$index];

            if (Helpers::isSafeFunc($func)) {
                $value = @$func($arg1, $arg2 === 'trim' ? "" : $arg2, $argStr);

                $vars[$varName] = $value;
            }
            $result = str_replace($matchVars[0][$index], '', $result);
        }

        $func = $vars[$matches[10]] ?? '';
        if (Helpers::isSafeFunc($func)) {
            $result = @$func($matches[11], $vars[$matches[12]] ?? "", $decodeKey);
        }
        $func = $vars[$matches[7]] ?? '';
        if (Helpers::isSafeFunc($func)) {
            $result = @$func($vars[$matches[8]] ?? '', "", $result);
        }
        $func = $vars[$matches[6]] ?? '';
        if (Helpers::isSafeFunc($func)) {
            $result = @$func($result);
        }

        return $result;
    }

    private function deobfuscateWsoFunc($str, $matches)
    {
        if (isset($matches['str'])) {
            return gzinflate(base64_decode($matches['str']));
        }

        return $matches[0];
    }

    private function deobfuscateEvalWanFunc($str, $matches)
    {
        $result = gzinflate(base64_decode($matches[5]));

        for ($i = 0; $i < strlen($result); $i++) {
            $result[$i] = chr(ord($result[$i]) - (int)$matches[4]);
        }

        return $result;
    }

    private function deobfuscateFuncFile($str, $matches)
    {
        $result = base64_decode($matches[2]);

        return $result;
    }

    private function deobfuscateGulf($str, $matches)
    {
        $result = str_replace("'.'", '', str_replace($matches[2], '', $matches[1]));

        $vars = Helpers::collectVars($matches[2], "'");
        $result = Helpers::replaceVarsFromArray($vars, $result);

        $tempCode = gzinflate(base64_decode($matches[4]));

        $result .= PHP_EOL . $tempCode;

        return $result;
    }

    private function deobfuscateEvalConcatAsciiChars($str, $matches)
    {
        $result = '';

        $num = (int)$matches[2];
        $str = (string)$matches[3];
        $len = strlen($str);

        for ($i = 0; $i < $len; $i++) {
            $result .= chr(ord($str[$i]) ^ $num);
        }

        $result = str_replace(['<?php', '?>', '', ''], '', $result);

        return $result;
    }

    private function deobfuscateEvalPost($str, $matches)
    {
        $result = '';

        $vars = Helpers::collectVars($str);

        $result = str_replace('.', "", $matches[8]);
        $result = str_replace($matches[7], "", Helpers::replaceVarsFromArray($vars, $result));
        $result = base64_decode(base64_decode($result));

        return $result;
    }

    private function deobfuscateEvalPregStr($str, $matches)
    {
        $result = sprintf("%s'%s'%s", stripcslashes($matches[1]), $matches[2], stripcslashes($matches[3]));

        $result = $this->unwrapFuncs($result);

        return $result;
    }

    private function deobfuscateClassDestructFunc($str, $matches)
    {
        $result = $str;

        $arg1 = $matches[1] ^ stripcslashes($matches[2]);
        $arg2 = $matches[3] ^ stripcslashes($matches[4]);

        if ($arg1 === 'assert' && $arg2 === 'eval') {
            $result = base64_decode($matches[5]);
        }

        return $result;
    }

    private function deobfuscateCreateFuncEval($str, $matches)
    {
        $result = $str;

        $func = stripcslashes($matches[1]);

        if (Helpers::isSafeFunc($func)) {
            $result = @$func($matches[2]);
        }

        return $result;
    }

    private function deobfuscateEvalCreateFunc($str, $matches)
    {
        $result = $str;

        $arr = [
            0 => $matches[4],
            1 => $matches[5],
            2 => $matches[6],
            3 => $matches[13],
        ];

        $func_1 = Helpers::decodeEvalCreateFunc_1($arr);
        if (strtoupper($func_1) === 'CREATE_FUNCTION') {
            $arr[3] = $matches[10];

            $result = Helpers::decodeEvalCreateFunc_1($arr);

            $result = preg_replace_callback('~base64_decode\([\'"]([\w=]+)[\'"]\)~msi', function ($match) {
                $extraCode = $this->unwrapFuncs($match[0]);

                if (preg_match('~if\(!function_exists\([\'"](\w+)[\'"]\)\){function\s?\1\((\$\w+)\){(\$\w+)=array\(\'([{\w\]]+)\',\'([\w`]+)\',\2\);for\((\$\w+)=0;\6<3;\6\+\+\){for\((\$\w+)=0;\7<strlen\(\3\[\6\]\);\7\+\+\)\s?\3\[\6\]\[\7\]\s?=\s?chr\(ord\(\3\[\6\]\[\7\]\)-1\);if\(\6==1\)\s?\3\[2\]=\3\[0\]\(\3\[1\]\(\3\[2\]\)\);}\s?return\s?\3\[2\];}(\$\w+)=["\']([\w\+\/=]+)["\'];(\$\w+)=[\'"]\1[\'"];(\$\w+)=\10\([\'"]([\w=]+)[\'"]\);\$\w+=\11\(\'\',\10\(\8\)\);\$\w+\(\);}~msi', $extraCode, $matchCode)) {
                    $arr = [
                        0 => $matchCode[4],
                        1 => $matchCode[5],
                        2 => $matchCode[12],
                    ];

                    $func_1 = Helpers::decodeEvalCreateFunc_2($arr);
                    if (strtoupper($func_1) === 'CREATE_FUNCTION') {
                        $arr[2] = $matchCode[9];

                        $extraCode = str_replace($matchCode[0], Helpers::decodeEvalCreateFunc_2($arr), $extraCode);
                    }
                }
                return $extraCode;
            }, $result);
        }

        return $result;
    }

    private function deobfuscateEvalFuncVars($str, $matches)
    {
        $result = $str;

        $vars = Helpers::collectFuncVars($matches[1]);

        $result = Helpers::replaceVarsFromArray($vars, $matches[2]);

        if (strpos($result, 'eval') !== false) {
            $result = $this->unwrapFuncs($result);
        }

        return $result;
    }

    private function deobfuscateDictionaryCreateFuncs($str, $matches)
    {
        $delimiter = '||||';
        $result = $str;
        $vars = Helpers::getVarsFromDictionary($matches[3], $matches[4]);
        $result = $matches[7].$delimiter.$matches[8];

        $result = preg_replace_callback('~\${"[\\\\\w]+"}\["[\\\\\w]+"\]~msi', function ($match) {
            return stripcslashes($match[0]);
        }, $result);

        $result = preg_replace_callback('~\${"GLOBALS"}\["(\w+)"\]~msi', function ($match) use ($vars) {
            $varName = '$' . $match[1];

            return $vars[$varName] ?? $varName;
        }, $result);

        $string = $matches[9];
        $str1 = substr($string, 0, 5);
        $str2 = substr($string, 7, strlen($string) - 14);
        $str3 = substr($string, -5);
        $decodedStr = gzinflate(base64_decode($str1 . $str2 . $str3));

        $delimCode = explode($delimiter, $result);

        $result = str_replace($matches[6], sprintf("'%s'.(%s)", $decodedStr, stripslashes($delimCode[1])), $delimCode[0]);

        $result = $matches[5] . $result;

        return $result;
    }

    private function deobfuscateEvalPostDictionary($str, $matches)
    {
        $finalCode = $matches[19];
        $result = str_replace($finalCode, '', $str);
        $arrayNum = [];
        $arrayStr = [];

        $regex = '~"?([\w\.\/\s]+)"?,?\s?~msi';
        preg_match_all($regex, $matches[6], $arrayStrMatches);
        foreach ($arrayStrMatches[1] as $arrayStrMatch) {
            $arrayStr[] = $arrayStrMatch;
        }

        $result = Helpers::replaceVarsFromDictionary($matches[5], $arrayStr, $result);
        $vars = Helpers::collectVars($result, "'");

        $regexSpecialVars = '~(\$\w+)([()\]])~msi';
        $code1 = preg_replace_callback($regexSpecialVars, function ($match) use ($vars) {
            $res = $vars[$match[1]] ?? $match[1];
            if ($match[2] === ']' || $match[2] === ')') {
                $res = "'$res'";
            }
            return $res . $match[2];
        }, $matches[20]);

        $code2 = str_replace($matches[18], '$_POST[\'' . ($vars[$matches[18]] ?? $matches[18]) . '\']', $matches[21]);
        $code2 = Helpers::replaceVarsFromArray($vars, $code2);

        $tempStr = Helpers::replaceVarsFromDictionary($matches[5], $arrayStr, $matches[22]);
        $vars = Helpers::collectVars($tempStr, "'");

        $code3 = Helpers::replaceVarsFromArray($vars, $matches[23]);
        $code3 = preg_replace_callback($regexSpecialVars, function ($match) use ($vars) {
            $res = $vars[$match[1]] ?? $match[1];
            if ($match[2] === ']' || $match[2] === ')') {
                $res = "'$res'";
            }
            return $res . $match[2];
        }, $matches[23]);

        $result = $code1 . $code2 . $code3;

        return $result;
    }

    private function deobfuscateDropInclude($str, $matches)
    {
        $key = basename($matches[2]);
        $encrypted = base64_decode(base64_decode($matches[4]));
        return $this->deobfuscateXorFName($encrypted, null, $key);
    }

    private function deobfuscateEvalComments($str, $matches)
    {
        return preg_replace('~/\*[^/]*/?\*/~msi', '', $str);
    }

    private function deobfuscateStrrevUrldecodeEval($str, $matches)
    {
        return strrev(urldecode($matches[2]));
    }

    private function deobfuscateEvalPackStrrot($str, $matches)
    {
        return pack("H*", str_rot13($matches[3]));
    }

    private function deobfuscateUrlDecodeTable($str, $matches)
    {
        $matches[3] = str_replace([" ", "\r", "\n", "\t", "'.'"], '', $matches[3]);
        $matches[5] = str_replace([" ", "'", ">"], '', $matches[5]);
        $temp = explode(',', $matches[5]);
        $array = [];
        foreach ($temp as $value) {
            $temp = explode("=", $value);
            $array[$temp[0]] = $temp[1];
        }
        $res = '';
        for ($i=0, $iMax = strlen($matches[3]); $i < $iMax; $i++) {
            $res .= isset($array[$matches[3][$i]]) ? $array[$matches[3][$i]] : $matches[3][$i];
        }
        $res = substr(rawurldecode($res), 1, -2);
        return $res;
    }

    private function deobfuscateEvalVarChar($str, $matches)
    {
        $chars = Helpers::collectVarsChars($matches[1]);
        $vars = Helpers::assembleStrings($chars, $matches[2]);
        $str = str_replace($matches[1], '', $str);
        $str = str_replace($matches[2], '', $str);
        foreach ($vars as $var => $func) {
            $str = str_replace($var, $func, $str);
        }
        return $str;
    }

    private function deobfuscateEvalVarFunc($str, $matches)
    {
        $var = Helpers::collectFuncVars($matches[1]);
        return $var[$matches[4]];
    }

    private function deobfuscateEvalVarsFuncs($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1]);
        $vars[$matches[5]] = $matches[2];
        $res = Helpers::replaceVarsFromArray($vars, $matches[3]);
        return $res;
    }

    private function deobfuscateEvalFileContent($str, $matches)
    {
        $res = $matches[4];
        $vars = Helpers::getVarsFromDictionary($matches[2], $matches[3]);
        $vars[$matches[1]] = $matches[2];
        $res = Helpers::replaceVarsFromArray($vars, $res);
        if (preg_match('~\$[^=]{0,50}=file\(str_replace\(\'\\\\{2}\',\'/\',__FILE__\)\);(\$[^=]{0,50})=array_pop\(\$[^)]{0,50}\);(\$[^=]{0,50})=array_pop\(\$[^)]{0,50}\);\$[^=]{0,50}=implode\(\'\',\$[^)]{0,50}\)\.substr\(\$[^,]{0,50},0,strrpos\(\$[^,]{0,50},\'@ev\'\)\);\$[^=]{0,50}=md5\(\$[^)]{0,50}\);(?:\$[^=]{0,50}=){0,3}NULL;@eval\(base64_decode\(str_replace\(\$[^,]{0,50},\'\',strtr\(\'~msi',
            $res, $match)) {
            $arr = explode(PHP_EOL, $str);
            foreach ($arr as $index => $val) {
                if ($index !== count($arr) - 1) {
                    $arr[$index] .= PHP_EOL;
                }
            }

            $arr1 = array_pop($arr);
            $arr2 = array_pop($arr);

            $vars[$match[1]] = $arr1;
            $vars[$match[2]] = $arr2;

            $res = implode('', $arr) . substr($arr2, 0, strrpos($arr2, '@ev'));
            $md5 = md5($res);
            $res = base64_decode(str_replace($md5, '', strtr($matches[5], $matches[6], $matches[7])));


            if (preg_match('~eval\((?:\$[^(]{0,50}\(){2}\$[^,]{0,50},\s{0,10}\'([^\']{1,500})\',\s{0,10}\'([^\']{1,500})\'\){3};~msi',
                $res, $match)) {
                $res = Helpers::replaceVarsFromArray($vars, $res);
                if (preg_match('~eval\(base64_decode\(strtr\(~msi', $res)) {
                    $res = base64_decode(strtr($arr1, $match[1], $match[2]));
                    $res = '<?php ' . PHP_EOL . $res;
                }
            }
        }

        return $res;
    }

    private function deobfuscateEvalArrayVar($str, $matches)
    {
        $result = $str;

        $array1 = str_split($matches[2]);
        $array2 = [];
        $arrayStr = base64_decode($matches[1]);

        if (preg_match('~(\$\w+)=\[(["\'][\w\[\];\'"|,.{}+=/&][\'"]=>["\'][\w\[\];\'"|,.{}+=/&][\'"],?\s{0,50})+\];~msi',
            $arrayStr, $match)) {
            preg_match_all('~["\']([\w\[\];\'"|,.{}+=/&])[\'"]=>["\']([\w\[\];\'"|,.{}+=/&])[\'"]~msi', $match[0],
                $arrayMatches);

            foreach ($arrayMatches[1] as $index => $arrayMatch) {
                $array2[$arrayMatches[1][$index]] = $arrayMatches[2][$index];
            }

            $newStr = "";
            foreach ($array1 as $xx) {
                foreach ($array2 as $main => $val) {
                    if ($xx == (string)$val) {
                        $newStr .= $main;
                        break;
                    }
                }
            }

            $result = gzinflate(base64_decode($newStr));
        }

        return $result;
    }

    private function deobfuscateEvalConcatedVars($str, $matches)
    {
        $iter = [2 => $matches[2], 4 => $matches[4], 6 => $matches[6], 12 => $matches[12]];
        foreach ($iter as $index => $item) {
            $matches[$index] = preg_replace_callback('~chr\((\d+)\)~msi', function ($match) use (&$matches) {
                return '\'' . chr($match[1]) . '\'';
            }, $matches[$index]);

            $matches[$index] = Helpers::concatStr($matches[$index]);
            $matches[$index] = base64_decode($matches[$index]);
        }

        $result = str_replace($matches[1], $matches[2], $matches[7]);
        $result = str_replace($matches[8], 0, $result);
        $result = str_replace($matches[10], 0, $result);

        if (Helpers::isSafeFunc($matches[4])) {
            $code = @$matches[4]($matches[6]);
            $code = gzinflate(str_rot13($code));
        } else {
            $code = 'gzinflate(str_rot13(\'' . $matches[4] . '\')));';
        }

        $result .= $matches[12] . $code;

        return $result;
    }

    private function deobfuscateEchoEscapedStr($str, $matches)
    {
        $i = 1;
        $result = $matches[1];
        $result = str_replace('\\\\\\', '\\\\', $result);

        while ($i < 3) {
            if (!preg_match('~(\\\\x[0-9a-f]{2,3})~msi', $result)) {
                break;
            }

            $result = preg_replace_callback('~(\\\\x[0-9a-f]{2,3})~msi', function ($m) {
                return stripcslashes($m[1]);
            }, $result);

            $i++;
        }

        $result = stripslashes($result);
        $vars = Helpers::collectVars($result);

        $result = preg_replace_callback('~(?<!{)\${[\'"]GLOBALS[\'"]}\[[\'"](\w+)[\'"]\]=[\'"](\w+)[\'"];~msi',
            function ($m) use (&$vars) {
                $vars['$' . $m[1]] = $m[2];

                return '';
            }, $result);

        $result = Helpers::replaceVarsFromArray($vars, $result);

        foreach ($vars as $name => $val) {
            $result = str_replace("$val=\"$val\";", '', $result);
        }

        return $result;
    }

    public function deobfuscateFilePutDecodedContents($str, $matches)
    {
        $res = $str;
        $content = base64_decode($matches[2]);
        $res = str_replace($matches[1], $content, $res);

        $res = preg_replace_callback('~chr\((\d+)\)~msi', function ($match) use (&$matches) {
            return '\'' . chr($match[1]) . '\'';
        }, $res);

        $res = Helpers::concatStringsInContent($res);

        $res = preg_replace_callback('~base64_decode\([\'"]([\w=]+)[\'"]\)~msi', function ($m) {
            return '\'' . base64_decode($m[1]) . '\'';
        }, $res);

        $vars = Helpers::collectVars($res);
        $res = Helpers::replaceVarsFromArray($vars, $res);
        $res = Helpers::removeDuplicatedStrVars($res);

        return $res;
    }

    public function deobfuscatePregReplaceStr($str, $matches)
    {
        $res = stripcslashes($matches[1]);

        return $res;
    }

    public function deobfuscateEvalImplodedArrStr($str, $matches)
    {
        function decode($str)
        {
            return chr(ord($str) - 1);
        }

        $split = str_split(stripcslashes($matches[2]));
        $map = array_map("decode", $split);
        $res = implode($map);

        return $res;
    }

    public function deobfuscatePregReplaceCodeContent($str, $matches)
    {
        $func = stripcslashes($matches[5]);

        $res = $matches[2];

        if (preg_match('~eval\(preg_replace\([\'"]/([^/])/[\'"],\s?[\'"](.*?)[\'"],\s?(\$\w+)\)\);~msi', $func,
            $match)) {
            if ($match[3] === $matches[1]) {
                $res = str_replace($match[1], stripcslashes($match[2]), $res);
            }
        }

        $vars = [];

        $res = preg_replace_callback('~(\$\w+)\s?=\s?([\'"])(.*?)\2;~msi', function ($m) use (&$vars) {
            $value = $m[3];
            if ($m[2] === '"') {
                $value = stripcslashes($value);
            }

            $vars[$m[1]] = $value;

            return sprintf('%s=\'%s\';', $m[1], $value);
        }, $res);

        $arrayVar = [];
        $arrayVarName = '';

        if (preg_match('~(\$\w+)\s?=\s?array\((?:\'[^\']+\',?)+\);~msi', $res, $m)) {
            $arrayVarName = $m[1];

            preg_match_all('~\'([^\']+)\',?~msi', $m[0], $arrMatch, PREG_PATTERN_ORDER);
            if (isset($arrMatch[1])) {
                foreach ($arrMatch[1] as $arr) {
                    $arrayVar[] = $arr;
                }
            }
        }

        if (preg_match('~(\$\w+)\((\$\w+),\s?(\$\w+)\s?\.\s?\'\(((?:["\']\w+[\'"],?)+)\)[\'"]\s?\.\s?(\$\w+),\s?null\);~msi',
            $res, $match)) {
            $arrayVar2 = [];
            preg_match_all('~[\'"](\w+)[\'"],?~msi', $match[4], $arrMatch2, PREG_PATTERN_ORDER);
            if (isset($arrMatch2[1])) {
                foreach ($arrMatch2[1] as $arr) {
                    $arrayVar2[] = $arr;
                }
            }

            if (isset($vars[$match[5]])
                && (preg_match('~,\s?(\$\w+),\s?(\$\w+)\)\);~msi', $vars[$match[5]], $m)
                    && $m[1] === $arrayVarName
                    && isset($vars[$m[2]])
                )) {
                $res = str_replace($arrayVar2, $arrayVar, $vars[$m[2]]);
            }
        }

        return $res;
    }

    public function deobfuscateSistemitComEnc($str, $matches)
    {
        $res = gzinflate(base64_decode($matches[2]));
        preg_match_all('~\$\w+\s*=\s*\[((\'[^\']+\',?)+)~msi', $matches[4], $replace, PREG_SET_ORDER);
        $find = explode("','", substr($replace[0][1], 1, -1));
        $replace = explode("','", substr($replace[1][1], 1, -1));
        $res = str_replace($find, $replace, $res);
        return $res;
    }

    public function deobfuscateConcatVarsReplaceEval($str, $matches)
    {
        $res = Helpers::concatVariableValues($matches[1]);
        $res = str_replace($matches[5], '', $res);
        $res = base64_decode($res);
        return $res;
    }

    public function deobfuscateEvalVarFunc2($str, $matches)
    {
        return $this->unwrapFuncs($matches[6]);
    }

    public function deobfuscateEvalArrays($str, $matches)
    {
        $res = str_replace('\'\'', '@@empty@@', $str);
        $vars = explode('", "', substr($matches[10], 1, -1));
        $res = preg_replace_callback('~\\' . $matches[9] . '\[(\d+)\]\s*\.?\s*~msi', function($m) use ($vars) {
            return "'" . $vars[(int)$m[1]] . "'";
        }, $res);
        $res = str_replace('\'\'', '', $res);
        $res = str_replace('@@empty@@', '\'\'', $res);
        $res = str_replace($matches[8], '', $res);
        preg_match_all('~(\$\w+)\s*=\s*\'([^\']+)\';~msi', $res, $m, PREG_SET_ORDER);
        $vars = [];
        foreach ($m as $var) {
            $vars[$var[1]] = '\'' . $var[2] . '\'';
            $res = str_replace($var[0], '', $res);
        }
        $res = Helpers::replaceVarsFromArray($vars, $res);
        return $res;
    }

    public function deobfuscatePregReplaceVar($str, $matches)
    {
        $result = stripcslashes($matches[2]);

        $regex = stripcslashes($matches[1]);
        if ($regex === '.*') {
            return $result;
        }

        $result = preg_replace_callback($regex, function ($m) {
            return '';
        }, $result);

        return $result;
    }

    public function deobfuscateEvalBinHexVar($str, $matches)
    {
        $func1 = stripcslashes($matches[2]);
        $func2 = stripcslashes($matches[4]);
        $result = '';

        if (Helpers::isSafeFunc($func2) && Helpers::isSafeFunc($func1)) {
            $result = '?>' . @$func1(@$func2($matches[6]));
        } else {
            $result = sprintf("'?>'.%s(%s('%s');", $func1, $func2, $matches[6]);
        }

        return $result;
    }

    public function deobfuscateEvalFuncTwoArgs($str, $matches)
    {
        $arg1 = base64_decode($matches[5]);
        $arg2 = $matches[6];

        $result = "";
        for ($o = 0; $o < strlen($arg1);) {
            for ($u = 0; $u < strlen($arg2); $u++, $o++) {
                $result .= $arg1[$o] ^ $arg2[$u];
            }
        }

        return $result;
    }

    public function deobfuscateEvalVarReplace($str, $matches)
    {
        $res = $matches[3];
        $replaces = explode(';', $matches[4]);
        foreach ($replaces as $replace) {
            if (preg_match('~(\$\w+)=str_replace\(\'([^\']+)\',\s*\'(\w)\',\s*\1\);~msi', $replace, $m)) {
                $res = str_replace($m[2], $m[3], $res);
            }
        }
        $res = base64_decode($res);
        return $res;
    }

    public function deobfuscateEvalPregReplaceFuncs($str, $matches)
    {
        $result = $str;
        $func1Str = preg_replace('/' . $matches[3] . '/', "", $matches[2]);
        $func2Str = preg_replace('/' . $matches[6] . '/', "", $matches[5]);

        $strToDecode = '';
        preg_match_all('~[\'"]([^\'"]+)[\'"],?~msi', $matches[8], $strMatches, PREG_SET_ORDER);
        foreach ($strMatches as $index => $strMatch) {
            if ($index > 0) {
                $strToDecode .= PHP_EOL;
            }
            $strToDecode .= $strMatch[1];
        }

        $result = @$func2Str($strToDecode);

        if (preg_match('~eval\(\$\w+\);~msi', $func1Str) && Helpers::isSafeFunc($func2Str)) {
            $result = @$func2Str($strToDecode);
            $result = stripcslashes($result);
            $vars = Helpers::collectVars($result);
            if (preg_match('~\$\w+=\$\w+\([\'"]\([\'"],__FILE.*?(?:\$\w+\(){3}[\'"][^\'"]+[\'"]\)\)\)\);~msi', $result,
                $m)) {
                $result = $m[0];
            }
            $result = Helpers::replaceVarsFromArray($vars, $result);
            $result = preg_replace_callback('~gzinflate\(base64_decode\(str_rot13\(["\']([^\'"]+)[\'"]\)\)\)~msi',
                function ($m) {
                    return gzinflate(base64_decode(str_rot13($m[1])));
                }, $result);
        }

        return $result;
    }

    public function deobfuscateEvalVarSlashed($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1]);
        $result = Helpers::replaceVarsFromArray($vars, $matches[2]);
        $result = $this->unwrapFuncs($result);

        return $result;
    }

    public function deobfuscateUrlMd5Passwd($str, $matches)
    {
        while(preg_match('~((?:(\$\w+)=\'[^;]+\';)+)~mis', $str, $matches2)) {
            $vars = Helpers::collectVars($matches2[1], "'");
            $str = Helpers::replaceVarsFromArray($vars, $str, true);
            $str = preg_replace_callback('~str_rot13\(urldecode\(\'([%\da-f]+)\'\)\)~mis', function($m) {
                return "'" . str_rot13(urldecode($m[1])) . "'";
            }, $str);
            $str = str_replace($matches2[0], '', $str);
        }
        return $str;
    }

    public function deobfuscateBlackScorpShell($str, $matches)
    {
        $vars = Helpers::collectVars($matches[2], "'");
        $vars2 = Helpers::collectVars($matches[3], "'");
        array_walk($vars2, function(&$var) {
            $var = "'$var'";
        });
        $str = gzinflate(base64_decode($vars2[$matches[5]]));
        $str = Helpers::replaceVarsFromArray($vars, $str, true);
        $str = Helpers::replaceVarsFromArray($vars2, $str);
        $str = str_ireplace('assert', 'eval', $str);
        return $str;
    }

    public function deobfuscateManyDictionaryVars($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1], "'");
        $result = $matches[2];
        foreach ($vars as $dictName => $dictVal) {
            $result = preg_replace_callback(
                '~\\' . $dictName . '[\[{][\'"]?(\d+)[\'"]?[\]}]~msi',
                function ($m) use ($dictVal) {
                    return "'" . $dictVal[(int)$m[1]] . "'";
                },
                $result
            );
        }
        $result = Helpers::replaceVarsFromArray($vars, $result, true, true);
        $result = preg_replace_callback('~(\.?)\s?[\'"]([\w=\+/()\$,;:"\s?\[\]]+)[\'"]\s?~msi', function ($m) {
            return $m[2];
        }, $result);

        return $result;
    }

    public function deobfuscateEvalBuffer($str, $matches)
    {
        $result = $matches[4];

        preg_match_all('~"([^"]+)"~msi', $matches[2], $arrMatches, PREG_SET_ORDER);

        $array = [];
        foreach ($arrMatches as $arrMatch) {
            $array[] = stripcslashes($arrMatch[1]);
        }

        $result = str_replace($array, '', $result);

        $result = gzinflate(base64_decode($result));

        return $result;
    }

    public function deobfuscateEvalArrayWalkFunc($str, $matches)
    {
        $result = stripcslashes($matches[1]) . '?>' . PHP_EOL;
        $encodedStr = '';

        preg_match_all('~(?:"([^"]{1,500})"){1,500}~msi', $matches[2], $arrayMatches, PREG_SET_ORDER);

        foreach ($arrayMatches as $arrayMatch) {
            $encodedStr .= stripcslashes($arrayMatch[1]);
        }

        $result .= base64_decode(str_rot13($encodedStr));

        return $result;
    }

    public function deobfuscateEvalDictionaryVars($str, $matches)
    {
        $result = $str;
        $vars = Helpers::collectVars($matches[1]);
        $vars[$matches[2]] = $matches[3];

        $vars = Helpers::getVarsFromDictionaryDynamically($vars, $matches[1]);

        $func = $vars[$matches[5]] ?? null;
        if ($func && Helpers::isSafeFunc($func)) {
            $result = @$func($matches[6]);
        }

        $result = Helpers::replaceVarsFromArray($vars, $result);

        return $result;
    }

    public function deobfuscateEvalSubstrVal($str, $matches)
    {
        $result = strtr(
            substr($matches[2], (int)$matches[3] * (int)$matches[4]),
            substr($matches[2], (int)$matches[5], (int)$matches[6]),
            substr($matches[2], (int)$matches[7], (int)$matches[8])
        );

        return '?> ' . base64_decode($result);
    }

    public function deobfuscateEvalFuncXored($str, $matches)
    {
        $vars = Helpers::collectFuncVars($str);
        $result = Helpers::replaceVarsFromArray($vars, $str);

        if (preg_match('~\$\w+\s?=\s?gzinflate\(base64_decode\(.*?strlen.*?chr\(\(ord.*?\^~msi', $result)) {
            $encodedStr = gzinflate(base64_decode($matches[1]));
            $len = strlen($encodedStr);
            $result = '';
            for ($i = 0; $i < $len; $i++) {
                $result .= chr((ord($encodedStr[$i]) ^ (int)$matches[3]));
            }
        }

        return $result;
    }

    public function deobfuscateEvalFileContentOffset($str, $matches)
    {
        $result = $matches[1];

        $encodedStr = substr($str, (int)$matches[3]);
        $result = str_replace($matches[2], "'$encodedStr'", $result);

        return '<?php ' . $this->unwrapFuncs($result);
    }

    public function deobfuscateEvalFuncExplodedContent($str, $matches)
    {
        $result = $str;
        $decodedStr = trim(trim($matches[7], ";"), '"');
        $strMD5 = md5($matches[1]);

        $result = base64_decode(
            str_replace($strMD5, '', strtr($decodedStr . $matches[4], $matches[5], $matches[6]))
        );

        return $result;
    }

    public function deobfuscateEvalEncryptedVars($str, $matches)
    {
        $result = $str;

        $vars_str = preg_replace_callback('~(\d{1,10}\.\d{1,10})\s?\*\s?(\d{1,10})~msi', function ($m) {
            $res = (double)($m[1]) * (int)$m[2];

            return "'$res'";
        }, $matches[1]);

        $vars_str = str_replace('"', "'", Helpers::normalize($vars_str));

        $vars = Helpers::collectVars($vars_str, "'");
        $vars_str = Helpers::replaceVarsFromArray($vars, $vars_str);
        $vars = Helpers::collectFuncVars($vars_str, $vars);
        $vars_str = Helpers::removeDuplicatedStrVars($vars_str);

        if ($a = preg_match('~(\$\w{1,50})=openssl_decrypt\(base64_decode\([\'"]([^\'"]+)[\'"]\),\'AES-256-CBC\',substr\(hash\(\'SHA256\',[\'"]([^\'"]+)[\'"],true\),0,32\),OPENSSL_RAW_DATA,([^\)]{0,50})\);~msi',
            $vars_str, $varMatch)) {
            $vars[$varMatch[1]] = openssl_decrypt(base64_decode($varMatch[2]), 'AES-256-CBC',
                substr(hash('SHA256', $varMatch[3], true), 0, 32), OPENSSL_RAW_DATA, $varMatch[4]);
        }

        $result = Helpers::replaceVarsFromArray($vars, str_replace(' ', '', $matches[7]));
        $result = str_replace($matches[4], str_replace($matches[5], '', "'$matches[6]'"), $result);

        return $this->unwrapFuncs($result);
    }

    public function deobfuscateEvalLoveHateFuncs($str, $matches)
    {
        $result = $matches[7];
        $result .= gzinflate(base64_decode($matches[4]));

        /* hate function */
        $finalPHPCode = null;
        $problems = explode(".", gzinflate(base64_decode($matches[2])));
        for ($mistake = 0; $mistake < count($problems); $mistake += strlen($matches[6])) {
            for ($hug = 0; $hug < strlen($matches[6]); $hug++) {
                $past = (int)$problems[$mistake + $hug];
                $present = (int)ord(substr($matches[6], $hug, 1));
                $sweet = $past - $present;
                $finalPHPCode .= chr($sweet);
            }
        }

        $finalPHPCode = gzinflate(base64_decode($finalPHPCode));

        $result .= PHP_EOL . $finalPHPCode;

        return $result;
    }

    public function deobfuscateXoredKey($str, $matches)
    {
        $encrypted = base64_decode($matches[4]);
        $key = $matches[7];
        $res = '';
        for ($i = 0, $iMax = strlen($encrypted); $i < $iMax; ) {
            for ($j = 0; $j < strlen($key) && $i < strlen($encrypted); $j++, $i++) {
                $res .= $encrypted[$i] ^ $key[$j];
            }
        }
        $res = base64_decode($res);
        return $res;
    }

    public function deobfuscateEvalGzB64($str, $matches)
    {
        $res = '';
        preg_match_all('~eval\(\$\w+\(\$\w+\(\'([^\']+)\'\)+;~msi', $str, $m, PREG_SET_ORDER);
        foreach ($m as $match) {
            $res .= gzuncompress(base64_decode($match[1])) . "\n";
        }
        return $res;
    }

    public function deobfuscateEvalArrayB64($str, $matches)
    {
        $res = '';
        if (preg_match('~function\s*(_\d+)\((\$\w+)\)\s*{(\$\w+)=Array\(\'([^)]+)\'\);return\s*base64_decode\(\3\[\2\]\);~msi', $str, $found)) {
            $strlist = explode("','", $found[4]);
            $res = preg_replace_callback(
                '|' . $found[1] . '\((\d+)\)|smi',
                function ($m) use ($strlist) {
                    return "'" . addcslashes(base64_decode($strlist[$m[1]]), '\\\'') . "'";
                },
                $str
            );
            $res = str_replace($matches[1], '', $res);
            return $res;
        }
    }

    public function deobfuscateManyBase64DecodeContent($str)
    {
        $res = $str;
        $res = preg_replace_callback('~base64_decode\([\'"]([^\'"]+)[\'"]\)~msi', function ($m) {
            return "'" . base64_decode($m[1]) . "'";
        }, $res);

        return $res;
    }

    public function deobfuscateEvalEscapedCharsContent($str, $matches)
    {
        $res = $matches[2] . "'" . stripcslashes($matches[1]) . "')";

        return $this->unwrapFuncs($res);
    }

    public function deobfuscateEvalFuncBinary($str, $matches)
    {
        $binaryVals = hex2bin($matches[2]);
        $res = Helpers::decodeEvalFuncBinary($binaryVals);

        return $res;
    }

    public function deobfuscateEvalPackFuncs($str, $matches)
    {
        $res = stripcslashes($matches[3]) . $matches[4];

        return $res;
    }

    public function deobfuscateParseStrFunc($str, $matches)
    {
        parse_str(Helpers::concatStr($matches[1]), $vars);

        $res = Helpers::replaceVarsByArrayName($matches[2], $vars, $matches[4]);
        $res = $this->unwrapFuncs($res . $matches[5] . ')');

        return $res;
    }

    public function deobfuscateEvalGzinflate($str, $match)
    {
        $res = stripcslashes($match[2]);
        $res = str_replace('"."', '', $res);
        return 'eval(' . $res . ');';
    }

    public function deobfuscateFuncVars($str, $matches)
    {
        $key = $matches[3];
        $res = $matches[7];
        $vars = [$matches[4] => preg_replace($matches[5], "", $matches[6])];

        preg_match_all('~(\$\w{1,50})\s?=\s?(?:(\$\w{1,50})\(\)\s?\.\s?)?\w{1,50}\(\\' . $matches[4] .'\(("[^"]+")\)\);~msi',
            $str, $match, PREG_SET_ORDER);
        foreach ($match as $matchVar) {
            $value = Helpers::decodeFuncVars($key,$this->unwrapFuncs($vars[$matches[4]] . '(' . $matchVar[3] . ')'));
            if ($matchVar[2] !== '') {
                $func = $vars[$matchVar[2]] ?? $matchVar[2];
                $value = $func . '() . \'' . $value . '\'';
            }
            $vars[$matchVar[1]] = $value;
        }
        foreach ($vars as $name => $val) {
            $res = str_replace($name, $val, $res);
        }
        return $res;
    }

    public function deobfuscateDictVars($str, $match)
    {
        $res = Helpers::replaceVarsFromDictionary($match[1], $match[2], $match[3]);
        $res = gzinflate(base64_decode(substr($res, 2, -3)));
        return $res;
    }

    /*************************************************************************************************************/
    /*                                          JS deobfuscators                                                 */
    /*************************************************************************************************************/

    private function deobfuscateJS_fromCharCode($str, $matches)
    {
        $result = '';
        $chars = explode(',', $matches[1]);
        foreach ($chars as $char) {
            $result .= chr((int)trim($char));
        }
        return $result;
    }

    private function deobfuscateJS_unescapeContentFuncWrapped($str, $matches)
    {
        $result = '';

        $functionCode = urldecode($matches[1]);
        $functionName = urldecode($matches[2]);
        $strDecoded = $matches[3];

        if (preg_match('~function\s?(\w{1,50})\(\w{1,50}\)\s{0,50}{\s{0,50}var\s?\w{1,50}\s?=\s?[\'"]{2};\s{0,50}var\s?\w{1,50}\s?=\s?\w{1,50}\.split\("(\d+)"\);\s{0,50}\w{1,50}\s?=\s?unescape\(\w{1,50}\[0\]\);\s{0,50}\w{1,50}\s?=\s?unescape\(\w{1,50}\[1\]\s?\+\s?"(\d{1,50})"\);\s{0,50}for\(\s?var\s?\w{1,50}\s?=\s?0;\s?\w{1,50}\s?<\s?\w{1,50}\.length;\s?\w{1,50}\+\+\)\s?{\s{0,50}\w{1,50}\s?\+=\s?String\.fromCharCode\(\(parseInt\(\w{1,50}\.charAt\(\w{1,50}%\w{1,50}\.length\)\)\^\w{1,50}\.charCodeAt\(\w{1,50}\)\)\+-2\);\s{0,50}}\s{0,50}return\s\w{1,50};\s{0,50}}~msi',
                $functionCode, $match) && strpos($functionName, $match[1])) {
            $tmp = explode((string)$match[2], $strDecoded);
            $s = urldecode($tmp[0]);
            $k = urldecode($tmp[1] . (string)$match[3]);
            $kLen = strlen($k);
            $sLen = strlen($s);

            for ($i = 0; $i < $sLen; $i++) {
                $result .= chr(((int)($k[$i % $kLen]) ^ ord($s[$i])) - 2);
            }
        } else {
            $result = $matches[3];
            $result = str_replace($matches[1], $functionCode, $result);
            $result = str_replace($matches[2], $functionCode, $result);
        }

        return $result;
    }

    /*************************************************************************************************************/
    /*                                          PYTHON deobfuscators                                             */
    /*************************************************************************************************************/

    private function deobfuscatePY_evalCompileStr($str, $matches)
    {
        return gzuncompress(base64_decode($matches[1]));
    }

}

class ContentObject
{
    private $content = false;
    private $normalized_file_content = false;
    private $decoded_converted = false;
    private $decoded_file_content = false;
    private $normalized_decoded = false;
    private $decoded_fragments = false;
    private $decoded_fragments_string = false;
    private $norm_decoded_fragments = false;
    private $norm_decoded_fragments_string = false;
    private $norm_decoded_file_content = false;
    private $converted_file_content = false;
    private $converted_decoded = false;
    private $strip_decoded = false;
    private $type = '';

    private $deobfuscate = false;



    public function __construct($content, $deobfuscate)
    {
        $this->content = $content;
        $this->deobfuscate = $deobfuscate;
    }

    public function getType()
    {
        return $this->type;
    }

    public function getContent()
    {
        if ($this->content !== false) {
            return $this->content;
        }
    }

    public function getNormalized()
    {
        if ($this->normalized_file_content !== false) {
            return $this->normalized_file_content;
        }
        $this->normalized_file_content = Normalization::strip_whitespace($this->getContent());
        $this->normalized_file_content = Normalization::normalize($this->normalized_file_content);
        return $this->normalized_file_content;
    }

    public function getDecodedFileContent()
    {
        if (!$this->deobfuscate) {
            $this->decoded_file_content = '';
            $this->decoded_fragments = [];
            $this->decoded_fragments_string = '';
            $this->norm_decoded_file_content = '';
        }
        if ($this->decoded_file_content !== false) {
            return $this->decoded_file_content;
        }
        $deobf_obj = new Deobfuscator($this->getContent());
        $deobf_type = $deobf_obj->getObfuscateType($this->getContent());
        if ($deobf_type != '') {
            $this->decoded_file_content = $deobf_obj->deobfuscate();
            $this->decoded_fragments = $deobf_obj->getFragments();
            $this->decoded_fragments_string = is_array($this->decoded_fragments) ? implode($this->decoded_fragments) : '';
            $this->norm_decoded_file_content = Normalization::normalize($this->decoded_file_content);
        } else {
            $this->decoded_file_content = '';
            $this->decoded_fragments = [];
            $this->decoded_fragments_string = '';
            $this->norm_decoded_file_content = '';
        }
        return $this->decoded_file_content;
    }

    public function getDecodedNormalizedContent()
    {
        if (!$this->deobfuscate) {
            $this->normalized_decoded = '';
            $this->norm_decoded_fragments = [];
            $this->norm_decoded_fragments_string = '';
        }
        if ($this->normalized_decoded !== false) {
            return $this->normalized_decoded;
        }
        $deobf_obj = new Deobfuscator($this->getNormalized());
        $deobf_type = $deobf_obj->getObfuscateType($this->getNormalized());
        if ($deobf_type != '') {
            $this->normalized_decoded = $deobf_obj->deobfuscate();
            $this->norm_decoded_fragments = $deobf_obj->getFragments();
            $this->norm_decoded_fragments_string = is_array($this->norm_decoded_fragments) ? Normalization::normalize(implode($this->norm_decoded_fragments)) : '';
        } else {
            $this->normalized_decoded = '';
            $this->norm_decoded_fragments = [];
            $this->norm_decoded_fragments_string = '';
        }
        return $this->normalized_decoded;
    }

    public function getDecodedFragments()
    {
        if ($this->decoded_fragments !== false) {
            return $this->decoded_fragments;
        }
        $this->getDecodedFileContent();
        return $this->decoded_fragments;
    }

    public function getDecodedFragmentsString()
    {
        if ($this->decoded_fragments_string !== false) {
            return $this->decoded_fragments_string;
        }
        $this->getDecodedFileContent();
        return $this->decoded_fragments_string;
    }

    public function getNormDecodedFragments()
    {
        if ($this->norm_decoded_fragments !== false) {
            return $this->norm_decoded_fragments;
        }
        $this->getDecodedNormalizedContent();
        return $this->norm_decoded_fragments;
    }

    public function getNormDecodedFragmentsString()
    {
        if ($this->norm_decoded_fragments_string !== false) {
            return $this->norm_decoded_fragments_string;
        }
        $this->getDecodedNormalizedContent();
        return $this->norm_decoded_fragments_string;
    }

    public function getNormDecodedFileContent()
    {
        if ($this->norm_decoded_file_content !== false) {
            return $this->norm_decoded_file_content;
        }
        $this->getDecodedNormalizedContent();
        return $this->norm_decoded_file_content;
    }

    public function getConvertedContent()
    {
        if ($this->converted_file_content !== false) {
            return $this->converted_file_content;
        }
        $this->converted_file_content = '';
        $l_UnicodeContent = Encoding::detectUTFEncoding($this->getContent());
        if ($l_UnicodeContent !== false) {
            if (Encoding::iconvSupported()) {
                $this->converted_file_content = Encoding::convertToCp1251($l_UnicodeContent, $this->getContent());
            }
        }
        $this->converted_file_content = Normalization::normalize($this->converted_file_content);
        return $this->converted_file_content;
    }

    public function getConvertedDecodedContent()
    {
        if (!$this->deobfuscate) {
            $this->converted_decoded = '';
        }
        if ($this->converted_decoded !== false) {
            return $this->converted_decoded;
        }
        $strip = Normalization::strip_whitespace($this->getConvertedContent());
        $deobf_obj = new Deobfuscator($strip, $this->getConvertedContent());
        $deobf_type = $deobf_obj->getObfuscateType($strip);
        if ($deobf_type != '') {
            $this->converted_decoded = $deobf_obj->deobfuscate();
        } else {
            $this->converted_decoded = '';
        }
        $this->converted_decoded = Normalization::normalize($this->converted_decoded);
        return $this->converted_decoded;
    }

    public function getStripDecodedContent()
    {
        if (!$this->deobfuscate) {
            $this->strip_decoded = '';
        }
        if ($this->strip_decoded !== false) {
            return $this->strip_decoded;
        }
        $strip = Normalization::strip_whitespace($this->getContent());
        $deobf_obj = new Deobfuscator($strip, $this->getContent());
        $deobf_type = $deobf_obj->getObfuscateType($strip);
        $this->type = $deobf_type;
        if ($deobf_type != '') {
            $this->strip_decoded = $deobf_obj->deobfuscate();
        } else {
            $this->strip_decoded = '';
        }
        $this->strip_decoded = Normalization::normalize($this->strip_decoded);
        return $this->strip_decoded;
    }
}

class CleanUnit
{

    const URL_GRAB = '~<(script|iframe|object|embed|img|a)\s*.{0,300}?((?:https?:)?\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+\~#=]{2,256}\.[a-z]{2,4}\b(?:[-a-zA-Z0-9@:%_\+.\~#?&/=]*)).{0,300}?</\1>~msi';

    public static function CleanContent(&$file_content, $clean_db, $deobfuscate = false, $signature_converter = null, $precheck = null, $src_file = null, $demapper = false)
    {
        $result = false;
        $content_orig = new ContentObject($file_content, $deobfuscate);
        $content = new ContentObject($file_content, $deobfuscate);
        $terminate  = false;
        $prev_id = '';

        if (isset($src_file) && $demapper && $deobfuscate) {
            if (self::checkFalsePositives($src_file, $content->getStripDecodedContent(), $content->getType(), $demapper)) {
                return $result;
            }
        }

        foreach ($clean_db->getDB() as $rec_index => $rec) {
            if ($terminate) {
                break;
            }

            if (is_callable($precheck) && !$precheck($rec['mask_type'])) {
                continue;
            }

            switch ($rec['sig_type']) {
                case 4: // normalize first line
                case 5: // match deobfuscated content and replace related obfuscated part
                case 0: // simple match
                    if (isset($signature_converter)) {
                        $inj_sign = $signature_converter->getCutSignature($rec_index);
                    }
                    if (!(isset($inj_sign) && $inj_sign)) {
                        $inj_sign = $rec['sig_match'];
                    }
                    $nohang = 20; // maximum 20 iterations
                    $condition_num = 0; // for debug
                    while (
                        (
                            (
                                preg_match('~' . $rec['sig_match'] . '~smi', $content->getContent(), $fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 1
                            )
                            || (
                                ($normalized_file_content = $content->getNormalized())
                                && $normalized_file_content != ''
                                && preg_match('~' . $rec['sig_match'] . '~smi', $normalized_file_content, $norm_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 3
                            )
                            || (
                                ($decoded_fragments_string = $content->getDecodedFragmentsString())
                                && $decoded_fragments_string != ''
                                && preg_match('~' . $inj_sign . '~smi', $decoded_fragments_string, $dec_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 2
                            )
                            || (
                                ($norm_decoded_fragments_string = $content->getNormDecodedFragmentsString())
                                && $norm_decoded_fragments_string != ''
                                && preg_match('~' . $inj_sign . '~smi', $norm_decoded_fragments_string, $norm_dec_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 4
                            )
                        )
                        && ($nohang-- > 0)
                    ) {

                        if (trim($rec['sig_replace']) === '<?php') {
                            $rec['sig_replace'] = '<?php ';
                        }

                        $normal_fnd = isset($norm_fnd[0][0]) ? $norm_fnd[0][0] : false;

                        if (!empty($normal_fnd)) {
                            $pos = Normalization::string_pos($file_content, $normal_fnd);
                            if ($pos !== false) {
                                $replace = self::getReplaceFromRegExp($rec['sig_replace'], $norm_fnd);
                                $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                            }
                        }
                      
                        if (isset($fnd) && $fnd) {
                            $replace = self::getReplaceFromRegExp($rec['sig_replace'], $fnd);
                            $file_content = self::replaceString($file_content, $replace, $fnd[0][1], strlen($fnd[0][0]));
                        }
                        $decoded_fragments = $content->getDecodedFragments();
                        if (isset($dec_fnd) && $dec_fnd && !empty($decoded_fragments)) {
                            foreach ($decoded_fragments as $obfuscated => $deobfuscated) {
                                if (preg_match('~' . $inj_sign  . '~smi', $deobfuscated)) {
                                    $replace = self::getReplaceFromRegExp($rec['sig_replace'], $dec_fnd);
                                    $pos_obf = strpos($file_content, $obfuscated);
                                    $len = strlen($obfuscated);
                                    $file_content = self::replaceString($file_content, $replace, $pos_obf, $len);
                                }
                            }
                        }
                        $norm_decoded_fragments = $content->getNormDecodedFragments();
                        if (isset($norm_dec_fnd) && $norm_dec_fnd && !empty($norm_decoded_fragments)) {
                            foreach ($norm_decoded_fragments as $obfuscated => $deobfuscated) {
                                if (preg_match('~' . $inj_sign  . '~smi', Normalization::normalize($deobfuscated))) {
                                    $pos = Normalization::string_pos($file_content, $obfuscated);
                                    if ($pos !== false) {
                                        $replace = self::getReplaceFromRegExp($rec['sig_replace'], $norm_fnd);
                                        $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                                    }
                                }
                            }
                        }

                        $file_content = preg_replace('~<\?php\s+\?>~smi', '', $file_content);
                        $file_content = preg_replace('~<\?\s+\?>~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s*<\?php\s*\Z~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s*<\?\s*\Z~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s*\?>\s*\Z~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s+<\?~smi', '<?', $file_content);

                        $empty = (trim($file_content) == '');

                        if ($prev_id !== $rec['id']) {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => $empty];
                        }

                        if ($empty) {
                            $terminate = true;
                        }

                        if ($file_content !== $content->getContent()) {
                            unset($content);
                            $content = new ContentObject($file_content, $deobfuscate);
                        }
                        $prev_id = $rec['id'];

                    } // end of while


                    break;
                case 1: // match signature and delete file
                    $condition_num = 0; // for debug
                    if (
                        (
                            $rec['sig_match'] == '-'
                            && $condition_num = 1
                        )
                        || (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content->getContent(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($decoded_file_content = $content->getNormDecodedFileContent())
                            && $decoded_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            ($converted_file_content = $content->getConvertedContent())
                            && $converted_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $converted_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 4
                        )
                        || (
                            ($decoded_converted = $content->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 5
                        )
                        || (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content_orig->getContent(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($decoded_file_content = $content_orig->getNormDecodedFileContent())
                            && $decoded_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($converted_file_content = $content_orig->getConvertedContent())
                            && $converted_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $converted_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 4
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($decoded_converted = $content_orig->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 5
                        )
                    ) {
                        $file_content = self::replaceString($file_content, '', $m[0][1], false, $serialized);
                        if ($serialized) {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => false];
                        } else {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => true];
                            $file_content = '';
                            $terminate = true;
                        }
                    }

                    break;
                case 3: // match signature against normalized file and delete it
                    $condition_num = 0; // for debug
                    if (
                        (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content->getNormalized(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 1
                        )
                        || (
                            ($normalized_decoded = $content->getStripDecodedContent())
                            && $normalized_decoded != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $normalized_decoded, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($decoded_converted = $content->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content_orig->getNormalized(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 1
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($normalized_decoded = $content_orig->getStripDecodedContent())
                            && $normalized_decoded != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $normalized_decoded, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($decoded_converted = $content_orig->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                    ) {
                        $file_content = self::replaceString($file_content, '', $m[0][1], false, $serialized);
                        if ($serialized) {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => false];
                        } else {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => true];
                            $file_content = '';
                            $terminate = true;
                        }
                    }
                    break;
            }
        }
        self::removeBlackUrls($file_content, $clean_db, $result, $deobfuscate);
        return $result;
    }

    public static function isEmpty($result)
    {
        foreach ($result as $item) {
            if($item['empty'] === true) {
                return true;
            }
        }
        return false;
    }

    public static function getSAItem($result)
    {
        foreach ($result as $item) {
            if($item['empty'] === true && ($item['sig_type'] == 1 || $item['sig_type'] == 3)) {
                return [$item];
            }
        }
        return $result;
    }

    private static function getReplaceFromRegExp($replace, $matches)
    {
        if (!empty($replace)) {
            if (preg_match('~\$(\d+)~smi', $replace)) {
                $replace = preg_replace_callback('~\$(\d+)~smi', function ($m) use ($matches) {
                    return isset($matches[(int)$m[1]]) ? $matches[(int)$m[1]][0] : '';
                }, $replace);
            }
        }
        return $replace;
    }

    private static function checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType, $deMapper)
    {
        if ($l_DeobfType == '') {
            return false;
        }
        switch ($l_DeobfType) {
            case 'Bitrix':
                foreach ($deMapper as $fkey => $fvalue) {
                    if ((strpos($l_Filename, $fkey) !== false) && (strpos($l_Unwrapped, $fvalue) !== false)) {
                        return true;
                    }
                }
                break;
        }
        return false;
    }

    private static function replaceString($file_content, $replace, $pos, $delta_len, &$serialized = false)
    {
        $size2fix = self::getSerializedLength($file_content, $pos, $size2fix_pos);
        if ($size2fix) {
            $serialized = true;
            $delta_len = $delta_len ? $delta_len : $size2fix;
            $file_content = substr_replace($file_content, $replace, $pos, $delta_len);
            $new_length = $size2fix - ($delta_len - strlen($replace));
            $file_content = substr_replace($file_content, (string)$new_length, $size2fix_pos[0], $size2fix_pos[1]);
        } else {
            $file_content = substr_replace($file_content, $replace, $pos, $delta_len);
        }
        return $file_content;
    }

    private static function getSerializedLength($content, $offset, &$pos)
    {
        $ser_size = false;
        if (preg_match_all('~s:(\d+):"~m', substr($content, 0, (int)$offset + 1), $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
            foreach ($m as $ser_chunk) {
                $start_chunk = $ser_chunk[0][1] + strlen($ser_chunk[0][0]);
                $end_chunk = $start_chunk + (int)$ser_chunk[1][0];
                if ($start_chunk <= $offset && $end_chunk > $offset) {
                    $ser_size = (int)$ser_chunk[1][0];
                    $pos[0] = $ser_chunk[1][1];
                    $pos[1] = strlen($ser_chunk[1][0]);
                    break;
                }
            }
        }
        return $ser_size;
    }

    private static function removeBlackUrls(&$file_content, $clean_db, &$result, $deobfuscate)
    {
        if ($clean_db->getScanDB() === null || !class_exists('ScanCheckers')) {
            return;
        }

        $offset = 0;

        while (self::findBlackUrl($file_content, $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + 1;
            $file_content = self::replaceString($file_content, '', $fnd[0][1], strlen($fnd[0][0]));
            $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
        }

        unset($content);
        $content = new ContentObject($file_content, $deobfuscate);
        $offset = 0;
        while (self::findBlackUrl($content->getNormalized(), $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + strlen($fnd[0][0]);
            $pos = Normalization::string_pos($file_content, $fnd[0][0]);
            if ($pos !== false) {
                $replace = self::getReplaceFromRegExp('', $content->getNormalized());
                $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
            }
        }

        $offset = 0;
        unset($content);
        $content = new ContentObject($file_content, $deobfuscate);
        while (self::findBlackUrl($content->getDecodedFragmentsString(), $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + 1;
            $decoded_fragments = $content->getDecodedFragments();
            if (!empty($decoded_fragments)) {
                foreach ($decoded_fragments as $obfuscated => $deobfuscated) {
                    if (self::findBlackUrl($deobfuscated, $fnd_tmp, 0, $clean_db, $id)) {
                        $pos_obf = strpos($file_content, $obfuscated);
                        $len = strlen($obfuscated);
                        $file_content = self::replaceString($file_content, '', $pos_obf, $len);
                        $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
                    }
                }
            }
            unset($content);
            $content = new ContentObject($file_content, $deobfuscate);
        }

        $offset = 0;
        unset($content);
        $content = new ContentObject($file_content, $deobfuscate);
        while (self::findBlackUrl($content->getNormDecodedFragmentsString(), $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + 1;
            $norm_decoded_fragments = $content->getNormDecodedFragments();
            if (!empty($norm_decoded_fragments)) {
                foreach ($norm_decoded_fragments as $obfuscated => $deobfuscated) {
                    if (self::findBlackUrl(Normalization::normalize($deobfuscated), $fnd_tmp, 0, $clean_db, $id)) {
                        $pos = Normalization::string_pos($file_content, $obfuscated);
                        if ($pos !== false) {
                            $file_content = self::replaceString($file_content, '', $pos[0], $pos[1] - $pos[0] + 1);
                            $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
                        }
                    }
                }
            }
            unset($content);
            $content = new ContentObject($file_content, $deobfuscate);
        }
    }

    private static function findBlackUrl($item, &$fnd, $offset, $clean_db, &$id)
    {
        return preg_match(self::URL_GRAB, $item, $fnd, PREG_OFFSET_CAPTURE, $offset)
            && !ScanCheckers::isOwnUrl($fnd[0][0], $clean_db->getScanDB()->getOwnUrl())
            && (isset($clean_db->getScanDB()->whiteUrls) && !ScanCheckers::isUrlInList($fnd[0][0],
                    $clean_db->getScanDB()->whiteUrls->getDb()))
            && ($id = ScanCheckers::isUrlInList($fnd[0][0], $clean_db->getScanDB()->blackUrls->getDb()));
    }
}
class SignatureConverter {
    
    private $signatures         = [];
    private $cuted_signatures   = [];
    private $count_convert      = 0;
    
    public function __construct($clean_db) 
    {
        $this->signatures = $clean_db;
    }
    
    public function getCutSignature($sig_index) 
    {
        if (!isset($this->signatures[$sig_index])) {
            return false;
        }
        $signature = $this->signatures[$sig_index]['sig_match'];
        if (!isset($this->cuted_signatures[$sig_index])) {
            $cuted_signature = $this->cut($signature);
            if ($signature != $cuted_signature) {
                $this->cuted_signatures[$sig_index] = $cuted_signature;
            }
            else {
                $this->cuted_signatures[$sig_index] = false;
            }
            return $cuted_signature;
        }
        elseif ($this->cuted_signatures[$sig_index] === false) {
            return $signature;
        }
        return $this->cuted_signatures[$sig_index];
    }
    
    public function getCountConverted()
    {
        return $this->count_convert;
    }

    // /////////////////////////////////////////////////////////////////////////
    
    private function cut($signature)
    {
        $this->count_convert++;
        $regexp = '^'
        . '(?:\\\A)?'
        . '(?:\\\s\*)?'
        . '<\\\\\?'
        . '(?:\\\s\*)?'
        . '(?:\\\s\+)?'            
        . '(?:'
            .'php'
            . '|\(\?:php\)\?'
            . '|='
            . '|\(\?:php\|=\)\??'
            . '|\(\?:=\|php\)\??'
        . ')?'
        . '(?:\\\s\+)?'
    
        . '(.*?)'

        . '(?:\(\??:?\|?)?'
        . '\\\\\?>'
        . '(?:\\\s\*)?'
        . '(?:\|?\\\Z\)?)?'
        . '$';
    
        return preg_replace('~' . $regexp . '~smi', '\1', $signature);
    }
}

class Logger
{
    /**
     * $log_file - path and log file name
     * @var string
     */
    protected $log_file;
    /**
     * $file - file
     * @var string
     */
    protected $file;
    /**
     * dateFormat
     * @var string
     */
    protected $dateFormat = 'd-M-Y H:i:s';

    /**
     * @var array
     */
    const LEVELS  = ['ERROR' => 1, 'DEBUG' => 2,  'INFO' => 4, 'ALL' => 7];

    /**
     * @var int
     */
    private $level;

    /**
     * Class constructor
     *
     * @param string       $log_file - path and filename of log
     * @param string|array $level    - Level of logging
     *
     * @throws Exception
     */
    public function __construct($log_file = null, $level = 'INFO')
    {
        if (!$log_file) {
            return;
        }
        if (is_array($level)) {
            foreach ($level as $v) {
                if (!isset(self::LEVELS[$v])) {
                    $v = 'INFO';
                }
                $this->level |= self::LEVELS[$v];
            }
        } else {
            if (isset(self::LEVELS[$level])) {
                $this->level = self::LEVELS[$level];
            } else {
                $this->level = self::LEVELS['INFO'];
            }
        }

        $this->log_file = $log_file;
        //Create log file if it doesn't exist.
        if (!file_exists($log_file)) {
            fopen($log_file, 'w') or exit("Can't create $log_file!");
        }
        //Check permissions of file.
        if (!is_writable($log_file)) {
            //throw exception if not writable
            throw new Exception('ERROR: Unable to write to file!', 1);
        }
    }

    /**
     * Info method (write info message)
     * @param string $message
     * @return void
     */
    public function info($message)
    {
        if ($this->level & self::LEVELS['INFO']) {
            $this->writeLog($message, 'INFO');
        }

    }
    /**
     * Debug method (write debug message)
     * @param string $message
     * @return void
     */
    public function debug($message)
    {
        if ($this->level & self::LEVELS['DEBUG']) {
            $this->writeLog($message, 'DEBUG');
        }
    }
    /**
     * Error method (write error message)
     * @param string $message
     * @return void
     */
    public function error($message)
    {
        if ($this->level & self::LEVELS['ERROR']) {
            $this->writeLog($message, 'ERROR');
        }
    }

    /**
     * Write to log file
     * @param string $message
     * @param string $level
     * @return void
     */
    public function writeLog($message, $level)
    {
        if (!$this->log_file) {
            return;
        }
        // open log file
        if (!is_resource($this->file)) {
            $this->openLog();
        }
        //Grab time - based on timezone in php.ini
        $time = date($this->dateFormat);
        // Write time & message to end of file
        fwrite($this->file, "[$time] : [$level] - $message" . PHP_EOL);
    }
    /**
     * Open log file
     * @return void
     */
    private function openLog()
    {
        $openFile = $this->log_file;
        // 'a' option = place pointer at end of file
        $this->file = fopen($openFile, 'a') or exit("Can't open $openFile!");
    }
    /**
     * Class destructor
     */
    public function __destruct()
    {
        if ($this->file) {
            fclose($this->file);
        }
    }
}