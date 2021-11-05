<?php

/**
 * Security Api
 *
 * This is a advanced security class
 *
 *
 * @link www.omerfd,com
 * @since 1.0.0
 *
 * @version 1.0.0
 *
 * @package Omerfdmrl\Security
 * 
 * @licence: The MIT License (MIT) - Copyright (c) - http://opensource.org/licenses/MIT
 */

namespace Omerfdmrl\Security;

class Security implements Security_Interface {

    /**
     * @var string $cipher Cipher Type
     */
    private static string $cipher = 'AES-128-ECB';

    /**
     * @var string|int $key Security Key
     */
    private static string|int $key = '';

    /**
     * @var int $level For Hard Level
     */
    private static int $level = 8;

    /**
     * @var array $refudesExtension Refused Extensions For File Upload
     */
    public static array $refusedExtension = ['php','bat',''];

    /**
     * @var array $allowedExtension Allowed Extensions For File Upload
     */
    public static array $allowedExtension = ['jpg','png','gif'];

    /**
     * @var string|int $csrfTokenName Token Name For Use In Forms And Session
     */
    private static string|int $csrfTokenName = '_token';

    /**
     * @var string $htaccessPath .htaccess File Path
     */
    public static string $htaccessPath;

    /**
     * @var string $htaccessContent .htaccess File Content
     */
    protected static string $htaccessContent;


    /**
     * Necessary Default Definitions
     */
    public function __construct()
    {
        self::$htaccessPath = getcwd() . '/.htaccess';
        self::$htaccessContent = "
        ##### Security Codes Start #####
        # Enable rewrite engine
        RewriteEngine On

        # Block suspicious request methods
        RewriteCond %{REQUEST_METHOD} ^(HEAD|TRACE|DELETE|TRACK|DEBUG) [NC]

        RewriteRule ^(.*)$ - [F,L]


        # Block suspicious user agents and requests
        RewriteCond %{HTTP_USER_AGENT} (libwww-perl|wget|python|nikto|curl|scan|java|winhttp|clshttp|loader) [NC,OR]
        RewriteCond %{HTTP_USER_AGENT} (<|>|'|%0A|%0D|%27|%3C|%3E|%00) [NC,OR]
        RewriteCond %{HTTP_USER_AGENT} (;|<|>|'|\"|\)|\(|%0A|%0D|%22|%27|%28|%3C|%3E|%00).*(libwww-perl|wget|python|nikto|curl|scan|java|winhttp|HTTrack|clshttp|archiver|loader|email|harvest|extract|grab|miner) [NC,OR]
        RewriteCond %{THE_REQUEST} \?\ HTTP/ [NC,OR]
        RewriteCond %{THE_REQUEST} \/\*\ HTTP/ [NC,OR]
        RewriteCond %{THE_REQUEST} etc/passwd [NC,OR]
        RewriteCond %{THE_REQUEST} cgi-bin [NC,OR]
        RewriteCond %{THE_REQUEST} (%0A|%0D) [NC,OR]
        
        # Block Indexes
        Options -Indexes
        
        # Block LFI and RFI
        php_flag allow_url_include off
        php_flag allow_url_fopen off


        # Block Bad Commands
        php_admin_value disable_functions \"exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source\"
        

        # Block MySQL injections, RFI, base64, etc.
        RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=http:// [OR]
        RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=(\.\.//?)+ [OR]
        RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=/([a-z0-9_.]//?)+ [NC,OR]
        RewriteCond %{QUERY_STRING} \=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} [NC,OR]
        RewriteCond %{QUERY_STRING} (\.\./|\.\.) [OR]
        RewriteCond %{QUERY_STRING} ftp\: [NC,OR]
        RewriteCond %{QUERY_STRING} http\: [NC,OR]
        RewriteCond %{QUERY_STRING} https\: [NC,OR]
        RewriteCond %{QUERY_STRING} \=\|w\| [NC,OR]
        RewriteCond %{QUERY_STRING} ^(.*)/self/(.*)$ [NC,OR]
        RewriteCond %{QUERY_STRING} ^(.*)cPath=http://(.*)$ [NC,OR]
        RewriteCond %{QUERY_STRING} (\<|%3C).*script.*(\>|%3E) [NC,OR]
        RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]
        RewriteCond %{QUERY_STRING} (\<|%3C).*iframe.*(\>|%3E) [NC,OR]
        RewriteCond %{QUERY_STRING} (<|%3C)([^i]*i)+frame.*(>|%3E) [NC,OR]
        RewriteCond %{QUERY_STRING} base64_encode.*\(.*\) [NC,OR]
        RewriteCond %{QUERY_STRING} base64_(en|de)code[^(]*\([^)]*\) [NC,OR]
        RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
        RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2}) [OR]
        RewriteCond %{QUERY_STRING} ^.*(\[|\]|\(|\)|<|>).* [NC,OR]
        RewriteCond %{QUERY_STRING} (NULL|OUTFILE|LOAD_FILE) [OR]
        RewriteCond %{QUERY_STRING} (\./|\../|\.../)+(motd|etc|bin) [NC,OR]
        RewriteCond %{QUERY_STRING} (localhost|loopback|127\.0\.0\.1) [NC,OR]
        RewriteCond %{QUERY_STRING} (<|>|'|%0A|%0D|%27|%3C|%3E|%00) [NC,OR]
        RewriteCond %{QUERY_STRING} concat[^\(]*\( [NC,OR]
        RewriteCond %{QUERY_STRING} union([^s]*s)+elect [NC,OR]
        RewriteCond %{QUERY_STRING} union([^a]*a)+ll([^s]*s)+elect [NC,OR]
        RewriteCond %{QUERY_STRING} (;|<|>|'|\"|\)|%0A|%0D|%22|%27|%3C|%3E|%00).*(/\*|union|select|insert|drop|delete|update|cast|create|char|convert|alter|declare|order|script|set|md5|benchmark|encode) [NC,OR]
        RewriteCond %{QUERY_STRING} (sp_executesql) [NC]

        RewriteRule ^(.*)$ - [F,L]
        ##### Security Codes End #####
        ";
    }

    /**
     * Set Cipher Value
     * AES256-SHA,AES256-SHA256,AES128-SHA...
     * 
     * @param $cipher
     */
    public function set_cipher($cipher): void
    {
        self::$cipher = $cipher;
    }

    /**
     * Set Security Key
     * 
     * @param $key
     */
    public function set_key($key): void
    {
        self::$key = $key;
    }

    /**
     * Set Allowed Extensions For File Upload
     * 
     * @param array $allowedExtension
     */
    public function set_allowedExtension(array $allowedExtension): void
    {
        self::$allowedExtension = $allowedExtension;
    }

    /**
     * Set Token Name For Form İnput Name And Session
     * 
     * @param string $csrfTokenName
     */
    public function set_tokenName(string $csrfTokenName): void
    {
        self::$csrfTokenName = $csrfTokenName;
    }

    /**
     * Set Own .htaccess File Path
     * 
     * @param string $htaccessPath
     */
    public function set_htaccessPath(string $htaccessPath): void
    {
        self::$htaccessPath = $htaccessPath;
    }

    /**
     * Encrypte Data
     * 
     * @param string|int $data
     */
    public static function encrypte(string|int $data): string|int
    {
        return openssl_encrypt($data,self::$cipher,self::$key);
    }

    /**
     * Decrypte Data
     * 
     * @param string|int $data
     */
    public static function decrypte(string|int $data): string|int
    {
        return openssl_decrypt($data,self::$cipher,self::$key);
    }

    /**
     * For Secure From Xss...
     * 
     * @param string|int $data
     */
    public static function clear(string|int $data): string|int
    {
        return htmlspecialchars(strip_tags(trim($data)));
    }

    /**
     * Undecryptable Encryption
     * password...
     * 
     * @param string|int $data
     */
    public static function hard(string|int $data): string|int
    {
        for($i = 0;$i<self::$level;$i++){
            if($i %2 == 0){
                $data = md5($data);
            }else {
                $data = sha1($data);
            }
        }
        return $data;
    }

    /**
     * Validate Data
     * 
     * @param array|null $data
     */
    public static function validator(array|null $data = []): bool
    {
        $output = False;
        if($data != null){
            foreach($data as $key => $value){
                if(empty($key) && $key == null && $key == '' && !$key){
                    $output = False;
                }else {
                    $output = True;
                }
            }
        }else {
            $output = False;
        }
        return $output;
    }

    /**
     * For Array Cleaning
     * 
     * @param array $data
     */
    public static function array(array $data = []): array
    {
        foreach($data as $key => $value){
            $data[$key] = self::clear($value);
        }
        return $data;
    }

    /**
     * Get Post Datas
     * 
     * @param array|string $data
     */
    public static function post(array|string $data): string|int|null
    {
        if(is_array($_POST[$data])){
            return self::array($_POST[$data]);
        }else {
            return self::clear($_POST[$data]);
        }
    }

    /**
     * Get Get Datas
     * 
     * @param array|string $data
     */
    public static function get(array|string $data): string|int|null
    {
        if(is_array($_GET[$data])){
            return self::array($_GET[$data]);
        }else {
            return self::clear($_GET[$data]);
        }
    }

    /**
     * For file Upload Security
     * 
     * @param array $data
     */
    public static function files(array $data = []): array|null
    {  
        foreach($data as $key => $value){
            $path = preg_replace('/\d/','',pathinfo($_FILES[$key]['name'], PATHINFO_EXTENSION));
            if(in_array($path,self::$refusedExtension,True) && !in_array($path,self::$allowedExtension)){
                $_FILES[$key] = NULL;
            } 
        }
        return $data;
    }

    /**
     * Csrf Protection
     */
    protected static function csrf(): void
    {
        if(!self::validator(@$_SESSION)){
            session_start();
        }
        if(!self::validator($_POST)){
            $_SESSION[self::$csrfTokenName] = md5(microtime() . rand(0,9999999));
        }elseif(self::validator($_POST)){
            if(self::post(self::$csrfTokenName) != $_SESSION[self::$csrfTokenName]){
                die();
            }
        }
    }

    /**
     * Get Validate Token For Form İnput
     */
    public static function get_token(): int|string|null
    {
        return $_SESSION[self::$csrfTokenName];
    }

    /**
     * Write .htaccess File For Secure
     * MySQL Injections, RFI, Base64...
     */
    public static function htaccess(): void
    {   
        if(!file_exists(self::$htaccessPath)){
            touch(self::$htaccessPath);
            self::write_htaccess();
        }else {
            $file = fopen(self::$htaccessPath,'a+');
            $content = @fread($file,@filesize(self::$htaccessPath));
            if(!preg_match('/##### Security Codes Start #####/',$content)){
                self::write_htaccess();
            }
        }
    }

    /**
     * For Write Htaccess File
     */
    private static function write_htaccess()
    {
        $file = fopen(self::$htaccessPath,'a');
        fwrite($file,self::$htaccessContent);
    }

    /**
     * All In One WAF
     * 
     * @param bool $postControl
     * @param bool $getControl
     * @param bool $fileControl
     * @param bool $csrfControl
     */
    public static function waf(bool $postControl = True,bool $getControl = True,bool $fileControl = True,bool $csrfControl = True,bool $writeHtaccess = True): void
    {
        if(self::validator($_POST) && $postControl){
            self::array($_POST);
        }
        if(self::validator($_GET) && $getControl){
            self::array($_GET);
        }
        if(isset($_FILES) && $fileControl){
            self::files($_FILES);
        }
        if($csrfControl){
            self::csrf();
        }
        if($writeHtaccess){
            self::htaccess();
        }
    }

}
