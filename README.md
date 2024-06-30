## Security

Advanced Security Class for Php

[![Latest Stable Version](http://poser.pugx.org/omerfdmrl/security/v)](https://packagist.org/packages/omerfdmrl/security) 
[![Total Downloads](http://poser.pugx.org/omerfdmrl/security/downloads)](https://packagist.org/packages/omerfdmrl/security) 
[![Latest Unstable Version](http://poser.pugx.org/omerfdmrl/security/v/unstable)](https://packagist.org/packages/omerfdmrl/security) 
[![License](http://poser.pugx.org/omerfdmrl/security/license)](https://packagist.org/packages/omerfdmrl/security) 
[![PHP Version Require](http://poser.pugx.org/omerfdmrl/security/require/php)](https://packagist.org/packages/omerfdmrl/security)


### Features
- Secure From XSS, CSRF, SQL Injection, BASE64, RFI, LFI, Command Injection, Block Suspicious Request Methods, Block Suspicious User Agents And Requests
- Block exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source Functions
- Advanced Encrypte - Decrypte
- Undecryptable Encryption
- Advanced WAF system

## Install

run the following command directly.

```
$ composer require omerfdmrl/security
```

## Example Usage
```php
include 'vendor/autoload.php';

use Omerfdmrl\Security\Security;

$security = new Security;

// Default is: AES-128-ECB
$security->set_cipher('AES-128-ECB');

// Default is: md5(your-domain)
$security->set_key('My Secure Key');

// Default is: ['jpg','png','gif'] | Default refused extensions is: ['php','bat','']
$security->set_allowedExtension(array('jpg','png','gif'));

// Default is: _token
$security->set_tokenName('_token');

// Default is: getcwd() . '/.htaccess'
$security->set_htaccessPath(__DIR__ . '.htaccess');

// Default is: True,True,True,True,True | You must call waf() function
// postControl, getControl, fileControl, csrfControl, writeHtaccess
$security->waf(True,True,True,True,True);
```


## Docs
Documentation page: [Security Docs][doc-url]


## Licence
[MIT Licence][mit-url]

## Contributing

1. Fork it ( https://github.com/omerfdmrl/security/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [omerfdmrl](https://github.com/omerfdmrl) Ömer Faruk Demirel - creator, maintainer

[mit-url]: http://opensource.org/licenses/MIT
[doc-url]: https://github.com/omerfdmrl/security/wiki
