## Security

Advanced Security Class for Php

[![Total Downloads](https://poser.pugx.org/izniburak/router/d/total.svg)](https://packagist.org/packages/omerfdmrl/security)
[![Latest Stable Version](https://poser.pugx.org/izniburak/router/v/stable.svg)](https://packagist.org/packages/omerfdmrl/security)
[![Latest Unstable Version](https://poser.pugx.org/izniburak/router/v/unstable.svg)](https://packagist.org/packages/omerfdmrl/security)
[![License](https://poser.pugx.org/izniburak/router/license.svg)](https://packagist.org/packages/omerfdmrl/security)

### Features
- Secure From XSS, CSRF, SQL Injection, BASE64, RFI, LFI, Command Injection, Block Suspicious Request Methods, Block Suspicious User Agents And Requests, 
- Advanced Encrypte - Decrypte
- Undecryptable Encryption
- Advanced WAF system
- 

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
$security->waf(True,True,True,True,True);
```


## Docs
Documentation page: [Security Docs][doc-url]


## Licence
[MIT Licence][mit-url]

## Contributing

1. Fork it ( https://github.com/omerfdmrl/waf/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [omerfdmrl](https://github.com/omerfdmrl) Ömer Faruk Demirel - creator, maintainer

[mit-url]: http://opensource.org/licenses/MIT
[doc-url]: https://github.com/omerfdmrl/waf/wiki
