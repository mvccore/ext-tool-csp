# MvcCore - Extension - Tool - Content Security Policy

[![Latest Stable Version](https://img.shields.io/badge/Stable-v5.0.1-brightgreen.svg?style=plastic)](https://github.com/mvccore/ext-tool-csp/releases)
[![License](https://img.shields.io/badge/License-BSD%203-brightgreen.svg?style=plastic)](https://mvccore.github.io/docs/mvccore/5.0.0/LICENSE.md)
![PHP Version](https://img.shields.io/badge/PHP->=5.4-brightgreen.svg?style=plastic)

## Installation
```shell
composer require mvccore/ext-tool-csp
```

## Features
Extension to easilly complete `Content-Security-Policy` HTTP header.  
Read more info here:
 - [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
 - [W3C](https://www.w3.org/TR/CSP3/)
 - [Content Security Policy](https://content-security-policy.com/)

## Usage
```php
<?php

include_once('vendor/autoload.php');

use \MvcCore\Ext\Tools\Csp;

Csp::GetInstance()
	->Disallow(
		Csp::FETCH_DEFAULT_SRC | 
		Csp::FETCH_OBJECT_SRC
	)
	->AllowSelf(
		Csp::FETCH_SCRIPT_SRC | 
		Csp::FETCH_STYLE_SRC | 
		Csp::FETCH_IMG_SRC |
		Csp::FETCH_FONT_SRC |
		Csp::FETCH_MEDIA_SRC |
		Csp::FETCH_CONNECT_SRC |
		Csp::FETCH_FRAME_SRC
	)
	->AllowHosts(
		Csp::FETCH_SCRIPT_SRC | Csp::FETCH_CONNECT_SRC, [
			'https://some.tracking-counter-1.com/',
		]
	)
	->AllowHosts(
		Csp::FETCH_SCRIPT_SRC, [
			'https://cdnjs.com/',
			'https://code.jquery.com/',
		]
	)
	->AllowHosts(
		Csp::FETCH_IMG_SRC, [
			'data:',
		]
	)
	->AllowNonce()
	->AllowGoogleMaps();
```

```html
<script nonce="<?=Csp::GetInstance()->GetNonce()?>"></script>
```
