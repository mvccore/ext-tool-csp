<?php

namespace MvcCore\Ext\Tools;

/**
 * Extension to easilly complete `Content-Security-Policy` HTTP header.
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
 * @see https://www.w3.org/TR/CSP3/
 * @see https://content-security-policy.com/
 */
class Csp implements \MvcCore\Ext\Tools\Csps\IConstants {

	use \MvcCore\Ext\Tools\Csps\Props,
		\MvcCore\Ext\Tools\Csps\LocalMethods,
		\MvcCore\Ext\Tools\Csps\PublicMethods,
		\MvcCore\Ext\Tools\Csps\GroupMethods;
	
	/**
	 * MvcCore Extension - Tool - Content Security Policy - version:
	 * Comparison by PHP function version_compare();
	 * @see http://php.net/manual/en/function.version-compare.php
	 */
	const VERSION = '5.0.0';

}