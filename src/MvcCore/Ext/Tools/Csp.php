<?php

namespace MvcCore\Ext\Tools;

/**
 * Extension to easilly complete `Content-Security-Policy` HTTP header.
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
 * @see https://www.w3.org/TR/CSP3/
 * @see https://content-security-policy.com/
 */
class Csp implements \MvcCore\Ext\Tools\Csp\IConstants {

	use \MvcCore\Ext\Tools\Csp\Props,
		\MvcCore\Ext\Tools\Csp\LocalMethods,
		\MvcCore\Ext\Tools\Csp\PublicMethods,
		\MvcCore\Ext\Tools\Csp\GroupMethods;
	
	/**
	 * MvcCore Extension - Tool - Content Security Policy - version:
	 * Comparison by PHP function version_compare();
	 * @see http://php.net/manual/en/function.version-compare.php
	 */
	const VERSION = '5.0.5';

}