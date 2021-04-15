<?php

namespace MvcCore\Ext\Tools\Csps;

use \MvcCore\Ext\Tools\Csp;

/**
 * @mixin \MvcCore\Ext\Tools\Csp
 */
trait PublicMethods {

	/**
	 * Get Content Security Policy singleton instance.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public static function GetInstance () {
		if (self::$instance === NULL)
			self::$instance = new static();
		return self::$instance;
	}


	/**
	 * Parse CSP header defined elsewhere
	 * in any 3rd party library or another PHP code.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function ParsePhpHeader () {
		$allResponseHeaders = headers_list();
		$cspHeaderLength = strlen(self::$headerName);
		foreach ($allResponseHeaders as $responseHeader) {
			$cspPos = mb_strpos($responseHeader, self::$headerName . ':');
			if ($cspPos === FALSE) continue;
			if ($this->lastCspHeader !== NULL && $this->lastCspHeader === $responseHeader) break;
			$this->lastCspHeader = $responseHeader;
			$cspHeaderValue = mb_substr($responseHeader, $cspPos + $cspHeaderLength + 1);
			$cspHeaderValue = trim(preg_replace('#\s+#', ' ', $cspHeaderValue));
			$cspHeaderSections = explode(';', $cspHeaderValue);
			foreach ($cspHeaderSections as $cspHeaderSection) {
				$cspHeaderSection = trim($cspHeaderSection);
				if (!$cspHeaderSection) continue;
				$firstSpacePos = mb_strpos($cspHeaderSection, ' ');
				if ($firstSpacePos === FALSE) continue;
				$directiveName = mb_substr($cspHeaderSection, 0, $firstSpacePos);
				$directiveValuesStr = mb_substr($cspHeaderSection, $firstSpacePos + 1);
				if (
					!isset(self::$directives[$directiveName]) ||
					mb_strlen($directiveValuesStr) === 0
				) continue;
				$directiveValues = explode(' ', $directiveValuesStr);
				$directiveConfig = isset($this->config[$directiveName])
					? $this->config[$directiveName]
					: [];
				foreach ($directiveValues as $directiveValue) {
					if ($directiveValue === "'none'") {
						$directiveConfig = FALSE;
						break;
					} else {
						$directiveConfig[$directiveValue] = TRUE;
					}
				}
				$this->config[$directiveName] = $directiveConfig;
			}
			break;
		}
		return $this;
	}


	/**
	 * Allow self resources by given CSP directive(s).
	 * @param  int $sourceFlags CSP directive(s) to allow self resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowSelf ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'self'", TRUE);
	}

	/**
	 * Disallow previously allowed self resources by given CSP directive(s).
	 * @param  int $sourceFlags CSP directive(s) to allow self resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowSelf ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'self'", FALSE);
	}
	
	/**
	 * Check if there is/are allowed self resources by given CSP directive(s).
	 * @param  int $sourceFlags CSP directive(s) to check if allowed self resources.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function IsAllowedSelf ($sourceFlags) {
		return $this->isConfigAllowed($sourceFlags, "'self'");
	}


	/**
	 * Allow loading of resources from a specific host,
	 * with optional scheme, port, and path. e.g. `example.com`,
	 * `*.example.com`, `https://*.example.com:12/path/to/file.js`.
	 * @param  int   $sourceFlags 
	 * CSP directive(s) to allow resources by second argument.
	 * @param  array $hostsOrUrls 
	 * Host, with optional scheme, port, and path. e.g. `example.com`, 
	 * `*.example.com`, `https://*.example.com:12/path/to/file.js`.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowHosts ($sourceFlags, array $hostsOrUrls) {
		if (count($hostsOrUrls) === 0) return $this;
		$this->checkSendHeaders();
		foreach ($hostsOrUrls as $hostOrUrl) 
			$this->setConfigAllow($sourceFlags, $hostOrUrl);
		return $this;
	}

	/**
	 * Disallow previously allowed loading of previously allowed resources from a specific host,
	 * with optional scheme, port, and path. e.g. `example.com`,
	 * `*.example.com`, `https://*.example.com:12/path/to/file.js`.
	 * @param  int   $sourceFlags 
	 * CSP directive(s) to disallow resources by second argument.
	 * @param  array $hostsOrUrls 
	 * Host, with optional scheme, port, and path. e.g. `example.com`, 
	 * `*.example.com`, `https://*.example.com:12/path/to/file.js`.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowHosts ($sourceFlags, array $hostsOrUrls) {
		if (count($hostsOrUrls) === 0) return $this;
		$this->checkSendHeaders();
		foreach ($hostsOrUrls as $hostOrUrl)
			$this->setConfigDisallow($sourceFlags, $hostOrUrl);
		return $this;
	}
	
	/**
	 * Check if there is allowed host or url resource by given CSP directive(s).
	 * @param  int    $sourceFlags CSP directive(s) to check if allowed host or url resources.
	 * @param  string $hostOrUrl
	 * Host, with optional scheme, port, and path. e.g. `example.com`, 
	 * `*.example.com`, `https://*.example.com:12/path/to/file.js`.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function IsAllowedHost ($sourceFlags, $hostOrUrl) {
		return $this->isConfigAllowed($sourceFlags, $hostOrUrl);
	}


	/**
	 * Allow loading of resources over a specific scheme, scheme should 
	 * always end with ":". e.g. `https`:, `http:`, `data:` etc.
	 * WARNING: THIS METHOD IS HIGHLY NOT RECOMMENDED!
	 * @param  int    $sourceFlags 
	 * CSP directive(s) to allow resources by second argument.
	 * @param  string $scheme 
	 * Scheme like `'http:'`, `'https:'` or `'data:'` ...
	 * @throws \Exception Headers has been sent already.
	 * @throws \InvalidArgumentException Provided scheme value is not valid scheme: `^([a-z][a-z0-9]+)\:$`.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowSheme ($sourceFlags, $scheme = 'https:') {
		$this->checkSendHeaders();
		$this->setConfigAllow($sourceFlags, $this->checkScheme($scheme));
		return $this;
	}

	/**
	 * Disallow previously allowed loading of resources over a specific scheme, 
	 * scheme should always end with ":". e.g. `https`:, `http:`, `data:` etc.
	 * WARNING: THIS METHOD IS HIGHLY NOT RECOMMENDED!
	 * @param  int    $sourceFlags 
	 * CSP directive(s) to disallow resources by second argument.
	 * @param  string $scheme 
	 * Scheme like `'http:'`, `'https:'` or `'data:'` ...
	 * @throws \Exception Headers has been sent already.
	 * @throws \InvalidArgumentException Provided scheme value is not valid scheme: `^([a-z][a-z0-9]+)\:$`.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowSheme ($sourceFlags, $scheme = 'https:') {
		$this->checkSendHeaders();
		$this->setConfigDisallow($sourceFlags, $this->checkScheme($scheme));
		return $this;
	}
	
	/**
	 * Check if there is allowed resources under scheme by given CSP directive(s).
	 * @param  int    $sourceFlags 
	 * CSP directive(s) to check if allowed resources under scheme.
	 * @param  string $scheme 
	 * Scheme like `'http:'`, `'https:'` or `'data:'` ...
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function IsAllowedSheme ($sourceFlags, $scheme = 'https:') {
		return $this->isConfigAllowed($sourceFlags, $this->checkScheme($scheme));
	}


	/**
	 * Allow use of inline resources like `<script></script>`, 
	 * `<style></style>` or `javascript:` URLs.
	 * WARNING: THIS METHOD IS HIGHLY NOT RECOMMENDED!
	 * @param  int $sourceFlags CSP directive(s) to allow inline resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowUnsafeInline ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'unsafe-inline'", TRUE);
	}

	/**
	 * Disallow use of inline resources like `<script></script>`, 
	 * `<style></style>` or `javascript:` URLs..
	 * @param  int $sourceFlags CSP directive(s) to disallow inline resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowUnsafeInline ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'unsafe-inline'", FALSE);
	}
	
	/**
	 * Check if there is allowed inline resources like `<script></script>`, 
	 * `<style></style>` or `javascript:` URLs.
	 * @param  int $sourceFlags CSP directive(s) to check allowed inline resources.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function IsAllowedUnsafeInline ($sourceFlags) {
		return $this->isConfigAllowed($sourceFlags, "'unsafe-inline'");
	}
	

	/**
	 * Allow inline CSS and JS code inside HTML element's attributes.
	 * For JS, enabling specific inline event handlers. If you only need 
	 * to allow inline event handlers and not inline `<script>` elements or 
	 * `javascript:` URLs, this is a safer than using the `'unsafe-inline'`.
	 * WARNING! This CSP is supported only from CSP Level 3!
	 * @param  int        $sourceFlags CSP directive(s) to allow unsave hashes resources.
	 * @see https://content-security-policy.com/unsafe-hashes/
	 * @see https://caniuse.com/?search=unsafe-hashes
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowUnsafeHashes ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'unsafe-hashes'", TRUE);
	}

	/**
	 * Disallow previously allowed inline CSS and JS code inside HTML element's attributes.
	 * For JS, disable previously enabled specific inline event handlers. If you only need 
	 * to allow inline event handlers and not inline `<script>` elements or 
	 * `javascript:` URLs, this is a safer than using the `'unsafe-inline'`.
	 * WARNING! This CSP is supported only from CSP Level 3!
	 * @param  int        $sourceFlags CSP directive(s) to disallow unsave hashes resources.
	 * @see https://content-security-policy.com/unsafe-hashes/
	 * @see https://caniuse.com/?search=unsafe-hashes
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowUnsafeHashes ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'unsafe-hashes'", FALSE);
	}
	
	/**
	 * Check if there is allowed inline CSS and JS code inside HTML element's 
	 * attributes. For JS, enabled specific inline event handlers. If you only need 
	 * to allow inline event handlers and not inline `<script>` elements or 
	 * `javascript:` URLs, this is a safer than using the `'unsafe-inline'`.
	 * WARNING! This CSP is supported only from CSP Level 3!
	 * @param  int $sourceFlags CSP directive(s) to check allowed unsave hashes resources.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function IsAllowedUnsafeHashes ($sourceFlags) {
		return $this->isConfigAllowed($sourceFlags, "'unsafe-hashes'");
	}


	/**
	 * Allow use of dynamic code evaluation by `eval()`, `setImmediate()`, 
	 * `new Function()`, `execScript()`, `setInterval()` and `setTimeout()`.
	 * WARNING: THIS METHOD IS HIGHLY NOT RECOMMENDED!
	 * @param  int        $sourceFlags CSP directive(s) to allow unsafe eval resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowUnsafeEval ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'unsafe-eval'", TRUE);
	}

	/**
	 * Disallow previously allowed to use of dynamic code evaluation by
	 * `eval()`, `setImmediate()`, `new Function()`, `execScript()`, 
	 * `setInterval()` and `setTimeout()`
	 * @param  int        $sourceFlags CSP directive(s) to disallow unsafe eval resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowUnsafeEval ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'unsafe-eval'", FALSE);
	}
	
	/**
	 * Check if there is allowed to use of dynamic code evaluation by 
	 * `eval()`, `setImmediate()`, `new Function()`, `execScript()`, 
	 * `setInterval()` and `setTimeout()`.
	 * @param  int $sourceFlags CSP directive(s) to check allowed dynamic code evaluation.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function IsAllowedUnsafeEval ($sourceFlags) {
		return $this->isConfigAllowed($sourceFlags, "'unsafe-eval'");
	}

	
	/**
	 * Allow anything in trusted `<script>` tag marked by nonce or hash.
	 * If you use this policy, there are ignored any allow-list or source 
	 * expressions such as 'self' or 'unsafe-inline'. So then, there is 
	 * necessary to mark all other `<script>` tags with nonce or hashes.
	 * WARNING! This CSP is supported only from CSP Level 3!
	 * @see https://content-security-policy.com/strict-dynamic/
	 * @see https://caniuse.com/?search=strict-dynamic
	 * @param  int        $sourceFlags CSP directive(s) to allow strict dynamic resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowStrictDynamic ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'strict-dynamic'", TRUE);
	}

	/**
	 * Disallow previously allowed anything in trusted `<script>` tag marked 
	 * by nonce or hash. If you use this policy, there are ignored any allow-list 
	 * or source expressions such as 'self' or 'unsafe-inline'. So then, 
	 * there is necessary to mark all other `<script>` tags with nonce or hashes.
	 * WARNING! This CSP is supported only from CSP Level 3!
	 * @see https://content-security-policy.com/strict-dynamic/
	 * @see https://caniuse.com/?search=strict-dynamic
	 * @param  int        $sourceFlags CSP directive(s) to disallow strict dynamic resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowStrictDynamic ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'strict-dynamic'", FALSE);
	}
	
	/**
	 * Check if there is allowed anything in trusted `<script>` tag marked 
	 * by nonce or hash. If you use this policy, there are ignored any allow-list 
	 * or source expressions such as 'self' or 'unsafe-inline'. So then, there 
	 * is necessary to mark all other `<script>` tags with nonce or hashes.
	 * WARNING! This CSP is supported only from CSP Level 3!
	 * @param  int $sourceFlags CSP directive(s) to check allowed strict dynamic resources.
	 * @return bool
	 */
	public function IsAllowedStrictDynamic ($sourceFlags) {
		return $this->isConfigAllowed($sourceFlags, "'strict-dynamic'");
	}


	/**
	 * Allow `<script>`, `<style>` or any other resources marked by nonce attribute.
	 * @param  int        $sourceFlags CSP directive(s) to allow resources with nonce attribute.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowNonce ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'nonce-{$this->GetNonce()}'", TRUE);
	}

	/**
	 * Disallow previously allowed `<script>`, `<style>` or any 
	 * other resources marked by nonce attribute.
	 * @param  int        $sourceFlags CSP directive(s) to disallow resources with nonce attribute.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowNonce ($sourceFlags) {
		return $this->setConfigCspDirective($sourceFlags, "'nonce-{$this->GetNonce()}'", FALSE);
	}

	/**
	 * Check if there is allowed `<script>`, `<style>` or any 
	 * other resources marked by nonce attribute.
	 * @param  int $sourceFlags CSP directive(s) to check allowed resources with nonce attribute.
	 * @return bool
	 */
	public function IsAllowedNonce ($sourceFlags) {
		return $this->isConfigAllowed($sourceFlags, "'nonce-{$this->GetNonce()}'");
	}


	/**
	 * Allow JS/CSS source code by hash (sha256 by default).
	 * @param  int        $sourceFlags CSP directive(s) to allow hashed resources.
	 * @param  string     $sourceCode  JS source code, including all whitespaces, excluding `<script>` tags.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowHashedSourceCode ($sourceFlags, $sourceCode, $hashAlgo = 'sha256') {
		$souceHash = base64_encode(hash($hashAlgo, $sourceCode, TRUE));
		return $this->setConfigCspDirective($sourceFlags, "'{$hashAlgo}-{$souceHash}'", TRUE);
	}

	/**
	 * Disallow previously allowed JS/CSS source code by hash (sha256 by default).
	 * @param  int        $sourceFlags CSP directive(s) to disallow hashed resources.
	 * @param  string     $sourceCode  JS source code, including all whitespaces, excluding `<script>` tags.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowHashedSourceCode ($sourceFlags, $sourceCode, $hashAlgo = 'sha256') {
		$souceHash = base64_encode(hash($hashAlgo, $sourceCode, TRUE));
		return $this->setConfigCspDirective($sourceFlags, "'{$hashAlgo}-{$souceHash}'", FALSE);
	}
	
	/**
	 * Check if there is allowed JS/CSS source code by hash (sha256 by default).
	 * @param  int $sourceFlags CSP directive(s) to check allowed resources by hash.
	 * @return bool
	 */
	public function IsAllowedHashedSource ($sourceFlags, $sourceCode, $hashAlgo = 'sha256') {
		$souceHash = base64_encode(hash($hashAlgo, $sourceCode, TRUE));
		return $this->isConfigAllowed($sourceFlags, "'{$hashAlgo}-{$souceHash}'");
	}


	/**
	 * Disallow CSP directive.
	 * @param  int        $sourceFlags CSP directive(s) to disallow completelly.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function Disallow ($sourceFlags)	{
		/** @var \MvcCore\Ext\Tools\Csp $this */
		$this->checkSendHeaders();
		foreach (Csp::$directives as $directiveName => $sourceFlag) {
			if (($sourceFlags & $sourceFlag) === 0) continue;
			$this->config[$directiveName] = FALSE;
		}
		return $this;
	}
	
	/**
	 * Get (cryptographic) nonce attribute value - "number (only used) once" 
	 * to whitelist `<script>`, `<style>` or any other resources. ¨This method could 
	 * be called multiple times in one request, because it creates the nonce number 
	 * only for first time and nextime there is returned the same value. Another PHP 
	 * request will get dirferent nonce value. Method returns only the attribute value
	 * like `RGhjbmhEM2toVE1lUGdYd2RheUs5QnNNcVhqaGd1VlY`.
	 * @return string
	 */
	public function GetNonce () {
		if ($this->nonceHash === NULL) 
			$this->nonceHash = self::createNonceHash();
		return $this->nonceHash;
	}

	/**
	 * Complete header from internal configuration and returns it.
	 * @param  bool   $withHeaderName `FALSE` by default to return only header value.
	 * @return string
	 */
	public function GetHeader ($withHeaderName = FALSE) {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		$headerSections = [];
		foreach ($this->config as $directiveName => $uniqueValues) {
			if (is_array($uniqueValues)) {
				$headerSections[] = $directiveName . ' ' . implode(' ', array_keys($uniqueValues));
			} else if (is_bool($uniqueValues) && !$uniqueValues) {
				$headerSections[] = $directiveName . " 'none'";
			}
		}
		if (count($headerSections) > 0) {
			if ($withHeaderName) {
				return Csp::$headerName . ': ' . implode('; ', $headerSections);
			} else {
				return implode('; ', $headerSections);
			}
		}
		return '';
	}
}
