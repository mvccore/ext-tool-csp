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
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective($sourceFlags, 'self', TRUE);
	}

	/**
	 * Disallow previously allowed self resources by given CSP directive(s).
	 * @param  int $sourceFlags CSP directive(s) to allow self resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowSelf ($sourceFlags) {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective($sourceFlags, 'self', FALSE);
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
		/** @var \MvcCore\Ext\Tools\Csp $this */
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
		/** @var \MvcCore\Ext\Tools\Csp $this */
		if (count($hostsOrUrls) === 0) return $this;
		$this->checkSendHeaders();
		foreach ($hostsOrUrls as $hostOrUrl)
			$this->setConfigDisallow($sourceFlags, $hostOrUrl);
		return $this;
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
		/** @var \MvcCore\Ext\Tools\Csp $this */
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
		/** @var \MvcCore\Ext\Tools\Csp $this */
		$this->checkSendHeaders();
		$this->setConfigDisallow($sourceFlags, $this->checkScheme($scheme));
		return $this;
	}

	/**
	 * Allow use of inline resources like `<script></script>` or `<style></style>`.
	 * WARNING: THIS METHOD IS HIGHLY NOT RECOMMENDED!
	 * @param  int $sourceFlags CSP directive(s) to allow inline resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowUnsafeInline ($sourceFlags) {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective($sourceFlags, 'unsafe-inline', TRUE);
	}

	/**
	 * Disallow use of inline resources like `<script></script>` or `<style></style>`.
	 * @param  int $sourceFlags CSP directive(s) to disallow inline resources.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowUnsafeInline ($sourceFlags) {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective($sourceFlags, 'unsafe-inline', FALSE);
	}

	/**
	 * Allow use of dynamic code evaluation such as `eval`, `setImmediate`, and `execScript`.
	 * WARNING: THIS METHOD IS HIGHLY NOT RECOMMENDED!
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowUnsafeEval () {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective(
			Csp::FETCH_SCRIPT_SRC, 'unsafe-eval', TRUE
		);
	}

	/**
	 * Disallow previously allowed to use of dynamic code evaluation 
	 * such as `eval`, `setImmediate`, and `execScript`.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowUnsafeEval () {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective(
			Csp::FETCH_SCRIPT_SRC, 'unsafe-eval', FALSE
		);
	}

	/**
	 * Allow JS source code by sha256 hash.
	 * @param  string $jsSourceCode JS source code, including all whitespaces, excluding `<script>` tags.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowJsSourceCode ($jsSourceCode) {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective(
			Csp::FETCH_SCRIPT_SRC, 
			'sha256-'. base64_encode(hash('sha256', $jsSourceCode, TRUE)), 
			TRUE
		);
	}

	/**
	 * Disallow previously allowed JS source code by sha256 hash.
	 * @param  string $jsSourceCode JS source code, including all whitespaces, excluding `<script>` tags.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowJsSourceCode ($jsSourceCode) {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective(
			Csp::FETCH_SCRIPT_SRC, 
			'sha256-' . base64_encode(hash('sha256', $jsSourceCode, TRUE)), 
			FALSE
		);
	}

	/**
	 * Allow to create another `<script>` tag inside external allowed script.
	 * WARNING! This CSP is supported only from CSP Level 3!
	 * @see https://content-security-policy.com/strict-dynamic/
	 * @see https://caniuse.com/?search=strict-dynamic
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowStrictDynamic () {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective(
			Csp::FETCH_SCRIPT_SRC, 'strict-dynamic', TRUE
		);
	}

	/**
	 * Disallow to create another `<script>` tag inside external allowed script.
	 * WARNING! This CSP is supported only from CSP Level 3!
	 * @see https://content-security-policy.com/strict-dynamic/
	 * @see https://caniuse.com/?search=strict-dynamic
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowStrictDynamic () {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective(
			Csp::FETCH_SCRIPT_SRC, 'strict-dynamic', FALSE
		);
	}

	/**
	 * Allow execution of inline scripts within a JS event handler attribute of a HTML element.
	 * WARNING! This CSP is supported only from CSP Level 3!
	 * @see https://content-security-policy.com/unsafe-hashes/
	 * @see https://caniuse.com/?search=unsafe-hashes
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowUnsaveHashes () {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective(
			Csp::FETCH_SCRIPT_SRC, 'unsafe-hashes', TRUE
		);
	}

	/**
	 * Disallow execution of inline scripts within a JS event handler attribute of a HTML element.
	 * WARNING! This CSP is supported only from CSP Level 3!
	 * @see https://content-security-policy.com/unsafe-hashes/
	 * @see https://caniuse.com/?search=unsafe-hashes
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function DisallowUnsaveHashes () {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		return $this->setConfigCspDirective(
			Csp::FETCH_SCRIPT_SRC, 'unsafe-hashes', FALSE
		);
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
	 * A (cryptographic) nonce (only used once) to whitelist scripts.
	 * Method returns unique nonce attribute each time it transmits
	 * a policy, e.g. `DhcnhD3khTMePgXwdayK9BsMqXjhguVV`.
	 * @param  bool       $checkSendHeaders `FALSE` by default, to not check if headers has been sent already or not.
	 * @throws \Exception Headers has been sent already.
	 * @return string
	 */
	public function GetNonce ($checkSendHeaders = FALSE) {
		/** @var \MvcCore\Ext\Tools\Csp $this */
		if ($this->nonceHash === NULL) {
			if ($checkSendHeaders) $this->checkSendHeaders();
			$this->nonceHash = self::createNonceHash();
			$this->setConfigAllow(
				Csp::FETCH_SCRIPT_SRC, 
				"'nonce-{$this->nonceHash}'"
			);
		}
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
