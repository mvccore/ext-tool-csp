<?php

namespace MvcCore\Ext\Tools\Csps;

/**
 * @mixin \MvcCore\Ext\Tools\Csp
 */
trait LocalMethods {

	/**
	 * There is not possible to create instance outside of this class.
	 * @return void
	 */
	private function __construct() {
	}

	/**
	 * Cryptographic nonce (only used once) to whitelist scripts.
	 * The server must generate a unique nonce value each time it
	 * transmits a policy. It is critical to provide a nonce that
	 * cannot be guessed as bypassing a resource's policy is otherwise
	 * trivial. This is used in conjunction with the script tag nonce
	 * attribute. e.g. `nonce-DhcnhD3khTMePgXwdayK9BsMqXjhguVV`.
	 * @return string
	 */
	protected static function createNonceHash () {
		if (function_exists('openssl_random_pseudo_bytes')) {
			$randomHash = bin2hex(openssl_random_pseudo_bytes(16));
		} else if (PHP_VERSION_ID >= 70000) {
			$randomHash = bin2hex(random_bytes(16));
		} else {
			$randomHash = '';
			for ($i = 0; $i < 16; $i++) 
				/** @see https://github.com/php/php-src/blob/master/ext/standard/mt_rand.c */
				$randomHash .= str_pad(dechex(rand(0,255)),2,'0',STR_PAD_LEFT);
		}
		return base64_encode($randomHash);
	}

	/**
	 * Allow or disallow predefined CSP directive.
	 * @param  int    $sourceFlags
	 * @param  string $value
	 * @param  bool   $allow
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	protected function setConfigCspDirective ($sourceFlags, $cspDirective, $allow) {
		$this->checkSendHeaders();
		$allow
			? $this->setConfigAllow($sourceFlags, $cspDirective)
			: $this->setConfigDisallow($sourceFlags, $cspDirective);
		return $this;
	}

	/**
	 * Set value into local configuration property to complete header value later.
	 * @param  int    $sourceFlags
	 * @param  string $value
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	protected function setConfigAllow ($sourceFlags, $value) {
		foreach (self::$directives as $directiveName => $sourceFlag) {
			if (($sourceFlags & $sourceFlag) === 0) continue;
			if (isset($this->config[$directiveName])) {
				$directiveConfig = $this->config[$directiveName];
				if (!is_array($directiveConfig)) $directiveConfig = [];
			} else {
				$directiveConfig = [];
			}
			$directiveConfig[$value] = TRUE;
			$this->config[$directiveName] = $directiveConfig;
		}
		return $this;
	}

	/**
	 * Unset value from local configuration property to complete header value later.
	 * @param  int    $sourceFlags
	 * @param  string $value
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	protected function setConfigDisallow ($sourceFlags, $value) {
		foreach (self::$directives as $directiveName => $sourceFlag) {
			if (($sourceFlags & $sourceFlag) === 0) continue;
			$directiveConfig = isset($this->config[$directiveName])
				? $this->config[$directiveName]
				: [];
			if (isset($directiveConfig[$value]))
				unset($directiveConfig[$value]);
			if (count($directiveConfig) === 0) {
				unset($this->config[$directiveName]);
			} else {
				$this->config[$directiveName] = $directiveConfig;
			}
		}
		return $this;
	}

	/**
	 * Check if given single CSP flag or all CSP flags has allowed values in second argument.
	 * @param  int    $sourceFlags
	 * @param  string $value 
	 * @param  bool   $checkAllFlags
	 * @return bool
	 */
	protected function isConfigAllowed ($sourceFlags, $value, $checkAllFlags = TRUE) {
		$log2 = log($sourceFlags) / log(2);
		$isSingleFlag = ($log2 - intval(round($log2))) === 0.0;
		if ($isSingleFlag) {
			$directiveName = array_search($sourceFlags, self::$directives, TRUE);
			return isset($this->config[$directiveName][$value]);
		} else {
			$allFlagsAllowed = $checkAllFlags;
			foreach (self::$directives as $directiveName => $cspFlag) {
				if (($sourceFlags & $cspFlag) != 0) {
					$allowed = isset($this->config[$directiveName][$value]);
					if (($allFlagsAllowed && !$allowed) || (!$allFlagsAllowed && $allowed)) {
						$allFlagsAllowed = !$allFlagsAllowed;
						break;
					}
				}
			}
			return $allFlagsAllowed;
		}
	}

	/**
	 * Check if headers has been sent already.
	 * @throws \Exception Headers has been sent already.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	protected function checkSendHeaders () {
		if (headers_sent())
			throw new \Exception("Headers has been sent already.");
		return $this;
	}

	/**
	 * Check scheme form and returns it if it is correct.
	 * @param  string $scheme
	 * @throws \InvalidArgumentException Provided scheme value is not valid scheme: `^([a-z][a-z0-9]+)\:$`.
	 * @return string
	 */
	protected function checkScheme ($scheme) {
		if (!preg_match("#^([a-z][a-z0-9]+)\:$#", $scheme))
			throw new \InvalidArgumentException(
				"Provided scheme value is not valid scheme: `{$scheme}`."
			);
		return $scheme;
	}
}