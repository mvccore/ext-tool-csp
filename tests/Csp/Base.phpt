<?php

include_once(__DIR__ . '/../bootstrap.php');
include_once(__DIR__ . '/../../src/MvcCore/Ext/Tools/Csp.php');

use \Tester\Assert,
	\MvcCore\Ext\Tools\Csp;

/**
 * @see run.cmd ./Csp/*
 */
class CspTest extends \Tester\TestCase {

	/** before each test method */
	public function setUp () {
		header_remove('Content-Security-Policy');

		$csp = Csp::GetInstance();

		$configProp = new \ReflectionProperty($csp, 'config');
		if (!$configProp->isPublic()) $configProp->setAccessible(TRUE);
		$configProp->setValue($csp, []);

		$lastCspHeaderProp = new \ReflectionProperty($csp, 'lastCspHeader');
		if (!$lastCspHeaderProp->isPublic()) $lastCspHeaderProp->setAccessible(TRUE);
		$lastCspHeaderProp->setValue($csp, NULL);
	}

	/** after each test method */
	public function tearDown () {
		header_remove('Content-Security-Policy');
	}

	public function testParseExistingHeader () {
		if (php_sapi_name() === 'cli') return; // header() function doesn't work in CLI

		// set some CSP header anywhere in third party library or in any PHP ocde elsewhere:
		header("Content-Security-Policy: default-src 'self' http://example.com; connect-src 'none';");

		Csp::GetInstance()->ParsePhpHeader();

		// allow something more
		Csp::GetInstance()->AllowHosts(
			Csp::FETCH_FRAME_SRC | Csp::FETCH_MEDIA_SRC | Csp::FETCH_CONNECT_SRC,
			['*.google.com'],
			TRUE
		);
		
		Assert::equal(
			Csp::GetInstance()->GetHeaderValue(),
			"default-src 'self' http://example.com; connect-src *.google.com; frame-src *.google.com; media-src *.google.com"
		);
	}

	public function testAllowSelf () {
		// allow something for start
		Csp::GetInstance()->AllowHosts(
			Csp::FETCH_MEDIA_SRC,
			['*.google.com', '*.youtube.com']
		);

		// allow something more with self
		Csp::GetInstance()->AllowSelf(
			Csp::FETCH_MEDIA_SRC | Csp::FETCH_CONNECT_SRC
		);

		Assert::equal(
			Csp::GetInstance()->GetHeaderValue(),
			"media-src *.google.com *.youtube.com 'self'; connect-src 'self'"
		);
	}

	public function testDisallow () {
		// allow something
		Csp::GetInstance()->AllowHosts(
			Csp::FETCH_IMG_SRC | Csp::FETCH_FONT_SRC,
			['https://google.com']
		);

		// then disallow whole directive
		Csp::GetInstance()->Disallow(
			Csp::FETCH_IMG_SRC
		);

		Assert::equal(
			Csp::GetInstance()->GetHeaderValue(),
			"font-src https://google.com; img-src 'none'"
		);
	}

	public function testDisallowHost () {
		// allow something
		Csp::GetInstance()->AllowHosts(
			Csp::FETCH_IMG_SRC | Csp::FETCH_FONT_SRC,
			['https://google.com']
		);

		// then disallow whole directive
		Csp::GetInstance()->DisallowHosts(
			Csp::FETCH_IMG_SRC,
			['https://google.com']
		);

		Assert::equal(
			Csp::GetInstance()->GetHeaderValue(),
			"font-src https://google.com"
		);
	}

	public function testBaseConfiguration () {
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
			->AllowGoogleMaps()
			->AllowNonce(Csp::FETCH_SCRIPT_SRC);
		
		$nonce = Csp::GetInstance()->GetNonce();

		Assert::equal(
			Csp::GetInstance()->GetHeaderValue(),
			"default-src 'none'; object-src 'none'; connect-src 'self' https://some.tracking-counter-1.com/; font-src 'self'; frame-src 'self'; img-src 'self' data: https://maps.gstatic.com https://maps.googleapis.com; media-src 'self'; script-src 'self' https://some.tracking-counter-1.com/ https://cdnjs.com/ https://code.jquery.com/ https://maps.googleapis.com https://maps.google.com https://maps.gstatic.com 'nonce-{$nonce}'; style-src 'self'"
		);
	}

	public function testNonce () {
		// allow something
		Csp::GetInstance()->AllowNonce(Csp::FETCH_SCRIPT_SRC);

		$n1 = Csp::GetInstance()->GetNonce();
		$n2 = Csp::GetInstance()->GetNonce();

		Assert::true(!!preg_match("#^([a-zA-Z0-9\=/\+]{24})$#", $n1));

		Assert::true($n1 !== NULL);
		Assert::true($n2 !== NULL);
		Assert::equal($n1, $n2);
	}

}

run(function () {
	(new CspTest)->run();
});