<?php

namespace MvcCore\Ext\Tools\Csps;

use \MvcCore\Ext\Tools\Csp;
use \MvcCore\Ext\Tools\Csps\IConstants;

/**
 * @mixin \MvcCore\Ext\Tools\Csp
 */
trait Props {

	/**
	 * Singleton instance place.
	 * @var \MvcCore\Ext\Tools\Csp
	 */
	protected static $instance			= NULL;

	/**
	 * Internal store with CSP directives and API flags.
	 * @var array
	 */
	protected static $directives		= [
		'child-src'						=> IConstants::FETCH_CHILD_SRC,
		'connect-src'					=> IConstants::FETCH_CONNECT_SRC,
		'default-src'					=> IConstants::FETCH_DEFAULT_SRC,
		'font-src'						=> IConstants::FETCH_FONT_SRC,
		'frame-src'						=> IConstants::FETCH_FRAME_SRC,
		'img-src'						=> IConstants::FETCH_IMG_SRC,
		'manifest-src'					=> IConstants::FETCH_MANIFEST_SRC,
		'media-src'						=> IConstants::FETCH_MEDIA_SRC,
		'object-src'					=> IConstants::FETCH_OBJECT_SRC,
		'script-src'					=> IConstants::FETCH_SCRIPT_SRC,
		'style-src'						=> IConstants::FETCH_STYLE_SRC,
		'base-uri'						=> IConstants::DOCUMENT_BASE_URI,
		'plugin-types'					=> IConstants::DOCUMENT_PLUGIN_TYPES,
		'sandbox'						=> IConstants::DOCUMENT_IFRAME_SANDBOX,
		'form-action'					=> IConstants::NAVIGATION_FORM_ACTION,
		'frame-ancestors'				=> IConstants::NAVIGATION_FRAME_ANCESTORS,
		'navigate-to'					=> IConstants::NAVIGATION_TO,
		'block-all-mixed-content'		=> IConstants::OTHER_BLOCK_ALL_MIXED_CONTENT,
		'upgrade-insecure-requests'		=> IConstants::OTHER_UPGRADE_INSECURE_REQUESTS,
	];


	/**
	 * A unique nonce hash, unique for each request.
	 * @var string|NULL
	 */
	protected $nonceHash				= NULL;

	/**
	 * Internal configuration to complete result http csp header.
	 * @var array
	 */
	protected $config					= [];

	/**
	 * Last CSP PHP header value to not to parse PHP 
	 * header next time for the same values.
	 * @var string|NULL
	 */
	protected $lastCspHeader			= NULL;
	
	/**
	 * HTTP header name.
	 * @var string
	 */
	protected $headerName				= 'Content-Security-Policy';
}
