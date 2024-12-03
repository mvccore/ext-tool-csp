<?php

namespace MvcCore\Ext\Tools\Csp;

use \MvcCore\Ext\Tools\Csp,
	\MvcCore\Ext\Tools\Csp\IConstants as CspConsts;

/**
 * @mixin \MvcCore\Ext\Tools\Csp
 */
trait GroupMethods {
	
	/**
	 * Allow Google Maps Embed API `<iframe>` source.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowGoogleMapsEmbedApi () {
		return $this
			->AllowHosts(
				CspConsts::FETCH_FRAME_SRC,
				['https://www.google.com/']
			);
	}

	/**
	 * Allow Google Maps JS API scripts and images.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowGoogleMapsJsApi () {
		return $this
			->AllowHosts(CspConsts::FETCH_SCRIPT_SRC, [
				'https://maps.googleapis.com',
				'https://maps.google.com',
				'https://maps.gstatic.com',
			])
			->AllowHosts(CspConsts::FETCH_IMG_SRC, [
				'data:',
				'https://maps.gstatic.com',
				'https://maps.googleapis.com',
			]);
	}

	/**
	 * Allow Google Fonts styles, images and font files.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowGoogleFonts () {
		return $this
			->AllowHosts(CspConsts::FETCH_STYLE_SRC, [
				'https://fonts.googleapis.com'
			])
			->AllowHosts(CspConsts::FETCH_IMG_SRC | CspConsts::FETCH_FONT_SRC, [
				'https://fonts.gstatic.com'
			]);
	}

	/**
	 * Allow Google Analytics scripts, images and connections.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowGoogleAnalytics () {
		return $this
			->AllowSelf(CspConsts::FETCH_SCRIPT_SRC)
			->AllowHosts(CspConsts::FETCH_IMG_SRC | CspConsts::FETCH_CONNECT_SRC | CspConsts::FETCH_SCRIPT_SRC, [
				'https://www.googletagmanager.com',
				'https://*.google-analytics.com',
				'https://ajax.googleapis.com'
			])
			->AllowHosts(CspConsts::FETCH_IMG_SRC | CspConsts::FETCH_CONNECT_SRC, [
				'https://stats.g.doubleclick.net',
			])
			->AllowHosts(CspConsts::FETCH_FRAME_SRC, [
				'https://*.fls.doubleclick.net'
			])
			->AllowHosts(CspConsts::FETCH_IMG_SRC, [
				'https://www.google.com',
			]);
	}
}
