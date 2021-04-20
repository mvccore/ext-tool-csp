<?php

namespace MvcCore\Ext\Tools\Csps;

use \MvcCore\Ext\Tools\Csp;

/**
 * @mixin \MvcCore\Ext\Tools\Csp
 */
trait GroupMethods {

	/**
	 * Allow Google Maps scripts and images.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowGoogleMaps () {
		return $this
			->AllowHosts(Csp::FETCH_SCRIPT_SRC, [
				'https://maps.googleapis.com',
				'https://maps.google.com',
				'https://maps.gstatic.com',
			])
			->AllowHosts(Csp::FETCH_IMG_SRC, [
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
			->AllowHosts(Csp::FETCH_STYLE_SRC, [
				'https://fonts.googleapis.com'
			])
			->AllowHosts(Csp::FETCH_IMG_SRC | Csp::FETCH_FONT_SRC, [
				'https://fonts.gstatic.com'
			]);
	}

	/**
	 * Allow Google Analytics scripts, images and connections.
	 * @return \MvcCore\Ext\Tools\Csp
	 */
	public function AllowGoogleAnalytics () {
		return $this
			->AllowSelf(Csp::FETCH_SCRIPT_SRC)
			->AllowHosts(Csp::FETCH_IMG_SRC | Csp::FETCH_CONNECT_SRC | Csp::FETCH_SCRIPT_SRC, [
				'https://www.googletagmanager.com',
				'https://www.google-analytics.com',
				'https://ssl.google-analytics.com',
				'https://ajax.googleapis.com'
			])
			->AllowHosts(Csp::FETCH_IMG_SRC | Csp::FETCH_CONNECT_SRC, [
				'https://stats.g.doubleclick.net',
			])
			->AllowHosts(Csp::FETCH_FRAME_SRC, [
				'https://*.fls.doubleclick.net'
			])
			->AllowHosts(Csp::FETCH_IMG_SRC, [
				'https://www.google.com',
			]);
	}
}
