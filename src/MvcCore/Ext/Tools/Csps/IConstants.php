<?php

namespace MvcCore\Ext\Tools\Csps;

interface IConstants {

	//region FETCH_DIRECTIVES

	/**
	 * Defines the valid sources for web workers and nested
	 * browsing contexts loaded using elements such as <frame> and <iframe>.
	 * Instead of child-src, if you want to regulate nested browsing
	 * contexts and workers, you should use the frame-src and
	 * worker-src directives, respectively.
	 */
	const FETCH_CHILD_SRC					= 1;

	/**
	 * Restricts the URLs which can be loaded using script interfaces
	 */
	const FETCH_CONNECT_SRC					= 2;

	/**
	 * Serves as a fallback for the other fetch directives.
	 */
	const FETCH_DEFAULT_SRC					= 4;

	/**
	 * Specifies valid sources for fonts loaded using @font-face.
	 */
	const FETCH_FONT_SRC					= 8;

	/**
	 * Specifies valid sources for nested browsing contexts
	 * loading using elements such as <frame> and <iframe>.
	 */
	const FETCH_FRAME_SRC					= 16;

	/**
	 * Specifies valid sources of images and favicons.
	 */
	const FETCH_IMG_SRC						= 32;

	/**
	 * Specifies valid sources of application manifest files.
	 */
	const FETCH_MANIFEST_SRC				= 64;

	/**
	 * Specifies valid sources for loading media using
	 * the <audio> , <video> and <track> elements.
	 */
	const FETCH_MEDIA_SRC					= 128;

	/**
	 * Specifies valid sources for the <object>, <embed>,
	 * and <applet> elements. Elements controlled by object-src
	 * are perhaps coincidentally considered legacy HTML elements
	 * and are not receiving new standardized features (such as
	 * the security attributes sandbox or allow for <iframe>).
	 * Therefore it is recommended to restrict this fetch-directive
	 * (e.g., explicitly set object-src `'none'` if possible).
	 */
	const FETCH_OBJECT_SRC					= 256;

	/**
	 * Specifies valid sources for JavaScript.
	 */
	const FETCH_SCRIPT_SRC					= 512;

	/**
	 * Specifies valid sources for stylesheets.
	 */
	const FETCH_STYLE_SRC					= 1024;

	//endregion

	//region DOCUMENT_DIRECTIVES

	/**
	 * Restricts the URLs which can be used in
	 * a document's <base> element.
	 */
	const DOCUMENT_BASE_URI					= 2048;

	/**
	 * Restricts the set of plugins that can be embedded into
	 * a document by limiting the types of resources which can be loaded.
	 */
	const DOCUMENT_PLUGIN_TYPES				= 4096;

	/**
	 * Enables a sandbox for the requested resource
	 * similar to the <iframe> sandbox attribute.
	 */
	const DOCUMENT_IFRAME_SANDBOX			= 8192;

	//endregion

	//region NAVIGATION_DIRECTIVES

	/**
	 * Restricts the URLs which can be used as the target of
	 * a form submissions from a given context.
	 */
	const NAVIGATION_FORM_ACTION			= 16384;

	/**
	 * Specifies valid parents that may embed a page
	 * using <frame>, <iframe>, <object>, <embed>, or <applet>.
	 */
	const NAVIGATION_FRAME_ANCESTORS		= 32768;

	/**
	 * Restricts the URLs that the document may navigate to by any means.
	 * For example when a link is clicked, a form is submitted, or
	 * `window.location` is invoked. If form-action is present then
	 * this directive is ignored for form submissions.
	 */
	const NAVIGATION_TO						= 65536;

	//endregion

	//region OTHER_DIRECTIVES

	/**
	 * Restricts the URLs which can be used as the target of
	 * a form submissions from a given context.
	 */
	const OTHER_BLOCK_ALL_MIXED_CONTENT		= 131072;

	/**
	 * Specifies valid parents that may embed a page
	 * using <frame>, <iframe>, <object>, <embed>, or <applet>.
	 */
	const OTHER_UPGRADE_INSECURE_REQUESTS	= 262144;

	//endregion
}
