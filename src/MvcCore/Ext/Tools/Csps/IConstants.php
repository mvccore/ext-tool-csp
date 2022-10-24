<?php

namespace MvcCore\Ext\Tools\Csp;

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
	 * The `script-src` directive specifies valid sources for 
	 * JavaScript. This includes not only URLs loaded directly 
	 * into `<script>` elements, but also things like inline script 
	 * event handlers (`onclick`) and XSLT stylesheets which can 
	 * trigger script execution.
	 */
	const FETCH_SCRIPT_SRC					= 512;

	/**
	 * The `script-src-attr` directive specifies valid sources 
	 * for JavaScript inline event handlers. This includes 
	 * only inline script event handlers like `onclick`, but not 
	 * URLs loaded directly into `<script>` elements.
	 */
	const FETCH_SCRIPT_SRC_ATTR				= 1024;

	/**
	 * The `script-src-elem` directive specifies valid sources 
	 * for JavaScript `<script>` elements, but not inline script 
	 * event handlers like `onclick`.
	 */
	const FETCH_SCRIPT_SRC_ELEM				= 2048;

	/**
	 * The `style-src` directive specifies valid 
	 * sources for stylesheets.
	 */
	const FETCH_STYLE_SRC					= 4096;

	/**
	 * The `style-src-attr` directive specifies valid sources 
	 * for inline styles applied to individual DOM elements.
	 */
	const FETCH_STYLE_SRC_ATTR				= 8192;

	/**
	 * The `style-src-elem` directive specifies valid sources 
	 * for stylesheets `<style>` elements and `<link>` elements 
	 * with `rel="stylesheet"`.
	 */
	const FETCH_STYLE_SRC_ELEM				= 16384;

	//endregion

	//region DOCUMENT_DIRECTIVES

	/**
	 * Restricts the URLs which can be used in
	 * a document's <base> element.
	 */
	const DOCUMENT_BASE_URI					= 32768;

	/**
	 * Restricts the set of plugins that can be embedded into
	 * a document by limiting the types of resources which can be loaded.
	 */
	const DOCUMENT_PLUGIN_TYPES				= 65536;

	/**
	 * Enables a sandbox for the requested resource
	 * similar to the <iframe> sandbox attribute.
	 */
	const DOCUMENT_IFRAME_SANDBOX			= 131072;

	//endregion

	//region NAVIGATION_DIRECTIVES

	/**
	 * Restricts the URLs which can be used as the target of
	 * a form submissions from a given context.
	 */
	const NAVIGATION_FORM_ACTION			= 262144;

	/**
	 * Specifies valid parents that may embed a page
	 * using <frame>, <iframe>, <object>, <embed>, or <applet>.
	 */
	const NAVIGATION_FRAME_ANCESTORS		= 524288;

	/**
	 * Restricts the URLs that the document may navigate to by any means.
	 * For example when a link is clicked, a form is submitted, or
	 * `window.location` is invoked. If form-action is present then
	 * this directive is ignored for form submissions.
	 */
	const NAVIGATION_TO						= 1048576;

	//endregion

	//region OTHER_DIRECTIVES

	/**
	 * Restricts the URLs which can be used as the target of
	 * a form submissions from a given context.
	 */
	const OTHER_BLOCK_ALL_MIXED_CONTENT		= 1048576;

	/**
	 * Specifies valid parents that may embed a page
	 * using <frame>, <iframe>, <object>, <embed>, or <applet>.
	 */
	const OTHER_UPGRADE_INSECURE_REQUESTS	= 4194304;

	//endregion
}
