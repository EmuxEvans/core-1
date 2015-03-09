<?php
/**
 * @author Clark Tomlinson  <fallen013@gmail.com>
 * @since 3/6/15, 10:35 AM
 * @link http:/www.clarkt.com
 * @copyright Clark Tomlinson © 2015
 *
 */

namespace OCA\Encryption;

use OCA\Encryption\Crypto\Crypt;
use OCP\ILogger;

class RequirementsChecker {
	/**
	 * @var Crypt
	 */
	private $crypt;
	/**
	 * @var ILogger
	 */
	private $log;

	/**
	 * RequirementsChecker constructor.
	 *
	 * @param Crypt $crypt
	 * @param ILogger $log
	 */
	public function __construct(Crypt $crypt, ILogger $log) {
		$this->crypt = $crypt;
		$this->log = $log;
	}

	/**
	 * @return bool
	 */
	public function checkExtensions() {
		return extension_loaded('openssl');
	}

	/**
	 * @return bool
	 */
	public function checkConfiguration() {
		if ($this->crypt->getOpenSSLPkey()) {
			return true;
		}
		$this->log->error('Encryption Libary: openssl_pkey_new() Fails:');
		return false;
	}
}
