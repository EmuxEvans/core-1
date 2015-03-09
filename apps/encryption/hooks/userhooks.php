<?php
/**
 * @author Clark Tomlinson  <clark@owncloud.com>
 * @since 2/19/15, 10:02 AM
 * @copyright Copyright (c) 2015, ownCloud, Inc.
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\Encryption\Hooks;


use OCA\Encryption\Hooks\Contracts\IHook;
use OCA\Encryption\KeyManager;
use OCA\Encryption\RequirementsChecker;
use OCP\App;
use OCP\ILogger;
use OCP\Template;
use OCP\Util;

class UserHooks implements IHook {
	/**
	 * @var KeyManager
	 */
	private $keyManager;
	/**
	 * @var RequirementsChecker
	 */
	private $requirementsChecker;
	/**
	 * @var ILogger
	 */
	private $logger;

	/**
	 * UserHooks constructor.
	 *
	 * @param KeyManager $keyManager
	 * @param RequirementsChecker $requirementsChecker
	 * @param ILogger $logger
	 */
	public function __construct(KeyManager $keyManager, RequirementsChecker $requirementsChecker, ILogger $logger) {

		$this->keyManager = $keyManager;
		$this->requirementsChecker = $requirementsChecker;
		$this->logger = $logger;
	}

	/**
	 * Connects Hooks
	 *
	 * @return null
	 */
	public function addHooks() {
		Util::connectHook('OC_User', 'post_login', 'OCA\Encryption\Hooks', 'login');
		Util::connectHook('OC_User', 'logout', 'OCA\Encryption\Hooks', 'logout');
		Util::connectHook('OC_User', 'post_setPassword', 'OCA\Encryption\Hooks', 'setPassphrase');
		Util::connectHook('OC_User', 'pre_setPassword', 'OCA\Encryption\Hooks', 'preSetPassphrase');
		Util::connectHook('OC_User', 'post_createUser', 'OCA\Encryption\Hooks', 'postCreateUser');
		Util::connectHook('OC_User', 'post_deleteUser', 'OCA\Encryption\Hooks', 'postDeleteUser');
	}


	/**
	 * Startup encryption backend upon user login
	 *
	 * @note This method should never be called for users using client side encryption
	 */
	public function login($params) {

		if (!App::isEnabled('encryption')) {
			return true;
		}


		$l = new \OC_L10N('encryption');

		$view = new \OC\Files\View('/');

		// ensure filesystem is loaded
		if (!\OC\Files\Filesystem::$loaded) {
			\OC_Util::setupFS($params['uid']);
		}
		$privateKey = $this->keyManager->getPrivateKey($params['uid']);

		// if no private key exists, check server configuration
		if (!$privateKey) {
			//check if all requirements are met
			if (!$this->requirementsChecker->checkExtensions() || !$this->requirementsChecker->checkConfiguration()) {
				$error_msg = $l->t("Missing requirements.");
				$hint = $l->t('Please make sure that OpenSSL together with the PHP extension is enabled and configured properly. For now, the encryption app has been disabled.');
				\OC_App::disable('encryption');
				$this->logger->error('Encryption Library' . $error_msg . ' ' . $hint);
				Template::printErrorPage($error_msg, $hint);
			}
		}

		$util = new Util($view, $params['uid']);

		// setup user, if user not ready force relogin
		if (Helper::setupUser($util, $params['password']) === false) {
			return false;
		}

		$session = $util->initEncryption($params);

		// Check if first-run file migration has already been performed
		$ready = false;
		$migrationStatus = $util->getMigrationStatus();
		if ($migrationStatus === Util::MIGRATION_OPEN && $session !== false) {
			$ready = $util->beginMigration();
		} elseif ($migrationStatus === Util::MIGRATION_IN_PROGRESS) {
			// refuse login as long as the initial encryption is running
			sleep(5);
			\OCP\User::logout();
			return false;
		}

		$result = true;

		// If migration not yet done
		if ($ready) {

			// Encrypt existing user files
			try {
				$result = $util->encryptAll('/' . $params['uid'] . '/' . 'files');
			} catch (\Exception $ex) {
				\OCP\Util::writeLog('Encryption library', 'Initial encryption failed! Error: ' . $ex->getMessage(), \OCP\Util::FATAL);
				$result = false;
			}

			if ($result) {
				\OC_Log::write(
					'Encryption library', 'Encryption of existing files belonging to "' . $params['uid'] . '" completed'
					, \OC_Log::INFO
				);
				// Register successful migration in DB
				$util->finishMigration();
			} else {
				\OCP\Util::writeLog('Encryption library', 'Initial encryption failed!', \OCP\Util::FATAL);
				$util->resetMigrationStatus();
				\OCP\User::logout();
			}
		}

		return $result;
	}

	/**
	 * remove keys from session during logout
	 */
	public function logout() {
		$session = new Session(new \OC\Files\View());
		$session->removeKeys();
	}

	/**
	 * setup encryption backend upon user created
	 *
	 * @note This method should never be called for users using client side encryption
	 */
	public function postCreateUser($params) {

		if (App::isEnabled('files_encryption')) {
			$view = new \OC\Files\View('/');
			$util = new Util($view, $params['uid']);
			Helper::setupUser($util, $params['password']);
		}
	}

	/**
	 * cleanup encryption backend upon user deleted
	 *
	 * @note This method should never be called for users using client side encryption
	 */
	public function postDeleteUser($params) {

		if (App::isEnabled('files_encryption')) {
			Keymanager::deletePublicKey(new \OC\Files\View(), $params['uid']);
		}
	}

	/**
	 * If the password can't be changed within ownCloud, than update the key password in advance.
	 */
	public function preSetPassphrase($params) {
		if (App::isEnabled('files_encryption')) {
			if (!\OC_User::canUserChangePassword($params['uid'])) {
				self::setPassphrase($params);
			}
		}
	}

	/**
	 * Change a user's encryption passphrase
	 *
	 * @param array $params keys: uid, password
	 */
	public function setPassphrase($params) {
		if (App::isEnabled('files_encryption') === false) {
			return true;
		}

		// Only attempt to change passphrase if server-side encryption
		// is in use (client-side encryption does not have access to
		// the necessary keys)
		if (Crypt::mode() === 'server') {

			$view = new \OC\Files\View('/');
			$session = new Session($view);

			// Get existing decrypted private key
			$privateKey = $session->getPrivateKey();

			if ($params['uid'] === \OCP\User::getUser() && $privateKey) {

				// Encrypt private key with new user pwd as passphrase
				$encryptedPrivateKey = Crypt::symmetricEncryptFileContent($privateKey, $params['password'], Helper::getCipher());

				// Save private key
				if ($encryptedPrivateKey) {
					Keymanager::setPrivateKey($encryptedPrivateKey, \OCP\User::getUser());
				} else {
					\OCP\Util::writeLog('files_encryption', 'Could not update users encryption password', \OCP\Util::ERROR);
				}

				// NOTE: Session does not need to be updated as the
				// private key has not changed, only the passphrase
				// used to decrypt it has changed


			} else { // admin changed the password for a different user, create new keys and reencrypt file keys

				$user = $params['uid'];
				$util = new Util($view, $user);
				$recoveryPassword = isset($params['recoveryPassword']) ? $params['recoveryPassword'] : null;

				// we generate new keys if...
				// ...we have a recovery password and the user enabled the recovery key
				// ...encryption was activated for the first time (no keys exists)
				// ...the user doesn't have any files
				if (($util->recoveryEnabledForUser() && $recoveryPassword)
					|| !$util->userKeysExists()
					|| !$view->file_exists($user . '/files')
				) {

					// backup old keys
					$util->backupAllKeys('recovery');

					$newUserPassword = $params['password'];

					// make sure that the users home is mounted
					\OC\Files\Filesystem::initMountPoints($user);

					$keypair = Crypt::createKeypair();

					// Disable encryption proxy to prevent recursive calls
					$proxyStatus = \OC_FileProxy::$enabled;
					\OC_FileProxy::$enabled = false;

					// Save public key
					Keymanager::setPublicKey($keypair['publicKey'], $user);

					// Encrypt private key with new password
					$encryptedKey = Crypt::symmetricEncryptFileContent($keypair['privateKey'], $newUserPassword, Helper::getCipher());
					if ($encryptedKey) {
						Keymanager::setPrivateKey($encryptedKey, $user);

						if ($recoveryPassword) { // if recovery key is set we can re-encrypt the key files
							$util = new Util($view, $user);
							$util->recoverUsersFiles($recoveryPassword);
						}
					} else {
						\OCP\Util::writeLog('files_encryption', 'Could not update users encryption password', \OCP\Util::ERROR);
					}

					\OC_FileProxy::$enabled = $proxyStatus;
				}
			}
		}
	}

	/**
	 * after password reset we create a new key pair for the user
	 *
	 * @param array $params
	 */
	public function postPasswordReset($params) {
		$uid = $params['uid'];
		$password = $params['password'];

		$util = new Util(new \OC\Files\View(), $uid);
		$util->replaceUserKeys($password);
	}
}
