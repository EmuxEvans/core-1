<?php
/**
 * @author Clark Tomlinson  <clark@owncloud.com>
 * @since 2/19/15, 9:52 AM
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

use OC\Files\View;
use OCA\Encryption\AppInfo\Encryption;
use OCA\Encryption\Crypto\Crypt;
use OCA\Encryption\HookManager;
use OCA\Encryption\Hooks\AppHooks;
use OCA\Encryption\Hooks\FileSystemHooks;
use OCA\Encryption\Hooks\ShareHooks;
use OCA\Encryption\Hooks\UserHooks;
use OCA\Encryption\KeyManager;
use OCA\Encryption\Recovery;
use OCP\App;

script('encryption', 'encryption');
script('encryption', 'detect-migration');


$ioc = \OC::$server;
$config = $ioc->getConfig();
// Lets register this encryption module
$encryptionModule = $ioc->getEncryptionManager()->registerEncryptionModule(new Encryption());

$ioc->registerService('Crypt', function (OC\Server $c) {
	return new Crypt($c->getLogger(), $c->getUserSession()->getUser(), $c->getConfig());
});

$ioc->registerService('KeyManager', function (OC\Server $c) {
	return new KeyManager($c->getEncryptionKeyStorage(), $c->query('Crypt'), $c->getConfig(), $c->getUserSession());
});


$ioc->registerService('Recovery', function (OC\Server $c) {
	return new Recovery(
		$c->getUserSession()->getUser(),
		$c->query('Crypt'),
		$c->getSecureRandom(),
		$c->query('KeyManager'),
		$c->getConfig(),
		$c->getEncryptionKeyStorage());
});

if ($config->getSystemValue('maintenance', false)) {

	// Register our hooks and fire them.
	$hookManager = new HookManager();

	$hookManager->registerHook([
		new UserHooks(),
		new ShareHooks(),
		new FileSystemHooks(),
		new AppHooks()
	]);

	$hookManager->fireHooks();

} else {
	// Logout user if we are in maintenance to force re-login
	$ioc->getUserSession()->logout();
}

// Register settings scripts
App::registerAdmin('encryption', 'settings/settings-admin');
App::registerPersonal('encryption', 'settings/settings-personal');
