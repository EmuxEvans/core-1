<?php

/**
 * ownCloud
 *
 * @author Jakob Sack
 * @copyright 2011 Jakob Sack kde@jakobsack.de
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

class OC_Connector_Sabre_File extends OC_Connector_Sabre_Node implements \Sabre\DAV\IFile {

	/**
	 * Updates the data
	 *
	 * The data argument is a readable stream resource.
	 *
	 * After a successful put operation, you may choose to return an ETag. The
	 * etag must always be surrounded by double-quotes. These quotes must
	 * appear in the actual string you're returning.
	 *
	 * Clients may use the ETag from a PUT request to later on make sure that
	 * when they update the file, the contents haven't changed in the mean
	 * time.
	 *
	 * If you don't plan to store the file byte-by-byte, and you return a
	 * different object on a subsequent GET you are strongly recommended to not
	 * return an ETag, and just return null.
	 *
	 * @param resource $data
	 * @throws \Sabre\DAV\Exception\Forbidden
	 * @throws OC_Connector_Sabre_Exception_UnsupportedMediaType
	 * @throws \Sabre\DAV\Exception\BadRequest
	 * @throws \Sabre\DAV\Exception
	 * @throws OC_Connector_Sabre_Exception_EntityTooLarge
	 * @throws \Sabre\DAV\Exception\ServiceUnavailable
	 * @return string|null
	 */
	public function put($data) {
		try {
			if ($this->info && $this->fileView->file_exists($this->path) &&
				!$this->info->isUpdateable()) {
				throw new \Sabre\DAV\Exception\Forbidden();
			}
		} catch (\OCP\Files\StorageNotAvailableException $e) {
			throw new \Sabre\DAV\Exception\ServiceUnavailable($e->getMessage());
		}

		// throw an exception if encryption was disabled but the files are still encrypted
		if (\OC_Util::encryptedFiles()) {
			throw new \Sabre\DAV\Exception\ServiceUnavailable();
		}

		$fileName = basename($this->path);
		if (!\OCP\Util::isValidFileName($fileName)) {
			throw new \Sabre\DAV\Exception\BadRequest();
		}

		// chunked handling
		if (isset($_SERVER['HTTP_OC_CHUNKED'])) {
			return $this->createFileChunked($data);
		}

		// mark file as partial while uploading (ignored by the scanner)
		$partFilePath = $this->path . '.ocTransferId' . rand() . '.part';

		try {
			$putOkay = $this->fileView->file_put_contents($partFilePath, $data);
			if ($putOkay === false) {
				\OC_Log::write('webdav', '\OC\Files\Filesystem::file_put_contents() failed', \OC_Log::ERROR);
				$this->fileView->unlink($partFilePath);
				// because we have no clue about the cause we can only throw back a 500/Internal Server Error
				throw new \Sabre\DAV\Exception('Could not write file contents');
			}
		} catch (\OCP\Files\NotPermittedException $e) {
			// a more general case - due to whatever reason the content could not be written
			throw new \Sabre\DAV\Exception\Forbidden($e->getMessage());

		} catch (\OCP\Files\EntityTooLargeException $e) {
			// the file is too big to be stored
			throw new OC_Connector_Sabre_Exception_EntityTooLarge($e->getMessage());

		} catch (\OCP\Files\InvalidContentException $e) {
			// the file content is not permitted
			throw new OC_Connector_Sabre_Exception_UnsupportedMediaType($e->getMessage());

		} catch (\OCP\Files\InvalidPathException $e) {
			// the path for the file was not valid
			// TODO: find proper http status code for this case
			throw new \Sabre\DAV\Exception\Forbidden($e->getMessage());
		} catch (\OCP\Files\LockNotAcquiredException $e) {
			// the file is currently being written to by another process
			throw new OC_Connector_Sabre_Exception_FileLocked($e->getMessage(), $e->getCode(), $e);
		} catch (\OCA\Encryption\Exception\EncryptionException $e) {
			throw new \Sabre\DAV\Exception\Forbidden($e->getMessage());
		} catch (\OCP\Files\StorageNotAvailableException $e) {
			throw new \Sabre\DAV\Exception\ServiceUnavailable($e->getMessage());
		}

		try {
			// if content length is sent by client:
			// double check if the file was fully received
			// compare expected and actual size
			if (isset($_SERVER['CONTENT_LENGTH']) && $_SERVER['REQUEST_METHOD'] !== 'LOCK') {
				$expected = $_SERVER['CONTENT_LENGTH'];
				$actual = $this->fileView->filesize($partFilePath);
				if ($actual != $expected) {
					$this->fileView->unlink($partFilePath);
					throw new \Sabre\DAV\Exception\BadRequest('expected filesize ' . $expected . ' got ' . $actual);
				}
			}

			// rename to correct path
			try {
				$renameOkay = $this->fileView->rename($partFilePath, $this->path);
				$fileExists = $this->fileView->file_exists($this->path);
				if ($renameOkay === false || $fileExists === false) {
					\OC_Log::write('webdav', '\OC\Files\Filesystem::rename() failed', \OC_Log::ERROR);
					$this->fileView->unlink($partFilePath);
					throw new \Sabre\DAV\Exception('Could not rename part file to final file');
				}
			}
			catch (\OCP\Files\LockNotAcquiredException $e) {
				// the file is currently being written to by another process
				throw new OC_Connector_Sabre_Exception_FileLocked($e->getMessage(), $e->getCode(), $e);
			}

			// allow sync clients to send the mtime along in a header
			$mtime = OC_Request::hasModificationTime();
			if ($mtime !== false) {
				if($this->fileView->touch($this->path, $mtime)) {
					header('X-OC-MTime: accepted');
				}
			}
			$this->refreshInfo();
		} catch (\OCP\Files\StorageNotAvailableException $e) {
			throw new \Sabre\DAV\Exception\ServiceUnavailable($e->getMessage());
		}

		return '"' . $this->info->getEtag() . '"';
	}

	/**
	 * Returns the data
	 *
	 * @return string|resource
	 */
	public function get() {

		//throw exception if encryption is disabled but files are still encrypted
		if (\OC_Util::encryptedFiles()) {
			throw new \Sabre\DAV\Exception\ServiceUnavailable();
		} else {
			try {
				return $this->fileView->fopen(ltrim($this->path, '/'), 'rb');
			} catch (\OCA\Encryption\Exception\EncryptionException $e) {
				throw new \Sabre\DAV\Exception\Forbidden($e->getMessage());
			} catch (\OCP\Files\StorageNotAvailableException $e) {
				throw new \Sabre\DAV\Exception\ServiceUnavailable($e->getMessage());
			}
		}

	}

	/**
	 * Delete the current file
	 *
	 * @return void
	 * @throws \Sabre\DAV\Exception\Forbidden
	 */
	public function delete() {
		if (!$this->info->isDeletable()) {
			throw new \Sabre\DAV\Exception\Forbidden();
		}

		try {
			if (!$this->fileView->unlink($this->path)) {
				// assume it wasn't possible to delete due to permissions
				throw new \Sabre\DAV\Exception\Forbidden();
			}
		} catch (\OCP\Files\StorageNotAvailableException $e) {
			throw new \Sabre\DAV\Exception\ServiceUnavailable($e->getMessage());
		}

		// remove properties
		$this->removeProperties();

	}

	/**
	 * Returns the size of the node, in bytes
	 *
	 * @return int|float
	 */
	public function getSize() {
		return $this->info->getSize();
	}

	/**
	 * Returns the mime-type for a file
	 *
	 * If null is returned, we'll assume application/octet-stream
	 *
	 * @return mixed
	 */
	public function getContentType() {
		$mimeType = $this->info->getMimetype();

		// PROPFIND needs to return the correct mime type, for consistency with the web UI
		if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'PROPFIND' ) {
			return $mimeType;
		}
		return \OC_Helper::getSecureMimeType($mimeType);
	}

	/**
	 * @param resource $data
	 * @return null|string
	 */
	private function createFileChunked($data)
	{
		list($path, $name) = \Sabre\DAV\URLUtil::splitPath($this->path);

		$info = OC_FileChunking::decodeName($name);
		if (empty($info)) {
			throw new \Sabre\DAV\Exception\NotImplemented();
		}

		// we first assembly the target file as a part file
		$targetPath = $path . '/' . $info['name'];
		if (isset($_SERVER['CONTENT_LENGTH'])) {
			$expected = $_SERVER['CONTENT_LENGTH'];
		} else {
			$expected = -1;
		}
		$partFilePath = $path . '/' . $info['name'] . '.ocTransferId' . $info['transferid'] . '.part';
		/** @var \OC\Files\Storage\Storage $storage */
		list($storage,) = $this->fileView->resolvePath($partFilePath);
		$storeData = $storage->getChunkHandler()->storeChunk($partFilePath, $info['index'], $info['chunkcount'], $expected, $data, $info['transferid']);
		$bytesWritten = $storeData['bytesWritten'];

		//detect aborted upload
		if (isset ($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'PUT' ) {
			if (isset($_SERVER['CONTENT_LENGTH'])) {
				if ($bytesWritten != $expected) {
					throw new \Sabre\DAV\Exception\BadRequest(
						'expected filesize ' . $expected . ' got ' . $bytesWritten);
				}
			}
		}

		if ($storeData['complete']) {

			try {

				// here is the final atomic rename
				// trigger hooks for post processing
				$targetFileExists = $storage->file_exists('/files' . $targetPath);
				$run = $this->runPreHooks($targetFileExists, '/files' . $targetPath);
				if (!$run) {
					\OC::$server->getLogger()->error('Hook execution on {file} failed', array('app' => 'webdav', 'file' => $targetPath));
					// delete part file
					$storage->unlink('/files' . $partFilePath);
					throw new \Sabre\DAV\Exception('Upload rejected');
				}
				$renameOkay = $storage->rename('/files' . $partFilePath, '/files' . $targetPath);
				$fileExists = $storage->file_exists('/files' . $targetPath);
				if ($renameOkay === false || $fileExists === false) {
					\OC::$server->getLogger()->error('\OC\Files\Filesystem::rename() failed', array('app'=>'webdav'));
					// only delete if an error occurred and the target file was already created
					if ($fileExists) {
						$storage->unlink('/files' . $targetPath);
					}
					$partFileExists = $storage->file_exists('/files' . $partFilePath);
					if ($partFileExists) {
						$storage->unlink('/files' . $partFilePath);
					}
					throw new \Sabre\DAV\Exception('Could not rename part file assembled from chunks');
				}

				// trigger hooks for post processing
				$this->runPostHooks($targetFileExists, '/files' . $targetPath);

				// allow sync clients to send the mtime along in a header
				$mtime = OC_Request::hasModificationTime();
				if ($mtime !== false) {
					// TODO: will this update the cache properly - e.g. smb where we cannot change the mtime ???
					if($storage->touch('/files' . $targetPath, $mtime)) {
						header('X-OC-MTime: accepted');
					}
				}

				$info = $this->fileView->getFileInfo($targetPath);
				return $info->getEtag();
			} catch (\OCP\Files\StorageNotAvailableException $e) {
				throw new \Sabre\DAV\Exception\ServiceUnavailable($e->getMessage());
			}
		}

		return null;
	}

	private function runPreHooks($fileExists, $path) {
		$run = true;
		if(!$fileExists) {
			OC_Hook::emit(
				\OC\Files\Filesystem::CLASSNAME,
				\OC\Files\Filesystem::signal_create,
				array(
					\OC\Files\Filesystem::signal_param_path => $path,
					\OC\Files\Filesystem::signal_param_run => &$run
				)
			);
		}
		OC_Hook::emit(
			\OC\Files\Filesystem::CLASSNAME,
			\OC\Files\Filesystem::signal_write,
			array(
				\OC\Files\Filesystem::signal_param_path => $path,
				\OC\Files\Filesystem::signal_param_run => &$run
			)
		);

		return $run;
	}

	private function runPostHooks($fileExists, $path) {
		if(!$fileExists) {
			OC_Hook::emit(
				\OC\Files\Filesystem::CLASSNAME,
				\OC\Files\Filesystem::signal_post_create,
				array( \OC\Files\Filesystem::signal_param_path => $path)
			);
		}
		OC_Hook::emit(
			\OC\Files\Filesystem::CLASSNAME,
			\OC\Files\Filesystem::signal_post_write,
			array( \OC\Files\Filesystem::signal_param_path => $path)
		);
	}
}
