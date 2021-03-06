<?php
/**
 * Copyright (c) 2014 Robin Appelman <icewind@owncloud.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace OCP\Diagnostics;

interface IEvent {
	/**
	 * @return string
	 */
	public function getId();

	/**
	 * @return string
	 */
	public function getDescription();

	/**
	 * @return float
	 */
	public function getStart();

	/**
	 * @return float
	 */
	public function getEnd();

	/**
	 * @return float
	 */
	public function getDuration();
}
