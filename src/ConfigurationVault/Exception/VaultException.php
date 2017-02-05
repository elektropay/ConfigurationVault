<?php

/*
 * This file is part of the UCSDMath package.
 *
 * (c) 2015-2017 UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace UCSDMath\Configuration\ConfigurationVault\Exception;

use InvalidArgumentException;

/**
 * VaultException is the interface for file and input/output stream related
 * exceptions thrown by all ConfigurationVault classes.
 *
 * Method list: (+) @api, (-) protected or private visibility.
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 *
 * @api
 */
class VaultException extends InvalidArgumentException
{
}
