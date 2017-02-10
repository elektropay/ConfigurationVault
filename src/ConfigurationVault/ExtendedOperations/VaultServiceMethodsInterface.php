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

namespace UCSDMath\Configuration\ConfigurationVault\ExtendedOperations;

/**
 * VaultServiceMethodsInterface is the interface implemented by all Vault classes.
 *
 * Method list: (+) @api.
 *
 * (+) string hashidsEncode($numerical = null);
 * (+) ConfigurationVaultInterface unsetRegister(string $key, string $subkey = null);
 * (+) ConfigurationVaultInterface setAccountHomeDirectory(string $directoryPath = null;
 * (+) ConfigurationVaultInterface setVaultRequestedSection(string $vaultRequestedSection = null);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 *
 * @api
 */
interface VaultServiceMethodsInterface
{
    /**
     * Constants.
     */

    //--------------------------------------------------------------------------
}
