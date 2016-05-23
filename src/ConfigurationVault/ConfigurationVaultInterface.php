<?php

/*
 * This file is part of the UCSDMath package.
 *
 * Copyright 2016 UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace UCSDMath\Configuration\ConfigurationVault;

/**
 * ConfigurationVaultInterface is the interface implemented by all ConfigurationVault classes.
 *
 * Method noted as: (+) @api.
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 *
 * @api
 */
interface ConfigurationVaultInterface
{
    /**
     * Constants.
     *
     * @var string CHARSET                   A preferred character encoding set
     * @var string ENCRYPTION_SETTINGS_FILE  A encryption configuration settings file
     * @var string CIPHER                    A preferred AES cipher
     * @var string CIPHER_MODE               A use with Cipher Block Chaining (CBC)
     * @var string KEY_BYTE_SIZE             A input length
     * @var string MAC_BYTE_SIZE             A input length
     * @var string HASH_FUNCTION             A seeding function
     * @var string TEST_DATA                 A text as a constant.
     */
    const CHARSET                  = 'UTF-8';
    const ENCRYPTION_SETTINGS_FILE = 'configuration-settings-encryption.yml';
    const CIPHER                   = MCRYPT_RIJNDAEL_256;
    const CIPHER_MODE              = MCRYPT_MODE_CBC;
    const KEY_BYTE_SIZE            = 32;
    const MAC_BYTE_SIZE            = 32;
    const HASH_FUNCTION            = 'sh1';
    const TEST_DATA                = 'Hi There...';
    const DEFAULT_VAULT_SECTION    = 'webadmin';

    //--------------------------------------------------------------------------

    /**
     * Set ConfigurationVault to encryption mode.
     *
     * @param bool $value  A option to work with encrypted configuration data
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultRecordEncrypted(bool $value = true): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set ConfigurationVault to encryption mode.
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function loadVaultSettingsFile(): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Open configuration file settings.
     *
     * @param string $vaultFilename              A specific configuration to open. (e.g., 'Database')
     * @param string $vaultFileRequestedSection  A specific file section (e.g., 'webadmin')
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function openVaultFile(string $vaultFilename, string $vaultFileRequestedSection = null): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the database record properties.
     *
     * @param string $release      A release collection type (e.g., 'database', 'account', 'smtp')
     * @param string $environment  A operating environment (e.g., 'development', 'staging', 'production')
     * @param string $account      A specific section of data to open (e.g., 'webadmin', 'webuser', 'wwwdyn')
     *
     * @return ConfigurationVaultInterface The current instance
     */
    public function setRecordProperties(string $release, string $environment, string $account): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the account root path.
     *
     * @param string $value  A directory path to the account root (e.g., outside of web root)
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setAccountRoot(string $value): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the database record properties.
     *
     * @param string $value  A vault file name to open (e.g., 'database', 'account', 'encryption')
     *
     * @return ConfigurationVaultInterface The current instance
     */
    public function setVaultFilename(string $value): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the default requested section (e.g., 'webadmin', 'webuser', 'wwwdyn').
     *
     * @param string $requestedSection  A default section name to pull from the vault file
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultFileRequestedSection(string $requestedSection = null): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the location of the vault directory (e.g., '/home/www/.external-configuration-settings/').
     *
     * @param string $value  A default location path to the configuration settings directory
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultSettingsDirectory(string $value): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------
}
