<?php

/*
 * This file is part of the UCSDMath package.
 *
 * (c) UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace UCSDMath\Configuration\ConfigurationVault;

/**
 * ConfigurationVaultInterface is the interface implemented by all ConfigurationVault classes.
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
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

    // --------------------------------------------------------------------------

    /**
     * Set ConfigurationVault to encryption mode
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function setVaultRecordEncrypted($value = true);

    // --------------------------------------------------------------------------

    /**
     * Set ConfigurationVault to encryption mode
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function loadVaultSettingsFile();

    // --------------------------------------------------------------------------

    /**
     * Open configuration file settings.
     *
     * @param  string $vaultFilename              A specific configuration to open. (e.g., 'Database')
     * @param  string $vaultFileRequestedSection  A specific file section (e.g., 'webadmin')
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function openVaultFile($vaultFilename, $vaultFileRequestedSection = null);

    // --------------------------------------------------------------------------

    /**
     * Set the database record properties.
     *
     * @param  array $release      A release collection type (e.g., 'database', 'account', 'smtp')
     * @param  array $environment  A operating environment (e.g., 'development', 'staging', 'production')
     * @param  array $account      A specific section of data to open (e.g., 'webadmin', 'webuser', 'wwwdyn')
     *
     * @return ConfigurationVaultInterface
     */
    public function setRecordProperties($release, $environment, $account);

    // --------------------------------------------------------------------------

    /**
     * Pull the entire dataset.
     *
     * @return array
     */
    public function getResultDataSet();

    // --------------------------------------------------------------------------

    /**
     * Set the account root path.
     *
     * @param  string $value  A directory path to the account root (e.g., outside of web root)
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function setAccountRoot($value);

    // --------------------------------------------------------------------------

    /**
     * Set the database record properties.
     *
     * @param  string $value  A vault file name to open (e.g., 'database', 'account', 'encryption')
     *
     * @return ConfigurationVaultInterface
     */
    public function setVaultFilename($value);

    // --------------------------------------------------------------------------

    /**
     * Set the default requested section (e.g., 'webadmin', 'webuser', 'wwwdyn').
     *
     * @param  string $value  A default section name to pull from the vault file
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function setVaultFileRequestedSection($value);

    // --------------------------------------------------------------------------

    /**
     * Set the default environment (e.g., 'development', 'staging', 'production').
     *
     * @param  string $value  A default environment type
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function setVaultFileDefaultEnvironment($value);

    // --------------------------------------------------------------------------

    /**
     * Set the location of the vault directory (e.g., '/home/www/.external-configuration-settings/').
     *
     * @param  string $value  A default location path to the configuration settings directory
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function setVaultSettingsDirectory($value);
}
