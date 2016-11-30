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

namespace UCSDMath\Configuration\ConfigurationVault;

/**
 * ConfigurationVaultInterface is the interface implemented by all ConfigurationVault classes.
 *
 * Method list: (+) @api.
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
     * @var string CHARSET                  The preferred character encoding set
     * @var string ENCRYPTION_SETTINGS_FILE The encryption configuration settings file
     * @var string KEY_BYTE_SIZE            The input length
     * @var string MAC_BYTE_SIZE            The input length
     * @var string HASH_FUNCTION            The seeding function
     * @var string TEST_DATA                The text as a constant.
     */
    const CHARSET                  = 'UTF-8';
    const ENCRYPTION_SETTINGS_FILE = 'configuration-settings-encryption.yml';
    const KEY_BYTE_SIZE            = 32;
    const MAC_BYTE_SIZE            = 32;
    const HASH_FUNCTION            = 'sh1';
    const TEST_DATA                = 'Hi There...';
    const DEFAULT_VAULT_SECTION    = 'webadmin';

    //--------------------------------------------------------------------------

    /**
     * Set ConfigurationVault to encryption mode.
     *
     * @param bool $value The option to work with encrypted configuration data
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
     * @param string $vaultFilename             The specific configuration to open. (e.g., 'Database')
     * @param string $vaultFileRequestedSection The specific file section (e.g., 'webadmin')
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
     * @param string $release     The release collection type (e.g., 'database', 'account', 'smtp')
     * @param string $environment The operating environment (e.g., 'development', 'staging', 'production')
     * @param string $account     The specific section of data to open (e.g., 'webadmin', 'webuser', 'wwwdyn')
     *
     * @return ConfigurationVaultInterface The current instance
     */
    public function setRecordProperties(string $release, string $environment, string $account): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the account root path.
     *
     * @param string $value The directory path to the account root (e.g., outside of web root)
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
     * @param string $value The vault file name to open (e.g., 'database', 'account', 'encryption')
     *
     * @return ConfigurationVaultInterface The current instance
     */
    public function setVaultFilename(string $value): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the default requested section (e.g., 'webadmin', 'webuser', 'wwwdyn').
     *
     * @param string $requestedSection The default section name to pull from the vault file
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
     * @param string $value The default location path to the configuration settings directory
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultSettingsDirectory(string $value): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------
}
