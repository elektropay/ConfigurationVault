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

use UCSDMath\Filesystem\FilesystemInterface;
use UCSDMath\Serialization\Yaml\YamlInterface;

/**
 * WordPressVaultLocker is the default implementation of {@link ConfigurationVaultInterface} which
 * provides routine VaultLocker methods that are commonly used in WordPress.
 *
 * {@link AbstractConfigurationVault} is basically a base class for various Configuration Vault
 * routines which this class extends.
 *
 * Method list: (+) @api, (-) protected or private visibility.
 *
 * (+) ConfigurationVaultInterface __construct(FilesystemInterface $filesystem, YamlInterface $yaml);
 * (+) void __destruct();
 * (+) array getRecords();
 * (+) bool isVaultFileReadable();
 * (+) ConfigurationVaultInterface reset();
 * (+) ConfigurationVaultInterface setVaultFileDefaultEnvironment(string $value);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
class WordPressVaultLocker extends AbstractConfigurationVault implements ConfigurationVaultInterface
{
    /**
     * Constants.
     *
     * @var string VERSION The version number
     *
     * @api
     */
    const VERSION = '1.13.0';

    //--------------------------------------------------------------------------

    /**
     * Properties.
     *
     * @var string $wordpressConnectionSettings The name of the database settings
     */
    protected $wordpressConnectionSettings = 'MyWordPressSettings';

    //--------------------------------------------------------------------------

    /**
     * Constructor.
     *
     * @param FilesystemInterface $filesystem The FilesystemInterface
     * @param YamlInterface       $yaml       The YamlInterface
     *
     * @api
     */
    public function __construct(FilesystemInterface $filesystem, YamlInterface $yaml)
    {
        parent::__construct($filesystem, $yaml);

        $this->renderWordPressGlobalSettings();
    }

    //--------------------------------------------------------------------------

    /**
     * Does file exist and is readable.
     *
     * @return ConfigurationVaultInterface The current instance
     */
    public function renderWordPressGlobalSettings(): ConfigurationVaultInterface
    {
        /** Required by WordPress */
        $this->openVaultFile($this->wordpressConnectionSettings);

        define('DB_NAME', $this->get('database_name'));
        define('DB_USER', $this->get('database_username'));
        define('DB_PASSWORD', $this->get('database_password'));
        define('DB_HOST', $this->get('database_host'));
        define('DB_CHARSET', $this->get('database_charset'));
        define('DB_COLLATE', $this->get('database_collation'));

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Pull the entire dataset.
     *
     * @return array
     */
    public function getRecords(): array
    {
        return $this->getProperty('resultDataSet');
    }

    //--------------------------------------------------------------------------

    /**
     * Does file exist and is readable.
     *
     * @return bool
     */
    public function isVaultFileReadable(): bool
    {
        return is_readable($this->vaultFile);
    }

    //--------------------------------------------------------------------------

    /**
     * Set the default environment (e.g., 'development', 'staging', 'production').
     *
     * @param string $value The default environment type
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultDefaultEnvironment(string $value): ConfigurationVaultInterface
    {
        return $this->setProperty('vaultDefaultEnvironment', strtolower(trim($value)));
    }

    //--------------------------------------------------------------------------

    /**
     * Reset to default settings.
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function reset(): ConfigurationVaultInterface
    {
        return $this
            ->setProperty('vaultId', null)               // reset the configuration settings id for the record in process
            ->setProperty('vaultUuid', null)             // reset the configuration settings uuid for the record in process
            ->setProperty('vaultDate', null)             // reset the configuration settings date for the record in process
            ->setProperty('vaultFile', null)             // reset the configuration-settings file to open. (e.g., 'Database', 'Account', 'SMTP', etc.)
            ->setProperty('resultDataSet', [])           // reset the raw data from the specific vault file requested
            ->setProperty('storageRegister', [])         // restart storage register
            ->setProperty('vaultSection', null)          // reset the specific section of the vault/settings file to be processed (e.g., 'webadmin', 'webuser', 'wwwdyn', etc.)
            ->setProperty('vaultIsEncrypted', null)      // reset the configuration settings is_encrypted for the record in process
            ->setProperty('vaultEnvironments', [])       // reset the list of provided categories found in the configuration setting file
            ->setProperty('vaultReleaseType', null)      // reset the release collection type (e.g., 'database', 'account', 'smtp')
            ->setProperty('vaultEnvironment', null)      // reset the current environment defined and used for a vault file (e.g.,'development','staging','production')
            ->setProperty('vaultDefaultSection', null)   // reset the default section found in the configuration setting file
            ->setProperty('vaultRequestedSection', null) // reset the requested section of the vault file (e.g., 'webadmin', 'webuser', 'wwwdyn', etc.)
            ->loadHashids()                              // set to default Hashids Project Key
            ->setCipherMethod()                          // set to default cipher method: AES-256-CTR
            ->setIvByteSize()                            // set to default IV byte size for AES-256-CTR
            ->setByteSizeMap('ivByteSize')               // a map to ensure correct size for $ivByteSize
            ->setKeyByteSize()                           // set to default encryption key byte size for AES-256-CTR
            ->setByteSizeMap('keyByteSize')              // a map to ensure correct size for $keyByteSize
            ->setOpenSslOption();                        // set the bitwise disjunction \OPENSSL_RAW_DATA
    }

    //--------------------------------------------------------------------------
}
