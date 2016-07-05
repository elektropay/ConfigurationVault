<?php

/*
 * This file is part of the UCSDMath package.
 *
 * (c) 2015-2016 UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace UCSDMath\Configuration\ConfigurationVault;

use UCSDMath\Filesystem\FilesystemInterface;
use UCSDMath\Serialization\Yaml\YamlInterface;

/**
 * ConfigurationVault is the default implementation of {@link ConfigurationVaultInterface} which
 * provides routine ConfigurationVault methods that are commonly used in the framework.
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
class ConfigurationVault extends AbstractConfigurationVault implements ConfigurationVaultInterface
{
    /**
     * Constants.
     *
     * @var string VERSION The version number
     *
     * @api
     */
    const VERSION = '1.8.0';

    //--------------------------------------------------------------------------

    /**
     * Properties.
     */

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
    }

    //--------------------------------------------------------------------------

    /**
     * Destructor.
     *
     * @api
     */
    public function __destruct()
    {
        parent::__destruct();
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
        return is_readable($this->vaultSettingsDirectory . '/' . $this->vaultFilename);
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
    public function setVaultFileDefaultEnvironment(string $value): ConfigurationVaultInterface
    {
        $this->setProperty('vaultFileDefaultEnvironment', strtolower(trim($value)));

        return $this;
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
        $this->setProperty('cipherKey', null);
        $this->setProperty('vaultFilename', null);
        $this->setProperty('vaultFileType', null);
        $this->setProperty('vaultRecordId', null);
        $this->setProperty('vaultRecordUUID', null);
        $this->setProperty('vaultRecordDate', null);
        $this->setProperty('resultDataSet', []);
        $this->setProperty('storageRegister', []);
        $this->setProperty('vaultRecordEncrypted', null);
        $this->setProperty('vaultFileDefaultSection', null);
        $this->setProperty('vaultFileEnvironments', []);
        $this->setProperty('vaultFileRequestedSection', null);
        $this->setProperty('vaultFileDefaultEnvironment', null);
        $this->setProperty('theAccountRootPath', realpath(__DIR__ . '/../../../../../../../../../../'));

        return $this;
    }

    //--------------------------------------------------------------------------
}
