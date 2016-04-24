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

use UCSDMath\Filesystem\FilesystemInterface;
use UCSDMath\Serialization\Yaml\YamlInterface;

/**
 * ConfigurationVault is the default implementation of {@link ConfigurationVaultInterface} which
 * provides routine configuration-vault methods that are commonly used throughout the framework.
 *
 * Method list: (+) @api, (-) protected or private visibility.
 *
 * (+) ConfigurationVaultInterface __construct(FilesystemInterface $filesystem, YamlInterface $yaml);
 * (+) array getResultDataSet();
 * (+) bool isVaultFileReadable();
 * (+) ConfigurationVaultInterface reset();
 * (+) ConfigurationVaultInterface setVaultFileDefaultEnvironment($value);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 *
 * @api
 */
class ConfigurationVault extends AbstractConfigurationVault implements ConfigurationVaultInterface
{
    /**
     * Constants.
     *
     * @var string VERSION  A version number
     *
     * @api
     */
    const VERSION = '1.7.0';

    // --------------------------------------------------------------------------

    /**
     * Properties.
     */

    // --------------------------------------------------------------------------

    /**
     * Constructor.
     *
     * @param FilesystemInterface  $filesystem A FilesystemInterface
     * @param YamlInterface        $yaml       A YamlInterface
     *
     * @api
     */
    public function __construct(
        FilesystemInterface $filesystem,
        YamlInterface $yaml
    ) {
        parent::__construct($filesystem, $yaml);
    }

    // --------------------------------------------------------------------------

    /**
     * Pull the entire dataset.
     *
     * @return array
     */
    public function getResultDataSet(): array
    {
        return $this->getProperty('resultDataSet');
    }

    // --------------------------------------------------------------------------

    /**
     * Does file exist and is readable.
     *
     * @return bool
     */
    public function isVaultFileReadable(): bool
    {
        return is_readable($this->vaultSettingsDirectory . '/' . $this->vaultFilename);
    }

    // --------------------------------------------------------------------------

    /**
     * Set the default environment (e.g., 'development', 'staging', 'production').
     *
     * @param string $value  A default environment type
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function setVaultFileDefaultEnvironment(string $value): ConfigurationVaultInterface
    {
        $this->setProperty('vaultFileDefaultEnvironment', strtolower(trim($value)));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Reset to default settings.
     *
     * @return ConfigurationVaultInterface
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
        $this->setProperty('resultDataSet', array());
        $this->setProperty('storageRegister', array());
        $this->setProperty('vaultRecordEncrypted', null);
        $this->setProperty('vaultFileDefaultSection', null);
        $this->setProperty('vaultFileEnvironments', array());
        $this->setProperty('vaultFileRequestedSection', null);
        $this->setProperty('vaultFileDefaultEnvironment', null);
        $this->setProperty('theAccountRootPath', realpath(__DIR__ . '/../../../../../../../../../../'));

        return $this;
    }

    // --------------------------------------------------------------------------
}
