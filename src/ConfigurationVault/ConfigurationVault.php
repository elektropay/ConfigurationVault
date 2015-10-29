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

use UCSDMath\Filesystem\FilesystemInterface;
use UCSDMath\Serialization\Yaml\YamlInterface;

/**
 * ConfigurationVault is the default implementation of {@link ConfigurationVaultInterface} which
 * provides routine configuration-vault methods that are commonly used throughout the framework.
 *
 * Method list:
 *
 * @method ConfigurationVaultInterface reset();
 * @method Array getResultDataSet();
 * @method Boolean isVaultFileReadable();
 * @method Boolean isVaultRecordEncrypted();
 * @method ConfigurationVaultInterface setVaultSettingsDirectory($value);
 * @method ConfigurationVaultInterface setVaultFileRequestedSection($value);
 * @method ConfigurationVaultInterface setVaultRecordEncrypted($value = true);
 * @method ConfigurationVaultInterface setVaultFileDefaultEnvironment($value);
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
    const VERSION = '1.4.0';

    // --------------------------------------------------------------------------

    /**
     * Properties.
     */

    // --------------------------------------------------------------------------

    /**
     * Constructor.
     *
     * @param FilesystemInterface  $filesystem A FilesystemInterface Interface instance
     * @param YamlInterface        $yaml       A YamlInterface Interface instance
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
     * Reset to default settings.
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function reset()
    {
        $this->setProperty('cipherKey', null);
     // $this->setProperty('ACCOUNT_ROOT', realpath(__DIR__.'/../../../../../../../../../../'));
        $this->setProperty('vaultFilename', null);
        $this->setProperty('vaultFileType', null);
        $this->setProperty('vaultRecordId', null);
        $this->setProperty('vaultRecordUUID', null);
        $this->setProperty('vaultRecordDate', null);
        $this->setProperty('resultDataSet', array());
        $this->setProperty('storageRegister', array());
        $this->setProperty('vaultRecordEncrypted', null);
        $this->setProperty('vaultFileDefaultSection', null);
     // $this->setProperty('VAULT_SETTINGS_DIRECTORY', null);
        $this->setProperty('vaultFileEnvironments', array());
        $this->setProperty('vaultFileRequestedSection', null);
        $this->setProperty('vaultFileDefaultEnvironment', null);

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Returns bool status of property $vaultRecordEncrypted.
     *
     * @return bool
     *
     * @api
     */
    protected function isVaultRecordEncrypted()
    {
        return $this->getProperty('vaultRecordEncrypted');
    }

    // --------------------------------------------------------------------------

    /**
     * Pull the entire dataset.
     *
     * @throws \throwInvalidArgumentExceptionError on non array value for $this->resultDataSet
     *
     * @return array
     */
    public function getResultDataSet()
    {
        return $this->getProperty('resultDataSet');
    }

    // --------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function setVaultFileDefaultEnvironment($value)
    {
        $this->setProperty('vaultFileDefaultEnvironment', strtolower(trim($value)));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Does file exist and is readable.
     *
     * @return bool
     */
    protected function isVaultFileReadable()
    {
        return is_readable($this->VAULT_SETTINGS_DIRECTORY.'/'.$this->vaultFilename);
    }

    // --------------------------------------------------------------------------

    /**
     * Set ConfigurationVault to encryption mode
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function setVaultRecordEncrypted($value = true)
    {
        $this->setProperty('vaultRecordEncrypted', (bool) $value);

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function setVaultFileRequestedSection($value)
    {
        $this->setProperty('vaultFileRequestedSection', trim($value));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function setVaultSettingsDirectory($value)
    {
        $this->setProperty('VAULT_SETTINGS_DIRECTORY', rtrim($value, '/'));

        return $this;
    }
}
