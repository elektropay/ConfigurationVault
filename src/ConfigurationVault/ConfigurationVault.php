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
    const VERSION = '1.12.0';

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
        return $this->all();
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
     * Set the vault filename to open.
     *
     * @param string $vaultFileDesignator The specific configuration to open. (e.g., 'Database', 'SMTP', 'Account', 'Administrator', 'Encryption')
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @throws VaultException When an invalid filename is created
     */
    public function setVaultFile(string $vaultFileDesignator): ConfigurationVaultInterface
    {
        $filename = false !== strpos($vaultFileDesignator, 'configuration-settings')
            ? sprintf('%s/%s.yml', $this->getProperty('vaultSettingsDirectory'), strtolower(trim($vaultFileDesignator, '/ ')))
            : sprintf('%s/%s%s.yml', $this->getProperty('vaultSettingsDirectory'), 'configuration-settings-', strtolower(trim($vaultFileDesignator, '/ ')));

        if (!realpath($filename)) {
            throw new VaultException(sprintf('The parameters provided (file name: %s) does not exist or is not a valid file path. Please provide a real filename. Method: %s.', $filename, __METHOD__));
        }

        return $this->setProperty('vaultFile', $filename);
    }

    //--------------------------------------------------------------------------

    /**
     * Set the Initialization Vector (IV).
     *
     * @param string $encoded The ciphered text
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @throws VaultException When an invalid method is provided
     *
     * @api
     */
    public function setEncryptionKey(string $encoded = null): ConfigurationVaultInterface
    {
        if ($encoded !== null && empty($this->hashidsDecode($encoded))) {
            throw new VaultException(sprintf('Invalid Hashids string was found "%s". This cannot be decoded into an array.', $encoded));
        }
        list($dataSize,, $keySalt) = empty($this->hashidsDecode($encoded)) ? null : $this->hashidsDecode($encoded);
        list($hash, $hours, $minutes, $seconds, $uuid) = [
            $this->getProperty('primaryHashArray', 'hash'),
            $this->getProperty('primaryHashArray', 'hours'),
            $this->getProperty('primaryHashArray', 'minutes'),
            $this->getProperty('primaryHashArray', 'seconds'),
            $this->getProperty('primaryHashArray', 'uuid')
        ];
        $unsizedKey = sha1(join([mb_substr($hash, $hours, $minutes, self::CHARSET), mb_substr($hash, (-1 * $seconds), null, self::CHARSET), $uuid, $keySalt]));

        return $this->set(self::VAULTED, base64_decode($this->resizeKeyToMap($unsizedKey, $this->keyByteSizeMap)), 'key')->set(self::VAULTED, $keySalt, 'keySalt')->set(self::VAULTED, $dataSize, 'dataSize');
    }

    //--------------------------------------------------------------------------

    /**
     * Set the Initialization Vector (IV).
     *
     * @param string $encoded The ciphered text
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @throws VaultException When an invalid method is provided
     *
     * @api
     */
    public function setInitializationVector(string $encoded = null): ConfigurationVaultInterface
    {
        if ($encoded !== null && empty($this->hashidsDecode($encoded))) {
            throw new VaultException(sprintf('Invalid Hashids string was found "%s". This cannot be decoded into an array.', $encoded));
        }
        list($dataSize, $ivSalt, $keySalt) = empty($this->hashidsDecode($encoded)) ? null : $this->hashidsDecode($encoded);
        list($hash, $hours, $minutes, $seconds, $uuid) = [
            $this->getProperty('initializationVectorArray', 'hash'),
            $this->getProperty('initializationVectorArray', 'hours'),
            $this->getProperty('initializationVectorArray', 'minutes'),
            $this->getProperty('initializationVectorArray', 'seconds'),
            $this->getProperty('initializationVectorArray', 'uuid')
        ];
        $unsizedKey = sha1(join([mb_substr($hash, $hours, $minutes, self::CHARSET), mb_substr($hash, (-1 * $seconds), null, self::CHARSET), $uuid, $ivSalt]));

        return $this->set(self::VAULTED, base64_decode($this->resizeKeyToMap($unsizedKey, $this->ivByteSizeMap)), 'iv')
                ->set(self::VAULTED, $dataSize, 'dataSize')->set(self::VAULTED, $ivSalt, 'ivSalt')->set(self::VAULTED, $keySalt, 'keySalt');
    }

    //--------------------------------------------------------------------------

    /**
     * Validate the file path and name.
     *
     * @param string $vaultFilePath The absolute filename or path
     * @param string $vaultFile     The name of the Vault Settings File to use
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @throws FileNotFoundException When the vault file is missing or is not a file
     *
     * @api
     */
    public function validateEncryptionSettingsFileName($vaultFilePath = null, $vaultFile = null): ConfigurationVaultInterface
    {
        if ($vaultFile !== null) {
            if (!$this->exists($vaultFilePath)) {
                throw new FileNotFoundException(sprintf('Failed to read "%s" because this file does not exist at this path location.', $vaultFilePath), 0, null, $vaultFilePath);
            }
            if (!is_file($vaultFilePath)) {
                throw new FileNotFoundException(sprintf('The Vault file "%s" is not a file. Please recheck the file path or filename.', $vaultFilePath), 0, null, $vaultFilePath);
            }
        }

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Set the cipher method used to encrypt/decrypt OpenSSL payloads.
     *
     * @param string $method The cipher method used to encrypt/decrypt the payload (Default: 'AES-256-CTR','AES-256-GCM','AES-256-CCM',etc.)
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @throws VaultException When an invalid method is provided
     *
     * @api
     */
    public function setCipherMethod(string $method = self::DEFAULT_CIPHER_METHOD): ConfigurationVaultInterface
    {
        /* check against a defined whitelist */
        if (!in_array($method, array_values($this->availableOpenSslCipherMethods), true)) {
            throw new VaultException(sprintf('Invalid cipher method was requested "%s". Check available cipher methods for your current OpenSSL version: %s', $method, $this->openSslVersion));
        }

        return $this->setProperty('cipherMethod', $method)->set(self::VAULTED, $method, 'method');
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
