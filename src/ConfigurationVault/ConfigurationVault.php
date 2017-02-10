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
use UCSDMath\Configuration\ConfigurationVault\Exception\VaultException;
use UCSDMath\Configuration\ConfigurationVault\Exception\FileNotFoundException;

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
 * (+) string getRandomHex(int $length = 32);
 * (+) ConfigurationVaultInterface setEncryptionKey(string $encoded = null);
 * (+) ConfigurationVaultInterface setVaultDefaultEnvironment(string $value);
 * (+) ConfigurationVaultInterface setInitializationVector(string $encoded = null);
 * (+) ConfigurationVaultInterface setOpenSslOption(int $option = \OPENSSL_RAW_DATA);
 * (+) ConfigurationVaultInterface setCipherMethod(string $method = self::DEFAULT_CIPHER_METHOD);
 * (+) ConfigurationVaultInterface validateEncryptionSettingsFileName($vaultFilePath = null, $vaultFile = null);
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
    public const VERSION = '1.14.0';

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
     * Reset to default settings.
     *
     *
     *    - vaultId: reset the configuration settings id for the record in process
     *    - vaultUuid: reset the configuration settings uuid for the record in process
     *    - vaultDate: reset the configuration settings date for the record in process
     *    - vaultFile: reset the configuration-settings file to open. (e.g., 'Database', 'Account', 'SMTP', etc.)
     *    - resultDataSet: reset the raw data from the specific vault file requested
     *    - storageRegister: restart storage register
     *    - vaultSection: reset the specific section of the vault/settings file to be processed (e.g., 'webadmin', 'webuser', 'wwwdyn', etc.)
     *    - vaultIsEncrypted: reset the configuration settings is_encrypted for the record in process
     *    - vaultEnvironments: reset the list of provided categories found in the configuration setting file
     *    - vaultReleaseType: reset the release collection type (e.g., 'database', 'account', 'smtp')
     *    - vaultEnvironment: reset the current environment defined and used for a vault file (e.g.,'development','staging','production')
     *    - vaultDefaultSection: reset the default section found in the configuration setting file
     *    - vaultRequestedSection: reset the requested section of the vault file (e.g., 'webadmin', 'webuser', 'wwwdyn', etc.)
     *    - loadHashids(): set to default Hashids Project Key
     *    - setCipherMethod(): set to default cipher method: AES-256-CTR
     *    - setIvByteSize(): set to default IV byte size for AES-256-CTR
     *    - setByteSizeMap('ivByteSize'): a map to ensure correct size for $ivByteSize
     *    - setKeyByteSize(): set to default encryption key byte size for AES-256-CTR
     *    - setByteSizeMap('keyByteSize'):a map to ensure correct size for $keyByteSize
     *    - setOpenSslOption(): set the bitwise disjunction \OPENSSL_RAW_DATA
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function reset(): ConfigurationVaultInterface
    {
        return $this->setProperty('vaultId', null)->setProperty('vaultUuid', null)
            ->setProperty('vaultDate', null)->setProperty('vaultFile', null)
            ->setProperty('resultDataSet', [])->setProperty('storageRegister', [])
            ->setProperty('vaultSection', null)->setProperty('vaultIsEncrypted', null)
            ->setProperty('vaultEnvironments', [])->setProperty('vaultReleaseType', null)
            ->setProperty('vaultEnvironment', null)->setProperty('vaultDefaultSection', null)
            ->setProperty('vaultRequestedSection', null)->loadHashids()->setCipherMethod()->setIvByteSize()
            ->setByteSizeMap('ivByteSize')->setKeyByteSize()->setByteSizeMap('keyByteSize')->setOpenSslOption();
    }

    //--------------------------------------------------------------------------

    /**
     * Get a random hex string (CSPRNG Requires PHP v7.x).
     *
     * @param int $length The length of the token
     *
     * @return string The random token string
     *
     * @api
     */
    public function getRandomHex(int $length = 32): string
    {
        if (!is_callable('random_bytes')) {
            throw new VaultException('There is no suitable CSPRNG installed on your system');
        }

        return bin2hex(random_bytes($length/2));
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
        [$dataSize,, $keySalt] = empty($this->hashidsDecode($encoded)) ? null : $this->hashidsDecode($encoded);
        [$hash, $hours, $minutes, $seconds, $uuid] = [
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
        [$dataSize, $ivSalt, $keySalt] = empty($this->hashidsDecode($encoded)) ? null : $this->hashidsDecode($encoded);
        [$hash, $hours, $minutes, $seconds, $uuid] = [
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
     * Set the option integer flag.
     *
     * @param int $option The bitwise disjunction used in OpenSSL (Default: 0, \OPENSSL_RAW_DATA: 1, \OPENSSL_ZERO_PADDING: 2)
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setOpenSslOption(int $option = \OPENSSL_RAW_DATA): ConfigurationVaultInterface
    {
        return $this->set(self::VAULTED, $option, 'option');
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
}
