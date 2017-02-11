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

use UCSDMath\Configuration\ConfigurationVault\Exception\IOException;
use UCSDMath\Configuration\ConfigurationVault\ConfigurationVaultInterface;

/**
 * VaultServiceMethods is the default implementation of {@link VaultServiceMethodsInterface} which
 * provides routine Vault methods that are commonly used in the framework.
 *
 * {@link VaultServiceMethods} is a trait method implimentation requirement used in this framework.
 * This set is specifically used in Vault classes.
 *
 * use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\VaultServiceMethods;
 * use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\VaultServiceMethodsInterface;
 *
 * Method list: (+) @api, (-) protected or private visibility.
 *
 * (+) string hashidsEncode($numerical = null);
 * (+) ConfigurationVaultInterface unsetRegister(string $key, string $subkey = null);
 * (+) ConfigurationVaultInterface setAccountHomeDirectory(string $directoryPath = null;
 * (+) ConfigurationVaultInterface setVaultRequestedSection(string $vaultRequestedSection = null);
 * (-) Traversable toIterator($files);
 * (-) iterable renderAmbit(string $payload);
 * (-) ConfigurationVaultInterface setIvByteSize();
 * (-) ConfigurationVaultInterface setOpenSslVersion();
 * (-) ConfigurationVaultInterface setPrimaryHashArray();
 * (-) ConfigurationVaultInterface setCoreSeedHashArray();
 * (-) ConfigurationVaultInterface setRsaPublicPrivateKeys();
 * (-) ConfigurationVaultInterface setInitializationVectorArray();
 * (-) ConfigurationVaultInterface setVaultEnvironmentTypeSettings();
 * (-) ConfigurationVaultInterface setVaultRecordEncrypted($value = true);
 * (-) ConfigurationVaultInterface setAvailableOpenSslDigests(bool $aliases = false);
 * (-) ConfigurationVaultInterface setAvailableOpenSslCipherMethods(bool $aliases = false);
 * (-) ConfigurationVaultInterface setVaultDataArguments(iterable $arguments, iterable $vaultData);
 * (-) ConfigurationVaultInterface setKeyByteSize(int $size = self::DEFAULT_ENCRYPTION_KEY_BYTE_SIZE);
 *
 * VaultServiceMethods provides a common set of implementations where needed. The VaultServiceMethods
 * trait and the VaultServiceMethodsInterface should be paired together.
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
trait VaultServiceMethods
{
    /**
     * Properties.
     *
     * @var HashidsInterface $hashids The Hashids Interface
     * @var string $openSslVersion The OpenSSL version number installed on the system
     * @var string $cipherMethod The cipher method used by OpenSSL to encrypt/decrypt a payload (e.g.,'AES-256-CTR','AES-256-GCM','AES-256-CCM', etc.)
     * @var array  $encryptionSettingsRawData The raw Encryption Settings data
     */
    protected $hashids                   = null;
    protected $openSslVersion            = null;
    protected $cipherMethod              = null;
    protected $encryptionSettingsRawData = [];

    //--------------------------------------------------------------------------

    /**
     * Abstract Method Requirements.
     */
    abstract public function decrypt(string $payload): string;
    abstract protected function isVaultRecordEncrypted(): bool;
    abstract protected function stringSize(string $payload): int;
    abstract public function getProperty(string $name, string $key = null);
    abstract public function set(string $key, $value, string $subkey = null);
    abstract public function setProperty(string $name, $value, string $key = null);
    abstract public function getRandomInt(int $min = self::MIN_RANDOM_INT, int $max = self::MAX_RANDOM_INT): int;

    //--------------------------------------------------------------------------

    /**
     * Hashids encode.
     *
     * @param int|string|iterable $numerical The numerical integer or array to encoded
     *
     * @return string The encoded hashid
     *
     * @api
     */
    public function hashidsEncode($numerical = null): string
    {
        return $this->hashids->encode($numerical);
    }

    //--------------------------------------------------------------------------

    /**
     * Unset a storageRegister element.
     *
     * @param string $key    The element name
     * @param string $subkey The element subkey name
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function unsetRegister(string $key, string $subkey = null): ConfigurationVaultInterface
    {
        if (null === $subkey) {
            unset($this->{'storageRegister'}[$key]);
        } else {
            unset($this->{'storageRegister'}[$key][$subkey]);
        }

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Set the location of the Account Home Directory.
     *
     * The Account Home Directory is defined as the location where the unix user account
     * exists (e.g., '/home/jdeere').  This is a location that exist outside or one level above
     * the document root directory (i.e., above public_html).
     *
     * @param string $directoryPath The absolute path to the Account Home Directory (i.e., not document root)
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @throws IOException on invalid directory path
     *
     * @api
     */
    public function setAccountHomeDirectory(string $directoryPath = null): ConfigurationVaultInterface
    {
        if ($directoryPath !== null && !is_dir($directoryPath)) {
            throw new IOException(sprintf('The directory path %s does not exist. Please check the input parameter on method: %s.', $directoryPath, __METHOD__), 0, null, $directoryPath);
        }

        return $this->setProperty('accountHomeDirectory', $directoryPath === null ? realpath(sprintf('%s/../', $_SERVER['DOCUMENT_ROOT'])) : realpath($directoryPath));
    }

    //--------------------------------------------------------------------------

    /**
     * Set the default specific section of the settings file.
     *
     * @param string $vaultRequestedSection The requested section of the vault/settings file (e.g., 'webadmin', 'webuser', 'wwwdyn', etc.)
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultRequestedSection(string $vaultRequestedSection = null): ConfigurationVaultInterface
    {
        return $this->setProperty('vaultRequestedSection', '' === trim((string)$vaultRequestedSection) ? null : trim($vaultRequestedSection));
    }

    //--------------------------------------------------------------------------

    /**
     * Return as PHP Traversable Instance.
     *
     * {@see https://webmozart.io/blog/2012/10/07/give-the-traversable-interface-some-love/}
     *
     * @param mixed $files The string, array, object.
     *
     * @return \Traversable
     */
    protected function toIterator($files): \Traversable
    {
        if (!$files instanceof \Traversable) {
            $files = new \ArrayObject(is_array($files) ? $files : array($files));
        }

        return $files;
    }

    //--------------------------------------------------------------------------

    /**
     * Render the Ambit string.
     *
     * @param string $payload The string being encrypted
     *
     * @return string Returns the Ambit
     */
    protected function renderAmbit(string $payload): iterable
    {
        [$dataSize, $ivSalt, $keySalt] = [$this->stringSize($payload), $this->getRandomInt(), $this->getRandomInt()];

        return ['hash' => $this->hashids->encode([$dataSize, $ivSalt, $keySalt]), 'dataSize' => $dataSize, 'ivSalt' => $ivSalt, 'keySalt' => $keySalt];
    }

    //--------------------------------------------------------------------------

    /**
     * Set the initialization vector (iv) Byte Size (as determined by the cipher method used in OpenSSL).
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setIvByteSize(): ConfigurationVaultInterface
    {
        $ivByteSize = openssl_cipher_iv_length($this->cipherMethod);

        if (!$ivByteSize) {
            throw new \Exception(sprintf(
                'Byte size was not found or invalid cipher method was requested. Check available cipher methods for your current OpenSSL version: %s',
                $this->openSslVersion
            ));
        }

        return $this->setProperty('ivByteSize', $ivByteSize);
    }

    //--------------------------------------------------------------------------

    /**
     * Set OpenSSL version number.
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setOpenSslVersion(): ConfigurationVaultInterface
    {
        return $this->setProperty('openSslVersion', \OPENSSL_VERSION_TEXT);
    }

    //--------------------------------------------------------------------------

    /**
     * Set the primary hash as an array
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setPrimaryHashArray(): ConfigurationVaultInterface
    {
        /* type: encryption, default_environment: private */
        [$release, $environment] = [ $this->encryptionSettingsRawData['type'], $this->encryptionSettingsRawData['default_environment']];
        [$hash, $uuid, $date] = [
            join($this->encryptionSettingsRawData[$release][$environment]['primary_hash']['data']),
            trim($this->encryptionSettingsRawData[$release][$environment]['primary_hash']['uuid']),
            trim($this->encryptionSettingsRawData[$release][$environment]['primary_hash']['date'])
        ];
        [, $time] = explode(' ', $date);
        [$hours, $minutes, $seconds] = array_map('intval', explode(':', $time));

        return $this->setProperty('primaryHashArray', $hash, 'hash')->setProperty('primaryHashArray', $hours, 'hours')
            ->setProperty('primaryHashArray', $minutes, 'minutes')->setProperty('primaryHashArray', $seconds, 'seconds')->setProperty('primaryHashArray', $uuid, 'uuid');
    }

    //--------------------------------------------------------------------------

    /**
     * Set the core seed hash as an array
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setCoreSeedHashArray(): ConfigurationVaultInterface
    {
        /* type: encryption, default_environment: private */
        [$release, $environment] = [ $this->encryptionSettingsRawData['type'], $this->encryptionSettingsRawData['default_environment']];
        [$hash, $uuid, $date] = [
            join($this->encryptionSettingsRawData[$release][$environment]['core_seed_hash']['data']),
            trim($this->encryptionSettingsRawData[$release][$environment]['core_seed_hash']['uuid']),
            trim($this->encryptionSettingsRawData[$release][$environment]['core_seed_hash']['date'])
        ];
        [, $time] = explode(' ', $date);
        [$hours, $minutes, $seconds] = array_map('intval', explode(':', $time));

        return $this->setProperty('coreSeedHashArray', $hash, 'hash')->setProperty('coreSeedHashArray', $hours, 'hours')
            ->setProperty('coreSeedHashArray', $minutes, 'minutes')->setProperty('coreSeedHashArray', $seconds, 'seconds')->setProperty('coreSeedHashArray', $uuid, 'uuid');
    }

    //--------------------------------------------------------------------------

    /**
     * Set the RSA Private and Public Keys.
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setRsaPublicPrivateKeys(): ConfigurationVaultInterface
    {
        /* type: encryption, default_environment: private */
        [$release, $environment] = [$this->encryptionSettingsRawData['type'], $this->encryptionSettingsRawData['default_environment']];

        return $this
            ->setProperty('rsaPrivateKey4096', $this->encryptionSettingsRawData[$release][$environment]['private_key_4096']['data'])
                ->setProperty('rsaPublicKey4096', $this->encryptionSettingsRawData[$release][$environment]['public_key_4096']['data']);
    }

    //--------------------------------------------------------------------------

    /**
     * Set the initialization vector as an array
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setInitializationVectorArray(): ConfigurationVaultInterface
    {
        /* type: encryption, default_environment: private */
        [$release, $environment] = [ $this->encryptionSettingsRawData['type'], $this->encryptionSettingsRawData['default_environment']];
        [$hash, $uuid, $date, $map] = [
            join($this->encryptionSettingsRawData[$release][$environment]['initialization_vector']['data']),
            trim($this->encryptionSettingsRawData[$release][$environment]['initialization_vector']['uuid']),
            trim($this->encryptionSettingsRawData[$release][$environment]['initialization_vector']['date']),
            join($this->encryptionSettingsRawData[$release][$environment]['initialization_vector']['map'])
        ];
        [, $time] = explode(' ', $date);
        [$hours, $minutes, $seconds] = array_map('intval', explode(':', $time));

        return $this->setProperty('initializationVectorArray', $hash, 'hash')->setProperty('initializationVectorArray', $map, 'map')->setProperty('initializationVectorArray', $hours, 'hours')
            ->setProperty('initializationVectorArray', $minutes, 'minutes')->setProperty('initializationVectorArray', $seconds, 'seconds')->setProperty('initializationVectorArray', $uuid, 'uuid');
    }

    //--------------------------------------------------------------------------

    /**
     * Set the environment type settings.
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setVaultEnvironmentTypeSettings(): ConfigurationVaultInterface
    {
        /* The release collection type (e.g., 'database', 'account', 'smtp') */
        $this->setProperty('vaultReleaseType', $this->getProperty('resultDataSet', 'type'));
        /* The current environment defined and used for a vault file (e.g.,'development','staging','production') */
        $this->setProperty(
            'vaultEnvironment',
            null !== $this->getProperty('vaultDefaultEnvironment') ? $this->getProperty('vaultDefaultEnvironment') : $this->getProperty('resultDataSet', 'default_environment')
        );

        /* The specific section of the vault/settings file to be processed (e.g., 'webadmin', 'webuser', 'wwwdyn', etc.) */
        return $this->setProperty('vaultSection', $this->getProperty('vaultRequestedSection'));
    }

    //--------------------------------------------------------------------------

    /**
     * Set ConfigurationVault to encryption mode.
     *
     * @param bool $value The option to work with encrypted configuration data
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setVaultRecordEncrypted($value = true): ConfigurationVaultInterface
    {
        return $this->setProperty('vaultIsEncrypted', (bool) $value);
    }

    //--------------------------------------------------------------------------

    /**
     * Set the list of available digest methods in the current version of PHP's OpenSSL.
     *
     * @param bool $aliases The option to include digest aliases in results
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setAvailableOpenSslDigests(bool $aliases = false): ConfigurationVaultInterface
    {
        return $this->setProperty('availableOpenSslDigests', openssl_get_md_methods($aliases));
    }

    //--------------------------------------------------------------------------

    /**
     * Set the list of available cipher methods in the current version of PHP's OpenSSL.
     *
     * @param bool $aliases The option to include cipher aliases in results
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setAvailableOpenSslCipherMethods(bool $aliases = false): ConfigurationVaultInterface
    {
        return $this->setProperty('availableOpenSslCipherMethods', openssl_get_cipher_methods($aliases));
    }

    //--------------------------------------------------------------------------

    /**
     * Set any required vault file arguments.
     *
     * @param iterable $arguments The specific list of arguments to set
     * @param iterable $vaultData The raw dataset from the vault file (YAML)
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setVaultDataArguments(iterable $arguments, iterable $vaultData): ConfigurationVaultInterface
    {
        foreach ($arguments as $argument) {
            true === $this->isVaultRecordEncrypted() ? $this->set($argument, $this->decrypt($vaultData[$argument])) : $this->set($argument, $vaultData[$argument]);
        }
        $this->unsetRegister(self::VAULTED);

        /* Informational: non-encrypted properties of the record */
        return $this->set('id', $this->getProperty('vaultId'))->set('uuid', $this->getProperty('vaultUuid'))
            ->set('date', $this->getProperty('vaultDate'))->set('is_encrypted', $this->getProperty('vaultIsEncrypted'));
    }

    //--------------------------------------------------------------------------

    /**
     * Set the Encryption Key Byte Size (as determined by the cipher method used in OpenSSL).
     *
     * @param int $size The size in bytes for the key
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setKeyByteSize(int $size = self::DEFAULT_ENCRYPTION_KEY_BYTE_SIZE): ConfigurationVaultInterface
    {
        if (!$size) {
            throw new \Exception(sprintf(
                'Byte size was not found or invalid cipher method was requested. Check available cipher methods for your current OpenSSL version: %s',
                $this->openSslVersion
            ));
        }

        return $this->setProperty('keyByteSize', $size);
    }

    //--------------------------------------------------------------------------
}
