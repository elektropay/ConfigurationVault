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
 * (+) string decrypt(string $payload);
 * (+) string encrypt(string $payload);
 * (+) ConfigurationVaultInterface loadVaultSettingsFile();
 * (+) ConfigurationVaultInterface setVaultFile(string $vaultFileDesignator);
 * (+) ConfigurationVaultInterface setHashidsProjectKey(string $optional = null);
 * (+) ConfigurationVaultInterface setEncryptionSettingsFileName(string $vaultFile = null);
 * (+) ConfigurationVaultInterface setVaultSettingsDirectory(string $directoryPath = null);
 * (+) ConfigurationVaultInterface openVaultFile(string $vaultFileDesignator, string $vaultRequestedSection = null);
 * (+) array hashidsDecode(string $id = null, int $starting = 0, int $minLength = self::DEFAULT_MIN_HASHIDS_LENGTH);
 * (+) ConfigurationVaultInterface loadHashids(string $projectKey = null, int $minLength = self::DEFAULT_MIN_HASHIDS_LENGTH);
 * (+) ConfigurationVaultInterface setRecordProperties(string $vaultReleaseType, string $vaultEnvironment, string $vaultSection = null);
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
     * @var string CHARSET                       The preferred character encoding set
     * @var string ENCRYPTION_SETTINGS_FILE_NAME The encryption configuration settings file name
     * @var string VAULT_DIRECTORY_NAME          The Vault Directory Name (outside of root webspace)
     * @var int    KEY_BYTE_SIZE                 The input length
     * @var int    MAC_BYTE_SIZE                 The input length
     * @var string HASH_FUNCTION                 The seeding function
     * @var string TEST_DATA                     The text as a constant.
     * @var string DEFAULT_CIPHER_METHOD         The default cipher method used to encrypt/decrypt openssl payloads.
     * @var int    MIN_RANDOM_INT                The input length
     * @var int    MAX_RANDOM_INT                The input length
     */
    public const CHARSET                          = 'utf-8';
    public const ENCRYPTION_SETTINGS_FILE_NAME    = 'configuration-settings-encryption.yml';
    public const VAULT_DIRECTORY_NAME             = '.external-configuration-settings';
    public const KEY_BYTE_SIZE                    = 32;
    public const MAC_BYTE_SIZE                    = 32;
    public const HASH_FUNCTION                    = 'sh1';
    public const TEST_DATA                        = 'Hi There...';
    public const DEFAULT_VAULT_SECTION            = 'webadmin';
    public const MIN_RANDOM_INT                   = 1;
    public const MAX_RANDOM_INT                   = 9999999999999999;
    public const PASSWORD_TOKENS                  = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    public const SEED_HASH_TOKENS                 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    public const IV_HASH_TOKENS                   = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    public const HEXADECIMAL_TOKENS               = '0123456789ABCDEFabcdef';
    public const PRIMARY_HASH_TOKENS              = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz/#!&$@*_.~+^=';
    public const DEFAULT_CIPHER_METHOD            = 'AES-256-CTR';
    public const CTR_CIPHER_METHOD                = 'AES-256-CTR';
    public const GCM_CIPHER_METHOD                = 'AES-256-GCM';
    public const XTS_CIPHER_METHOD                = 'AES-256-XTS';
    public const CCM_CIPHER_METHOD                = 'AES-256-CCM';
    public const CBC_CIPHER_METHOD                = 'AES-256-CBC';
    public const DEFAULT_IP_ADDRESS               = '127.0.0.1';
    public const DEFAULT_MYSQL_PORT               = 3306;
    public const DEFAULT_MYSQL_HOST               = 'localhost';
    public const DEFAULT_MYSQL_USERNAME           = 'root';
    public const DEFAULT_MIN_HASHIDS_LENGTH       = 30;
    public const DEFAULT_MIN_HASHIDS_MAP_STEPS    = 5;
    public const DEFAULT_ENCRYPTION_KEY_BYTE_SIZE = 32;
    public const VAULTED                          = '::privately-vaulted::';
    public const DEFAULT_VAULT_SIZE               = 50;
    public const THE_RAW_VAULT_DATA               = -68;

    //--------------------------------------------------------------------------

    /**
     * Decrypt a messages.
     *
     * Defaults to using Advanced Encryption Standard (AES), 256 bits
     * and any valid mode you may want to use.  Please reference the
     * defined DEFAULT_CIPHER_METHOD to see what is currently favored.
     *
     * @param string $payload The data payload to decrypt (includes iv)
     *
     * @return string The decrypted data
     *
     * @api
     */
    public function decrypt(string $payload): string;

    //--------------------------------------------------------------------------

    /**
     * Encrypt a messages.
     *
     * Defaults to using Advanced Encryption Standard (AES), 256 bits
     * and any valid mode you may want to use.  Please reference the
     * defined DEFAULT_CIPHER_METHOD to see what is currently favored.
     *
     * Note: The Ambit consists of: ['hash','dataSize,'ivSalt','keySalt']
     *
     * @param string $payload The data payload to encrypt
     *
     * @return string The encrypted data
     *
     * @api
     */
    public function encrypt(string $payload): string;

    //--------------------------------------------------------------------------

    /**
     * Load the Vault Settings File Information to Array.
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @throws IOException When target does not exist or is unreadable
     */
    public function loadVaultSettingsFile(): ConfigurationVaultInterface;

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
    public function setVaultFile(string $vaultFileDesignator): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the Hashids Project Key.
     *
     * @param string $optional The option to use your own seed for the Hashids Key
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setHashidsProjectKey(string $optional = null): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the Vault Settings File Name (e.g., '/home/jdeere/.external-configuration-settings/encryption-settings.yml').
     *
     * @param string $vaultFile The name of the Vault Settings File to use
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setEncryptionSettingsFileName(string $vaultFile = null): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the location of the Vault Settings Directory.
     *
     * The Vault Settings Directory is defined as the directory location outside of the
     * document root directory (or active webspace) where the configuration files
     * will exist (e.g., '/home/jdeere/.external-configuration-settings/').
     *
     * In many cases, the vault settings directory may exist within the unix user's account home directory.
     *
     * @param string $directoryPath The absolute path to the Vault Settings Directory (i.e., a hidden location)
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @throws IOException on invalid directory path
     *
     * @api
     */
    public function setVaultSettingsDirectory(string $directoryPath = null): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Open a selected configuration file.
     *
     * @param string $vaultFileDesignator   The specific configuration to open. (e.g., 'Database', 'SMTP', 'Account', 'Administrator', etc.)
     * @param string $vaultRequestedSection The requested section of the vault/settings file (e.g., 'webadmin', 'webuser', 'wwwdyn', etc.)
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function openVaultFile(string $vaultFileDesignator, string $vaultRequestedSection = null): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Hashids decode.
     *
     * @param string $id        The id string to decode
     * @param int    $starting  The option to define a starting point in the hash
     * @param int    $minLength The option to define a minimum padding length of the ids
     *
     * @return null|array The decoded id
     *
     * @api
     */
    public function hashidsDecode(string $id = null, int $starting = 0, int $minLength = self::DEFAULT_MIN_HASHIDS_LENGTH): ?array;

    //--------------------------------------------------------------------------

    /**
     * Load a new Hashid into memory.
     *
     * @param string $projectKey The option to define a project name to make your ids unique
     * @param int    $minLength  The option to define a minimum padding length of the ids
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function loadHashids(string $projectKey = null, int $minLength = self::DEFAULT_MIN_HASHIDS_LENGTH): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------

    /**
     * Set the database record properties.
     *
     * @param string $vaultReleaseType The release collection type (e.g., 'database', 'account', 'smtp') as specified within the vault file
     * @param string $vaultEnvironment The current environment defined and used for a vault file (e.g., 'development', 'staging', 'production')
     * @param string $vaultSection     The specific section of the vault/settings file to be processed or opened (e.g., 'webadmin', 'webuser', 'wwwdyn', etc.)
     *
     * @return ConfigurationVaultInterface The current instance
     */
    public function setRecordProperties(string $vaultReleaseType, string $vaultEnvironment, string $vaultSection = null): ConfigurationVaultInterface;

    //--------------------------------------------------------------------------
}
