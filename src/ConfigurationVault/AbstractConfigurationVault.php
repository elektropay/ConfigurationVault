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

use Hashids\Hashids;
use Hashids\HashidsInterface;
use UCSDMath\Filesystem\Filesystem;
use UCSDMath\Filesystem\FilesystemInterface;
use UCSDMath\Serialization\Yaml\Yaml;
use UCSDMath\Serialization\Yaml\YamlInterface;
use UCSDMath\Configuration\ConfigurationVault\Exception\IOException;
use UCSDMath\Configuration\ConfigurationVault\Exception\VaultException;
use UCSDMath\Configuration\ConfigurationVault\Exception\FileNotFoundException;
use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\ServiceFunctions;
use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\ServiceFunctionsInterface;
use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\VaultStandardOperations;
use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\VaultStandardOperationsInterface;
use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\VaultServiceMethods;
use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\VaultServiceMethodsInterface;
use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\ServiceSupportOperations;
use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\ServiceSupportOperationsInterface;

/**
 * AbstractConfigurationVault provides an abstract base class implementation of {@link ConfigurationVaultInterface}.
 * This service groups a common code base implementation that ConfigurationVault extends.
 *
 * This component library is used to service configuration information outside of web root.
 *
 * This class was created to handle a security concern of placing clear text account
 * credentials (e.g., usernames, passwords) in PHP source control files within
 * the web root directory space.
 *
 * There are a few of rules I have tried to apply, these are:
 *    - IVs should be random and generated by a CSPRNG.
 *    - IVs should not be reused. That is, don't encrypt plaintext "A" and
 *      plaintext "B" with the same IV. Every record should have its own IV.
 *    - The IV is not a secret like the key. It can be stored in plaintext along
 *      with the cipher text. Although, I prefer to hide it with Hashids.
 *
 * This process involves moving some configuration settings outside the web document root
 * (e.g., /home/username/.external) and into a hidden directory. The owner of the files
 * will be the Apache user (e.g., chown -R apache:apache /home/username/.external), and
 * readable only by Apache (e.g., find /home/username/.external -type f -exec chmod 400 {} \;).
 * In addition, we encrypt the clear text data to make it harder to read.
 *
 * YAML is a human-readable data serialization format that works well with configuration
 * settings. The YAML syntax was designed to be easily mapped to complex data structures.
 * All configuration settings files will be YAML with the ConfigurationVaultInterface.
 *
 * @link http://en.wikipedia.org/wiki/YAML
 * @link http://www.yaml.org/spec/1.2/spec.html
 *
 * Method list: (+) @api, (-) protected or private visibility.
 *
 * (+) ConfigurationVaultInterface __construct(?FilesystemInterface $filesystem = null, ?YamlInterface $yaml = null);
 * (+) void __destruct();
 * (+) string decrypt(string $payload);
 * (+) string encrypt(string $payload);
 * (+) ConfigurationVaultInterface reset();
 * (+) string getUuid(bool $isUpper = true);
 * (+) ConfigurationVaultInterface loadVaultSettingsFile();
 * (+) ConfigurationVaultInterface setHashidsProjectKey(string $optional = null);
 * (+) ConfigurationVaultInterface setEncryptionSettingsFileName(string $vaultFile = null);
 * (+) ConfigurationVaultInterface setVaultSettingsDirectory(string $directoryPath = null);
 * (+) null|iterable hashidsDecode(string $id = null, int $starting = 0, int $minLength = self::DEFAULT_MIN_HASHIDS_LENGTH);
 * (+) ConfigurationVaultInterface loadHashids(string $projectKey = null, int $minLength = self::DEFAULT_MIN_HASHIDS_LENGTH);
 * (+) ConfigurationVaultInterface setRecordProperties(string $vaultReleaseType, string $vaultEnvironment, string $vaultSection = null);
 * (-) ConfigurationVaultInterface loadEncryptionSettingsRawData();
 * (-) ConfigurationVaultInterface setByteSizeMap(string $keyType = 'ivByteSize', int $cipherMethodByteSize = null);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
abstract class AbstractConfigurationVault implements
    ConfigurationVaultInterface,
    ServiceFunctionsInterface,
    ServiceSupportOperationsInterface,
    VaultStandardOperationsInterface,
    VaultServiceMethodsInterface
{
    /**
     * Constants.
     *
     * @var string VERSION The version number
     *
     * @api
     */
    public const VERSION = '1.20.0';

    //--------------------------------------------------------------------------

    /**
     * Properties.
     *
     * @var    YamlInterface               $yaml                          The Yaml Interface
     * @var    FilesystemInterface         $filesystem                    The Filesystem Interface
     * @var    HashidsInterface            $hashids                       The Hashids Interface
     * @var    string                      $accountHomeDirectory          The absolute path to the Account Home Directory (i.e., not document root)
     * @var    string                      $vaultSettingsDirectory        The absolute path to the Vault Settings Directory (i.e., a hidden location)
     * @var    string                      $encryptionSettingsFileName    The absolute path to the Encryption Settings Yaml File
     * @var    iterable                    $encryptionSettingsRawData     The raw Encryption Settings data
     * @var    string                      $hashidsProjectKey             The project key used to encode/decode Hashids integers and arrays
     * @var    string                      $openSslVersion                The OpenSSL version number installed on the system
     * @var    iterable                    $primaryHashArray              The primary list of hash strings used to encrypt/decrypt data
     * @var    iterable                    $coreSeedHashArray             The core seed list of hash strings used to encrypt/decrypt data
     * @var    iterable                    $initializationVectorArray     The initialization vector list of hash strings used to encrypt/decrypt data
     * @var    string                      $rsaPublicKey4096              The RSA public key used by the application
     * @var    string                      $rsaPrivateKey4096             The RSA private key used by the application
     * @var    iterable                    $availableOpenSslDigests       The list of available digests provided in the current version of PHP's OpenSSL (e.g.,'SHA1','SHA256','SHA512', etc.)
     * @var    iterable                    $availableOpenSslCipherMethods The list of available cipher methods provided in the current version of PHP's OpenSSL
     * @var    string                      $cipherMethod                  The cipher method used by OpenSSL to encrypt/decrypt a payload (e.g.,'AES-256-CTR','AES-256-GCM','AES-256-CCM', etc.)
     * @var    int                         $ivByteSize                    The size in bytes for the initialization vector (determined by the cipher method used)
     * @var    iterable                    $ivByteSizeMap                 The map that defines a base64 encoded format for $ivByteSize with padding
     * @var    int                         $keyByteSize                   The size in bytes for the encryption key (please size the cipher method used)
     * @var    iterable                    $keyByteSizeMap                The map that defines a base64 encoded format for $keyByteSize with padding
     * @var    iterable                    $defaultByteSizeMapTypes       The defined array of values used to whitelist options
     * @var    string                      $vaultFile                     The absolute path to the configuration settings file to access and open
     * @var    string                      $vaultRequestedSection         The requested section of the vault/settings file (e.g., 'webadmin', 'webuser', 'wwwdyn', etc.)
     * @var    iterable                    $resultDataSet                 The raw data from the specific vault file requested
     * @var    string                      $vaultReleaseType              The release collection type (e.g., 'database', 'account', 'smtp') as specified within the vault file
     * @var    string                      $vaultDefaultEnvironment       The default category environment (this class specific)
     * @var    string                      $vaultEnvironment              The current environment defined and used for a vault file (e.g., 'development', 'staging', 'production')
     * @var    string                      $vaultSection                  The specific section of the vault/settings file to be processed (e.g., 'webadmin', 'webuser', 'wwwdyn', etc.)
     * @var    string                      $vaultId                       The configuration settings id for the record in process
     * @var    string                      $vaultUuid                     The configuration settings uuid for the record in process
     * @var    string                      $vaultDate                     The configuration settings date for the record in process
     * @var    string                      $vaultIsEncrypted              The configuration settings is_encrypted for the record in process
     * @var    iterable                    $vaultEnvironments             The list of provided categories found in the configuration setting file
     * @var    string                      $vaultDefaultSection           The default section found in the configuration setting file
     * @static ConfigurationVaultInterface $instance                      The static instance ConfigurationVaultInterface
     * @static int                         $objectCount                   The static count of ConfigurationVaultInterface
     * @var    iterable                    $storageRegister               The stored set of data structures used by this class
     * @var    string                        VAULTED[payload]             The data being processed
     * @var    string                        VAULTED[method]              The cipher method used by OpenSSL to encrypt/decrypt a payload (e.g.,'AES-256-CTR','AES-256-GCM','AES-256-CCM', etc.)
     * @var    string                        VAULTED[key]                 The properly sized encryption key used to encrypt/decrypt the payload (the key size is based on the cipher method/mode used)
     * @var    int                           VAULTED[option]              The bitwise disjunction used in OpenSSL (Default: 0, \OPENSSL_RAW_DATA: 1, \OPENSSL_ZERO_PADDING: 2)
     * @var    string                        VAULTED[iv]                  The fixed-size pseudorandom input primitive used in the encryption scheme (Raw binary: based on the method/mode used, AES-256-CTR)
     * @var    string                        VAULTED[dataSize]            The size of the data string within the payload
     * @var    string                        VAULTED[ivSalt]              The random number added in each IV
     * @var    string                        VAULTED[keySalt]             The salt used to create the encryption key
     */
    protected $yaml                          = null;
    protected $filesystem                    = null;
    protected $hashids                       = null;
    protected $accountHomeDirectory          = null;
    protected $vaultSettingsDirectory        = null;
    protected $encryptionSettingsFileName    = null;
    protected $encryptionSettingsRawData     = [];
    protected $hashidsProjectKey             = null;
    protected $openSslVersion                = null;
    protected $primaryHashArray              = [];
    protected $coreSeedHashArray             = [];
    protected $initializationVectorArray     = [];
    protected $rsaPublicKey4096              = null;
    protected $rsaPrivateKey4096             = null;
    protected $availableOpenSslDigests       = [];
    protected $availableOpenSslCipherMethods = [];
    protected $cipherMethod                  = null;
    protected $ivByteSize                    = null;
    protected $ivByteSizeMap                 = [];
    protected $keyByteSize                   = self::DEFAULT_ENCRYPTION_KEY_BYTE_SIZE;
    protected $keyByteSizeMap                = [];
    protected $defaultByteSizeMapTypes       = ['ivByteSize','keyByteSize'];
    protected $vaultFile                     = null;
    protected $vaultRequestedSection         = null;
    protected $resultDataSet                 = [];
    protected $vaultReleaseType              = null;
    protected $vaultDefaultEnvironment       = null;
    protected $vaultEnvironment              = null;
    protected $vaultSection                  = null;
    protected $vaultId                       = null;
    protected $vaultUuid                     = null;
    protected $vaultDate                     = null;
    protected $vaultIsEncrypted              = null;
    protected $vaultEnvironments             = [];
    protected $vaultDefaultSection           = null;
    protected static $instance               = null;
    protected static $objectCount            = 0;
    protected $storageRegister               = [
        self::VAULTED  => [
            'payload'  => null,
            'method'   => null,
            'key'      => null,
            'option'   => null,
            'iv'       => null,
            'dataSize' => null,
            'ivSalt'   => null,
            'keySalt'  => null,
        ]
    ];

    //--------------------------------------------------------------------------

    /**
     * Constructor.
     *
     * @param FilesystemInterface $filesystem The FilesystemInterface
     * @param YamlInterface       $yaml       The YamlInterface
     *
     * @api
     */
    public function __construct(FilesystemInterface $filesystem = null, YamlInterface $yaml = null)
    {
        if (null === $filesystem) {
            $filesystem = Filesystem::init();
        }
        if (null === $yaml) {
            $yaml = Yaml::init();
        }

        $this->setProperty('yaml', $yaml)->setProperty('filesystem', $filesystem)->setAccountHomeDirectory()
            ->setVaultSettingsDirectory()->setEncryptionSettingsFileName()->loadEncryptionSettingsRawData()->setHashidsProjectKey()
            ->loadHashids()->setPrimaryHashArray()->setCoreSeedHashArray()->setInitializationVectorArray()->setRsaPublicPrivateKeys()
            ->setAvailableOpenSslDigests()->setAvailableOpenSslCipherMethods()->setCipherMethod()->setIvByteSize()
            ->setByteSizeMap('ivByteSize')->setKeyByteSize()->setByteSizeMap('keyByteSize')->setOpenSslOption()->setOpenSslVersion();
    }

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
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function decrypt(string $payload): string
    {
        if (!is_callable('random_bytes')) {
            throw new VaultException('There is no suitable CSPRNG installed on your system');
        }
        $this->setInitializationVector($payload)->setEncryptionKey($payload);
        $decrypted = openssl_decrypt(
            base64_decode(substr($payload, self::THE_RAW_VAULT_DATA)),
            $this->get(self::VAULTED, 'method'),
            $this->get(self::VAULTED, 'key'),
            $this->get(self::VAULTED, 'option'),
            $this->get(self::VAULTED, 'iv')
        );

        return substr($decrypted, 0, $this->get(self::VAULTED, 'dataSize'));
    }

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
     * @param string $payload The data payload to decrypt (includes iv)
     *
     * @return string The decrypted data
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function encrypt(string $payload): string
    {
        if (!is_callable('random_bytes')) {
            throw new VaultException('There is no suitable CSPRNG installed on your system');
        }
        [$ambit, $payload] = [$this->renderAmbit($payload), sprintf('%s%s', $payload, $this->randomToken(self::DEFAULT_VAULT_SIZE - $this->stringSize($payload)))];
        $this->setInitializationVector($ambit['hash'])->setEncryptionKey($ambit['hash']);

        return sprintf(
            '%s|%s',
            $ambit['hash'],
            base64_encode(openssl_encrypt($payload, $this->get(self::VAULTED, 'method'), $this->get(self::VAULTED, 'key'), $this->get(self::VAULTED, 'option'), $this->get(self::VAULTED, 'iv')))
        );
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
        return $this
            ->setProperty('vaultId', null)->setProperty('vaultUuid', null)
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
     * Get the Initialization Vector (IV) character map size.
     *
     * @param string $keyType              The key type to set (either: 'ivByteSize', 'keyByteSize')
     * @param int    $cipherMethodByteSize The initialization vector (iv) byte size
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    protected function setByteSizeMap(string $keyType = 'ivByteSize', int $cipherMethodByteSize = null): ConfigurationVaultInterface
    {
        /* check against a defined whitelist */
        if (!in_array($keyType, array_values($this->defaultByteSizeMapTypes), true)) {
            throw new VaultException(sprintf(
                'Invalid Byte Size Type was requested "%s". Check the predefined byte types for your current OpenSSL methods: %s',
                $keyType,
                $this->defaultByteSizeMapTypes
            ));
        }
        $cipherMethodByteSize = $cipherMethodByteSize === null ? $this->getProperty($keyType) : $cipherMethodByteSize;

        return $this->setProperty(
            sprintf('%s%s', $keyType, 'Map'),
            $this->loadHashids($this->hashidsProjectKey, self::DEFAULT_MIN_HASHIDS_MAP_STEPS)
                ->hashids->decode(mb_substr($this->getProperty('initializationVectorArray', 'map'), (($cipherMethodByteSize -1) * self::DEFAULT_MIN_HASHIDS_MAP_STEPS), self::DEFAULT_MIN_HASHIDS_MAP_STEPS))
        )->loadHashids();
    }

    //--------------------------------------------------------------------------

    /**
     * Hashids decode.
     *
     * @param string $id        The id string to decode
     * @param int    $starting  The option to define a starting point in the hash
     * @param int    $minLength The option to define a minimum padding length of the ids
     *
     * @return null|iterable The decoded id
     *
     * @api
     */
    public function hashidsDecode(string $id = null, int $starting = 0, int $minLength = self::DEFAULT_MIN_HASHIDS_LENGTH): ?iterable
    {
        return $id === null
            ? null
            : $this->hashids->decode(mb_substr($id, $starting, $minLength, self::CHARSET));
    }

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
    public function loadHashids(string $projectKey = null, int $minLength = self::DEFAULT_MIN_HASHIDS_LENGTH): ConfigurationVaultInterface
    {
        return $this->setProperty('hashids', new Hashids(($projectKey === null ? $this->getProperty('hashidsProjectKey') : $projectKey), $minLength));
    }

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
    public function setHashidsProjectKey(string $optional = null): ConfigurationVaultInterface
    {
        /* type: encryption, default_environment: private */
        [$release, $environment] = [ $this->encryptionSettingsRawData['type'], $this->encryptionSettingsRawData['default_environment']];
        [$hash, $uuid, $date] = [
            join($this->encryptionSettingsRawData[$release][$environment]['hashids']['data']),
            trim($this->encryptionSettingsRawData[$release][$environment]['hashids']['uuid']),
            trim($this->encryptionSettingsRawData[$release][$environment]['hashids']['date'])
        ];
        [, $time] = explode(' ', $date);
        [$hours, $minutes, $seconds] = array_map('intval', explode(':', $time));
        $this->setProperty(
            'hashidsProjectKey',
            $optional === null
                ? sha1(join([mb_substr($hash, $hours, $minutes, self::CHARSET), mb_substr($hash, (-1 * $seconds), null, self::CHARSET), $uuid]))
                : $optional
        );

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Load the Encryption Settings File Information to Array.
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @throws IOException When target does not exist or is unreadable
     */
    protected function loadEncryptionSettingsRawData(): ConfigurationVaultInterface
    {
        /* we check that target exists and is readable */
        if (!$this->isReadable($this->encryptionSettingsFileName)) {
            throw new IOException(
                sprintf('Cannot read the target file "%s". Does not exists or maybe unreadable.', $this->encryptionSettingsFileName),
                0,
                null,
                $this->encryptionSettingsFileName
            );
        }

        return $this->setProperty('encryptionSettingsRawData', $this->yaml->deserialize($this->filesystem->read($this->encryptionSettingsFileName)));
    }

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
    public function setEncryptionSettingsFileName(string $vaultFile = null): ConfigurationVaultInterface
    {
        $vaultFilePath = sprintf('%s/%s', $this->getProperty('vaultSettingsDirectory'), $vaultFile);
        $this->validateEncryptionSettingsFileName($vaultFilePath, $vaultFile);

        return $this->setProperty(
            'encryptionSettingsFileName',
            $vaultFile === null
                ? realpath(sprintf('%s/%s', $this->getProperty('vaultSettingsDirectory'), static::ENCRYPTION_SETTINGS_FILE_NAME))
                : realpath($vaultFilePath)
        );
    }

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
    public function setVaultSettingsDirectory(string $directoryPath = null): ConfigurationVaultInterface
    {
        if ($directoryPath !== null && !is_dir($directoryPath)) {
            throw new IOException(sprintf('The directory path %s does not exist. Check parameter: %s.', $directoryPath, __METHOD__), 0, null, $directoryPath);
        }

        return $this->setProperty(
            'vaultSettingsDirectory',
            $directoryPath === null
                ? (realpath(sprintf('%s/../%s', $_SERVER['DOCUMENT_ROOT'], static::VAULT_DIRECTORY_NAME))
                    ? realpath(sprintf('%s/../%s', $_SERVER['DOCUMENT_ROOT'], static::VAULT_DIRECTORY_NAME))
                    : null)
                : (realpath($directoryPath) ? realpath($directoryPath) : null)
        );
    }

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
    public function setRecordProperties(string $vaultReleaseType, string $vaultEnvironment, string $vaultSection = null): ConfigurationVaultInterface
    {
        return null === $vaultSection
            ? $this->setProperty('resultDataSet', $this->getProperty('resultDataSet')[$vaultReleaseType][$vaultEnvironment])
            : $this->setProperty('resultDataSet', $this->getProperty('resultDataSet')[$vaultReleaseType][$vaultEnvironment][$vaultSection])
                ->setProperty('vaultId', $this->getProperty('resultDataSet', 'id'))
                    ->setProperty('vaultUuid', $this->getProperty('resultDataSet', 'uuid'))
                        ->setProperty('vaultDate', $this->getProperty('resultDataSet', 'date'))
                            ->setVaultRecordEncrypted($this->getProperty('resultDataSet', 'is_encrypted'));
    }

    //--------------------------------------------------------------------------

    /**
     * Load the Vault Settings File Information to Array.
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @throws IOException When target does not exist or is unreadable
     */
    public function loadVaultSettingsFile(): ConfigurationVaultInterface
    {
        /* we check that target exists and is readable */
        if (!$this->isReadable($this->vaultFile)) {
            throw new IOException(
                sprintf('Cannot read the target file "%s". Does not exists or maybe unreadable.', $this->vaultFile),
                0,
                null,
                $this->vaultFile
            );
        }

        return $this->setProperty('resultDataSet', $this->yaml->deserialize($this->filesystem->read($this->vaultFile)));
    }

    //--------------------------------------------------------------------------

    /**
     * Destructor.
     *
     * @api
     */
    public function __destruct()
    {
        static::$objectCount--;
    }

    //--------------------------------------------------------------------------

    /**
     * Method implementations inserted:
     *
     * Method list: (+) @api, (-) protected or private visibility.
     *
     * (+) string hashidsEncode($numerical = null);
     * (+) ConfigurationVaultInterface unsetRegister(string $key, string $subkey = null);
     * (+) ConfigurationVaultInterface setAccountHomeDirectory(string $directoryPath = null;
     * (+) ConfigurationVaultInterface setVaultRequestedSection(string $vaultRequestedSection = null);
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
     */
    use VaultServiceMethods;

    //--------------------------------------------------------------------------

    /**
     * Method implementations inserted:
     *
     * Method list: (+) @api, (-) protected or private visibility.
     *
     * (+) bool exists($files);
     * (+) string getUniqueId(int $length = 16);
     * (+) string reverseString(string $payload);
     * (+) string numberToString(string $payload);
     * (+) string stringToNumber(string $payload);
     * (+) string repeatString(string $str, int $number);
     * (+) string getSha512(string $data = null, bool $isUpper = true);
     * (+) string randomToken(int $length = 32, string $chars = self::PASSWORD_TOKENS);
     * (+) int getRandomInt(int $min = self::MIN_RANDOM_INT, int $max = self::MAX_RANDOM_INT);
     * (+) string decryptMessage(string $payload, string $encryptionKey, string $method = 'aes-256-cbc');
     * (+) string encryptMessage(string $payload, string $encryptionKey, string $method = 'aes-256-cbc');
     * (-) Traversable toIterator($files);
     * (-) bool isVaultRecordEncrypted();
     * (-) int stringSize(string $payload);
     * (-) bool isReadable(string $filename);
     * (-) string resizeKeyToMap(string $hash, iterable $specificMapSize);
     */
    use VaultStandardOperations;

    //--------------------------------------------------------------------------

    /**
     * Method implementations inserted:
     *
     * Method list: (+) @api, (-) protected or private visibility.
     *
     * (+) string getUuid(bool $isUpper = true);
     */
    use ServiceSupportOperations;

    //--------------------------------------------------------------------------

    /**
     * Method implementations inserted:
     *
     * Method list: (+) @api, (-) protected or private visibility.
     *
     * (+) iterable all();
     * (+) object init();
     * (+) string version();
     * (+) bool isString($str);
     * (+) bool has(string $key);
     * (+) string getClassName();
     * (+) int getInstanceCount();
     * (+) mixed getConst(string $key);
     * (+) iterable getClassInterfaces();
     * (+) bool isValidUuid(string $uuid);
     * (+) bool isValidEmail(string $email);
     * (+) bool isValidSHA512(string $hash);
     * (+) bool doesFunctionExist(string $functionName);
     * (+) bool isStringKey(string $str, iterable $keys);
     * (+) mixed get(string $key, string $subkey = null);
     * (+) mixed getProperty(string $name, string $key = null);
     * (+) mixed __call(string $callback, iterable $parameters);
     * (+) object set(string $key, $value, string $subkey = null);
     * (+) object setProperty(string $name, $value, string $key = null);
     * (-) Exception throwExceptionError(iterable $error);
     * (-) InvalidArgumentException throwInvalidArgumentExceptionError(iterable $error);
     */
    use ServiceFunctions;

    //--------------------------------------------------------------------------
}
