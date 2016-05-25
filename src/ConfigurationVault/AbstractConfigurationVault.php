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
use UCSDMath\Functions\ServiceFunctions;
use UCSDMath\Functions\ServiceFunctionsInterface;
use UCSDMath\Serialization\Yaml\YamlInterface;

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
 * This process involves moving some configuration settings outside the web root
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
 * (+) ConfigurationVaultInterface __construct(FilesystemInterface $filesystem, YamlInterface $yaml);
 * (+) void __destruct();
 * (+) bool isVaultRecordEncrypted();
 * (+) string decrypt($encryptedString);
 * (+) ConfigurationVaultInterface setHashKey();
 * (+) ConfigurationVaultInterface setCipherKey();
 * (+) ConfigurationVaultInterface setRsaPrivateKeys();
 * (+) ConfigurationVaultInterface setAccountRoot($value);
 * (+) ConfigurationVaultInterface loadVaultSettingsFile();
 * (+) ConfigurationVaultInterface setVaultFilename($value);
 * (+) ConfigurationVaultInterface setInitializationVector();
 * (+) ConfigurationVaultInterface setEnvironmentAccountType();
 * (+) ConfigurationVaultInterface setVaultSettingsDirectory($value);
 * (+) ConfigurationVaultInterface setVaultFileRequestedSection($value);
 * (+) ConfigurationVaultInterface setVaultRecordEncrypted($value = true);
 * (+) ConfigurationVaultInterface setRecordProperties($release, $environment, $account);
 * (+) ConfigurationVaultInterface setVaultDataArguments(array $arguments, array $vaultData);
 * (+) ConfigurationVaultInterface openVaultFile($vaultFilename, $vaultFileRequestedSection = null);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
abstract class AbstractConfigurationVault implements ConfigurationVaultInterface, ServiceFunctionsInterface
{
    /**
     * Constants.
     *
     * @var string VERSION A version number
     *
     * @api
     */
    const VERSION = '1.7.0';

    //--------------------------------------------------------------------------

    /**
     * Properties.
     *
     * @var    YamlInterface               $yaml                        A YamlInterface
     * @var    FilesystemInterface         $filesystem                  A FilesystemInterface
     * @var    string                      $cipherKey                   A encryption key
     * @var    array                       $hashKey                     A list of hash strings
     * @var    array                       $resultDataSet               A result data set
     * @var    array                       $storageRegister             A set of stored data elements
     * @var    string                      $vaultFilename               A requested configuration settings file
     * @var    string                      $vaultFileType               A configuration file type
     * @var    string                      $vaultRecordId               A configuration file record id
     * @var    string                      $vaultRecordUUID             A configuration file record uuid
     * @var    string                      $vaultRecordDate             A configuration file record date
     * @var    string                      $rsaPublicKey1024            A public key
     * @var    string                      $rsaPrivateKey1024           A private key
     * @var    string                      $theAccountRootPath          A absolute path to the account root (e.g., not web root)
     * @var    string                      $initializationVector        A primitive used for Cipher Block Chaining (CBC)
     * @var    string                      $vaultRecordEncrypted        A status of record encryption
     * @var    array                       $vaultFileEnvironments       A list of provided categories
     * @var    string                      $vaultSettingsDirectory      A configuration directory location
     * @var    string                      $vaultFileDefaultSection     A default section
     * @var    string                      $vaultFileRequestedSection   A user requested section
     * @var    string                      $vaultFileDefaultEnvironment A default category
     * @static ConfigurationVaultInterface $instance                    A ConfigurationVaultInterface
     * @static int                         $objectCount                 A ConfigurationVaultInterface count
     */
    protected $yaml                        = null;
    protected $filesystem                  = null;
    protected $cipherKey                   = null;
    protected $environment                 = null;
    protected $account                     = null;
    protected $release                     = null;
    protected $hashKey                     = array();
    protected $resultDataSet               = array();
    protected $storageRegister             = array();
    protected $vaultFilename               = null;
    protected $vaultFileType               = null;
    protected $vaultRecordId               = null;
    protected $vaultRecordUUID             = null;
    protected $vaultRecordDate             = null;
    protected $rsaPublicKey1024            = null;
    protected $rsaPrivateKey1024           = null;
    protected $theAccountRootPath          = null;
    protected $initializationVector        = null;
    protected $vaultRecordEncrypted        = false;
    protected $vaultFileEnvironments       = array();
    protected $vaultSettingsDirectory      = null;
    protected $vaultFileDefaultSection     = null;
    protected $vaultFileRequestedSection   = null;
    protected $vaultFileDefaultEnvironment = null;
    protected static $instance             = null;
    protected static $objectCount          = 0;

    //--------------------------------------------------------------------------

    /**
     * Constructor.
     *
     * @param FilesystemInterface  $filesystem A FilesystemInterface
     * @param YamlInterface        $yaml       A YamlInterface
     *
     * @api
     */
    public function __construct(FilesystemInterface $filesystem, YamlInterface $yaml)
    {
        /* Config. Arguments */
        $this->setProperty('filesystem', $filesystem)
            ->setProperty('yaml', $yaml)
                ->setVaultSettingsDirectory(realpath(__DIR__ . '/../../../../../../../../../../.external-configuration-settings'))
                    ->setAccountRoot(realpath(__DIR__ . '/../../../../../../../../../../'))
                        ->setHashKey()
                            ->setRsaPrivateKeys()
                                ->setInitializationVector();

        static::$instance = $this;
        static::$objectCount++;
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
     * Returns bool status of property $vaultRecordEncrypted.
     *
     * @return bool
     *
     * @api
     */
    protected function isVaultRecordEncrypted(): bool
    {
        return $this->getProperty('vaultRecordEncrypted');
    }

    //--------------------------------------------------------------------------

    /**
     * Set ConfigurationVault to encryption mode.
     *
     * @param bool $value  A option to work with encrypted configuration data
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultRecordEncrypted(bool $value = true): ConfigurationVaultInterface
    {
        $this->setProperty('vaultRecordEncrypted', (bool) $value);

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Decrypt Rijndael-256 AES Data Encryption Cipher with Cipher Block Chaining (CBC).
     *
     * @param string  $encryptedString  The data to decrypt
     *
     * @return string  A decrypted data
     */
    protected function decrypt(string $encryptedString, string $key = null): string
    {
        return trim(mcrypt_decrypt(
            static::CIPHER,
            $this->getProperty('cipherKey'),
            base64_decode($encryptedString),
            static::CIPHER_MODE,
            $this->getProperty('initializationVector')
        ));
    }

    //--------------------------------------------------------------------------

    /**
     * Setting the main Cipher Key for decryption if required.
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    protected function setCipherKey(): ConfigurationVaultInterface
    {
        $offset = (int) substr($this->vaultRecordDate, -2) / 1; // 0-59 seconds for offset
        $seed1 = mb_substr(implode(array_slice($this->getProperty('hashKey'), 0, 2)), $offset, 32, static::CHARSET);
        $seed2 = $this->vaultRecordUUID;
        $cnfKey = mb_strtoupper(mb_substr(sha1($seed1 . $seed2), 0, 32, static::CHARSET), static::CHARSET);
        $this->setProperty('cipherKey', mb_substr(sha1($cnfKey), 0, 32, static::CHARSET));

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Setting a general Initialization Vector
     * for cipher-block chaining (CBC).
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setHashKey(): ConfigurationVaultInterface
    {
        $encryptionFileArray = $this->yaml->deserialize($this->filesystem->read($this->vaultSettingsDirectory . '/' . static::ENCRYPTION_SETTINGS_FILE));
        $release = $encryptionFileArray['type']; // encryption
        $environment = $encryptionFileArray['default_environment']; // private
        $this->setProperty('hashKey', $encryptionFileArray[$release][$environment]['seed_hash']['key']);

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Storage of RSA Private Key.
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setRsaPrivateKeys(): ConfigurationVaultInterface
    {
        $encryptionFileArray = $this->yaml->deserialize($this->filesystem->read($this->vaultSettingsDirectory . '/' . static::ENCRYPTION_SETTINGS_FILE));
        $release = $encryptionFileArray['type']; // encryption
        $environment = $encryptionFileArray['default_environment']; // private
        $this->setProperty('rsaPrivateKey1024', $encryptionFileArray[$release][$environment]['rsa_private_1024']['key']);
        $this->setProperty('rsaPublicKey1024', $encryptionFileArray[$release]['public']['rsa_public_1024']['key']);

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Setting a general Initialization Vector (IV)
     * for cipher-block chaining (CBC).
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setInitializationVector(): ConfigurationVaultInterface
    {
        /* Initialization Vector (IV) does not need to be secret.
         * However, it does not need to be public either.
         */
        $ivsize = (int) mcrypt_get_iv_size(static::CIPHER, static::CIPHER_MODE);
        $this->setProperty('initializationVector', mb_substr(sha1(implode(array_slice($this->getProperty('hashKey'), 2, 2))), 0, $ivsize, static::CHARSET));

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Open configuration file settings.
     *
     * @param string $vaultFilename              A specific configuration to open. (e.g., 'Database')
     * @param string $vaultFileRequestedSection  A specific file section (e.g., 'webadmin')
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function openVaultFile(string $vaultFilename, string $vaultFileRequestedSection = null): ConfigurationVaultInterface
    {
        /* Extract the raw YAML file into array and store in $this->resultDataSet */
        $this->setVaultFilename($vaultFilename);
        $this->setVaultFileRequestedSection($vaultFileRequestedSection);
        $this->loadVaultSettingsFile();
        $this->setEnvironmentAccountType();

        if (null !== $this->getProperty('vaultFileRequestedSection')) {
            $this->setRecordProperties($this->release, $this->environment, $this->account);
            $this->setVaultRecordEncrypted($this->getProperty('resultDataSet')['is_encrypted']);
            $this->setCipherKey();

        } elseif (null !== $this->vaultFileDefaultEnvironment) {
            $this->setProperty('resultDataSet', $this->resultDataSet[$this->release][$this->environment]);
        }

        /* Removing the last four elements from the array */
        $vaultData = $this->getProperty('resultDataSet');
        $this->setVaultDataArguments(array_slice(array_keys($vaultData), 0, count(array_keys($vaultData)) - 4), $vaultData);

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Set any required vault file arguments.
     *
     * @param array $arguments  A specific list of arguments to set
     * @param array $vaultData  A raw dataset from the vault file (YAML)
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setVaultDataArguments(array $arguments, array $vaultData): ConfigurationVaultInterface
    {
        foreach ($arguments as $argument) {
            true === $this->isVaultRecordEncrypted()
                ? $this->set($argument, $this->decrypt($vaultData[$argument]))
                : $this->set($argument, $vaultData[$argument]);
        }

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Get environment account type settings.
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setEnvironmentAccountType(): ConfigurationVaultInterface
    {
        /* File type [database] */
        $this->release = $this->getProperty('resultDataSet')['type'];

        /* Default Environment [production] | User may ask for different environment. */
        $this->environment = null !== $this->getProperty('vaultFileDefaultEnvironment')
            ? $this->getProperty('vaultFileDefaultEnvironment')
            : $this->getProperty('resultDataSet')['default_environment'];

        /* Specific section [webadmin] */
        $this->account = $this->getProperty('vaultFileRequestedSection');

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function loadVaultSettingsFile(): ConfigurationVaultInterface
    {
        $this->setProperty(
            'resultDataSet',
            $this->yaml->deserialize($this->filesystem->read($this->vaultSettingsDirectory . '/' . $this->vaultFilename))
        );

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Set the database record properties.
     *
     * @param string $release      A release collection type (e.g., 'database', 'account', 'smtp')
     * @param string $environment  A operating environment (e.g., 'development', 'staging', 'production')
     * @param string $account      A specific section of data to open (e.g., 'webadmin', 'webuser', 'wwwdyn')
     *
     * @return ConfigurationVaultInterface The current instance
     */
    public function setRecordProperties(string $release, string $environment, string $account): ConfigurationVaultInterface
    {
        $this->setProperty('resultDataSet', $this->getProperty('resultDataSet')[$release][$environment][$account]);
        $this->setProperty('vaultRecordId', $this->getProperty('resultDataSet')['id']);
        $this->setProperty('vaultRecordUUID', $this->getProperty('resultDataSet')['uuid']);
        $this->setProperty('vaultRecordDate', $this->getProperty('resultDataSet')['date']);

        /* Adding back the id */
        $this->set('id', $this->getProperty('vaultRecordId'));
        $this->set('uuid', $this->getProperty('vaultRecordUUID'));
        $this->set('date', $this->getProperty('vaultRecordDate'));
        $this->set('is_encrypted', $this->getProperty('vaultRecordEncrypted'));

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Set the account root path.
     *
     * @param string $value  A directory path to the account root (e.g., outside of web root)
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setAccountRoot(string $value): ConfigurationVaultInterface
    {
        $this->setProperty('theAccountRootPath', rtrim($value, '/'));

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Set the database record properties.
     *
     * @param string $value  A vault file name to open (e.g., 'database', 'account', 'encryption')
     *
     * @return ConfigurationVaultInterface The current instance
     */
    public function setVaultFilename(string $value): ConfigurationVaultInterface
    {
        $filename = false !== strpos($value, 'configuration-settings')
            ? strtolower(trim($value, '/ ')) . '.yml'
            : 'configuration-settings-' . strtolower(trim($value, '/ ')) . '.yml';

        $this->setProperty('vaultFilename', $filename);

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Set the default requested section (e.g., 'webadmin', 'webuser', 'wwwdyn').
     *
     * @param string $requestedSection  A default section name to pull from the vault file
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultFileRequestedSection(string $requestedSection = null): ConfigurationVaultInterface
    {
        $this->isString($requestedSection)
            ? $this->setProperty('vaultFileRequestedSection', trim($requestedSection))
            : $this->setProperty('vaultFileRequestedSection', null);

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Set the location of the vault directory (e.g., '/home/www/.external-configuration-settings/').
     *
     * @param string $value  A default location path to the configuration settings directory
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultSettingsDirectory(string $value): ConfigurationVaultInterface
    {
        $this->setProperty('vaultSettingsDirectory', rtrim($value, '/'));

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Method implementations inserted:
     *
     * Method noted as: (+) @api, (-) protected or private visibility.
     *
     * (+) array all();
     * (+) object init();
     * (+) string version();
     * (+) bool isString($str);
     * (+) bool has(string $key);
     * (+) string getClassName();
     * (+) int getInstanceCount();
     * (+) bool isValidEmail($email);
     * (+) array getClassInterfaces();
     * (+) mixed getConst(string $key);
     * (+) bool isValidUuid(string $uuid);
     * (+) bool isValidSHA512(string $hash);
     * (+) mixed __call($callback, $parameters);
     * (+) bool doesFunctionExist($functionName);
     * (+) bool isStringKey(string $str, array $keys);
     * (+) mixed get(string $key, string $subkey = null);
     * (+) mixed getProperty(string $name, string $key = null);
     * (+) object set(string $key, $value, string $subkey = null);
     * (+) object setProperty(string $name, $value, string $key = null);
     * (-) \Exception throwExceptionError(array $error);
     * (-) \InvalidArgumentException throwInvalidArgumentExceptionError(array $error);
     */
    use ServiceFunctions;

    //--------------------------------------------------------------------------
}
