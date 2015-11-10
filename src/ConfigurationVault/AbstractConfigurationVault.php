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

use UCSDMath\Functions\ServiceFunctions;
use UCSDMath\Filesystem\FilesystemInterface;
use UCSDMath\Serialization\Yaml\YamlInterface;
use UCSDMath\Functions\ServiceFunctionsInterface;

/**
 * AbstractConfigurationVault provides an abstract base class implementation of {@link ConfigurationVaultInterface}.
 * Primarily, this services the fundamental implementations for all ConfigurationVault classes.
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
 * Method list:
 *
 * @method ConfigurationVaultInterface __construct(FilesystemInterface $filesystem, YamlInterface $yaml);
 * @method void __destruct();
 * @method Boolean isVaultRecordEncrypted();
 * @method string decrypt($encryptedString);
 * @method ConfigurationVaultInterface setHashKey();
 * @method ConfigurationVaultInterface setCipherKey();
 * @method ConfigurationVaultInterface setRsaPrivateKeys();
 * @method ConfigurationVaultInterface setAccountRoot($value);
 * @method ConfigurationVaultInterface loadVaultSettingsFile();
 * @method ConfigurationVaultInterface setVaultFilename($value);
 * @method ConfigurationVaultInterface setInitializationVector();
 * @method ConfigurationVaultInterface setEnvironmentAccountType();
 * @method ConfigurationVaultInterface setVaultSettingsDirectory($value);
 * @method ConfigurationVaultInterface setVaultFileRequestedSection($value);
 * @method ConfigurationVaultInterface setVaultRecordEncrypted($value = true);
 * @method ConfigurationVaultInterface setRecordProperties($release, $environment, $account);
 * @method ConfigurationVaultInterface setVaultDataArguments(array $arguments, array $vaultData);
 * @method ConfigurationVaultInterface openVaultFile($vaultFilename, $vaultFileRequestedSection = null);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
abstract class AbstractConfigurationVault implements ConfigurationVaultInterface, ServiceFunctionsInterface
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
     *
     * @var    YamlInterface               $yaml                        A YamlInterface instance
     * @var    FilesystemInterface         $filesystem                  A FilesystemInterface instance
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
     * @static ConfigurationVaultInterface $instance                    A ConfigurationVaultInterface instance
     * @static integer                     $objectCount                 A ConfigurationVaultInterface instance count
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
    protected $vaultRecordEncrypted        = null;
    protected $vaultFileEnvironments       = array();
    protected $vaultSettingsDirectory      = null;
    protected $vaultFileDefaultSection     = null;
    protected $vaultFileRequestedSection   = null;
    protected $vaultFileDefaultEnvironment = null;
    protected static $instance             = null;
    protected static $objectCount          = 0;

    // --------------------------------------------------------------------------

    /**
     * Constructor.
     *
     * @param FilesystemInterface  $filesystem A FilesystemInterface Interface instance
     * @param YamlInterface        $yaml       A YamlInterface Interface instance
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

    // --------------------------------------------------------------------------

    /**
     * Destructor.
     *
     * @api
     */
    public function __destruct()
    {
        static::$objectCount--;
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
     * {@inheritdoc}
     */
    public function setVaultRecordEncrypted($value = true)
    {
        $this->setProperty('vaultRecordEncrypted', (bool) $value);

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Decrypt Rijndael-256 AES Data Encryption Cipher with Cipher Block Chaining (CBC).
     *
     * @param  string  $encryptedString  The data to decrypt
     *
     * @return string  A decrypted data
     */
    protected function decrypt($encryptedString)
    {
        return trim(mcrypt_decrypt(
            static::CIPHER,
            $this->getProperty('cipherKey'),
            base64_decode($encryptedString),
            static::CIPHER_MODE,
            $this->getProperty('initializationVector')
        ));
    }

    // --------------------------------------------------------------------------

    /**
     * Setting the main Cipher Key for decryption if required.
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    protected function setCipherKey()
    {
        $offset = (int) substr($this->vaultRecordDate, -2) / 1; // 0-59 seconds for offset
        $seed1 = mb_substr(implode(array_slice($this->getProperty('hashKey'), 0, 2)), $offset, 32, static::CHARSET);
        $seed2 = $this->vaultRecordUUID;
        $cnfKey = mb_strtoupper(mb_substr(sha1($seed1 . $seed2), 0, 32, static::CHARSET), static::CHARSET);
        $this->setProperty('cipherKey', mb_substr(sha1($cnfKey), 0, 32, static::CHARSET));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Setting a general Initialization Vector
     * for cipher-block chaining (CBC).
     *
     * @return ConfigurationVaultInterface
     */
    protected function setHashKey()
    {
        $encryptionFileArray = $this->yaml->deserialize($this->filesystem->read($this->vaultSettingsDirectory . '/' . static::ENCRYPTION_SETTINGS_FILE));
        $release = $encryptionFileArray['type']; // encryption
        $environment = $encryptionFileArray['default_environment']; // private
        $this->setProperty('hashKey', $encryptionFileArray[$release][$environment]['seed_hash']['key']);

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Storage of RSA Private Key.
     *
     * @return ConfigurationVaultInterface
     */
    protected function setRsaPrivateKeys()
    {
        $encryptionFileArray = $this->yaml->deserialize($this->filesystem->read($this->vaultSettingsDirectory . '/' . static::ENCRYPTION_SETTINGS_FILE));
        $release = $encryptionFileArray['type']; // encryption
        $environment = $encryptionFileArray['default_environment']; // private
        $this->setProperty('rsaPrivateKey1024', $encryptionFileArray[$release][$environment]['rsa_private_1024']['key']);
        $this->setProperty('rsaPublicKey1024', $encryptionFileArray[$release]['public']['rsa_public_1024']['key']);

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Setting a general Initialization Vector (IV)
     * for cipher-block chaining (CBC).
     *
     * @return ConfigurationVaultInterface
     */
    protected function setInitializationVector()
    {
        /* Initialization Vector (IV) does not need to be secret.
         * However, it does not need to be public either.
         */
        $ivsize = (int) mcrypt_get_iv_size(static::CIPHER, static::CIPHER_MODE);
        $this->setProperty('initializationVector', mb_substr(sha1(implode(array_slice($this->getProperty('hashKey'), 2, 2))), 0, $ivsize, static::CHARSET));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Open configuration file settings.
     *
     * @param  string $vaultFilename              A specific configuration to open. (e.g., 'Database')
     * @param  string $vaultFileRequestedSection  A specific file section (e.g., 'webadmin')
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function openVaultFile($vaultFilename, $vaultFileRequestedSection = null)
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

    // --------------------------------------------------------------------------

    /**
     * Set any required vault file arguments.
     *
     * @param  array $arguments  A specific list of arguments to set
     * @param  array $vaultData  A raw dataset from the vault file (YAML)
     *
     * @return ConfigurationVaultInterface
     */
    protected function setVaultDataArguments(array $arguments, array $vaultData)
    {
        foreach ($arguments as $argument) {
            true === $this->isVaultRecordEncrypted()
                ? $this->set($argument, $this->decrypt($vaultData[$argument]))
                : $this->set($argument, $vaultData[$argument]);
        }

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Get environment account type settings.
     *
     * @return ConfigurationVaultInterface
     */
    protected function setEnvironmentAccountType()
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

    // --------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function loadVaultSettingsFile()
    {
        $this->setProperty(
            'resultDataSet',
            $this->yaml->deserialize($this->filesystem->read($this->vaultSettingsDirectory . '/' . $this->vaultFilename))
        );

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function setRecordProperties($release, $environment, $account)
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

    // --------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function setAccountRoot($value)
    {
        $this->setProperty('theAccountRootPath', rtrim($value, '/'));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function setVaultFilename($value)
    {
        $filename = false !== strpos($value, 'configuration-settings')
            ? strtolower(trim($value, '/ ')) . '.yml'
            : 'configuration-settings-' . strtolower(trim($value, '/ ')) . '.yml';

        $this->setProperty('vaultFilename', $filename);

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function setVaultFileRequestedSection($requestedSection = null)
    {
        $this->isString($requestedSection)
            ? $this->setProperty('vaultFileRequestedSection', trim($requestedSection))
            : $this->setProperty('vaultFileRequestedSection', null);

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function setVaultSettingsDirectory($value)
    {
        $this->setProperty('vaultSettingsDirectory', rtrim($value, '/'));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Method implementations inserted.
     *
     * The notation below illustrates visibility: (+) @api, (-) protected or private.
     *
     * @method all();
     * @method init();
     * @method get($key);
     * @method has($key);
     * @method version();
     * @method getClassName();
     * @method getConst($key);
     * @method set($key, $value);
     * @method isString($str);
     * @method getInstanceCount();
     * @method getClassInterfaces();
     * @method __call($callback, $parameters);
     * @method getProperty($name, $key = null);
     * @method doesFunctionExist($functionName);
     * @method isStringKey($str, array $keys);
     * @method throwExceptionError(array $error);
     * @method setProperty($name, $value, $key = null);
     * @method throwInvalidArgumentExceptionError(array $error);
     */
    use ServiceFunctions;
}
