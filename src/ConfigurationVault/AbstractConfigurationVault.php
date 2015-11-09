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

use Carbon\Carbon;
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
 * @method ConfigurationVaultInterface __construct();
 * @method void __destruct();
 * @method Boolean isVaultFileReadable();
 * @method Boolean isVaultRecordEncrypted();
 * @method ConfigurationVaultInterface setHashKey();
 * @method ConfigurationVaultInterface setCipherKey();
 * @method ConfigurationVaultInterface setVaultFilename($value);
 * @method ConfigurationVaultInterface setVaultRecordEncrypted($value = true);
 * @method string decrypt($encryptedString);
 * @method ConfigurationVaultInterface setInitializationVector();
 * @method string readRawVaultFileDataToResultDataSet();
 * @method ConfigurationVaultInterface openVaultFile($vaultFilename = null, $vaultFileRequestedSection = null);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
abstract class AbstractConfigurationVault implements ConfigurationVaultInterface
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
     * @var    FilesystemInterface         $filesystem                  A FilesystemInterface instance
     * @var    YamlInterface               $yaml                        A YamlInterface instance
     * @var    string                      $vaultFilename               A requested configuration settings file
     * @var    string                      $vaultFileType               A configuration file type
     * @var    string                      $vaultRecordId               A configuration file record id
     * @var    string                      $vaultRecordUUID             A configuration file record uuid
     * @var    string                      $vaultRecordDate             A configuration file record date
     * @var    string                      $vaultRecordEncrypted        A status of record encryption
     * @var    array                       $vaultFileEnvironments       A list of provided categories
     * @var    string                      $vaultSettingsDirectory      A configuration directory location
     * @var    string                      $vaultFileDefaultSection     A default section
     * @var    string                      $vaultFileRequestedSection   A user requested section
     * @var    string                      $vaultFileDefaultEnvironment A default category
     * @var    array                       $hashKey                     A list of hash strings
     * @var    string                      $cipherKey                   A encryption key
     * @var    array                       $resultDataSet               A result data set
     * @var    array                       $storageRegister             A set of stored data elements
     * @static ConfigurationVaultInterface $instance                    A ConfigurationVaultInterface instance
     * @static integer                     $objectCount                 A ConfigurationVaultInterface instance count
     * @var    string                      $initializationVector        A primitive used for Cipher Block Chaining (CBC)
     */
    protected $filesystem                  = null;
    protected $yaml                        = null;
    protected $vaultFilename               = null;
    protected $vaultFileType               = null;
    protected $vaultRecordId               = null;
    protected $vaultRecordUUID             = null;
    protected $vaultRecordDate             = null;
    protected $vaultRecordEncrypted        = null;
    protected $vaultFileEnvironments       = array();
    protected $VAULT_SETTINGS_DIRECTORY    = null;
    protected $vaultFileDefaultSection     = null;
    protected $vaultFileRequestedSection   = null;
    protected $ACCOUNT_ROOT                = null;
    protected $vaultFileDefaultEnvironment = null;
    protected $hashKey                     = array();
    protected $cipherKey                   = null;
    protected $rsaPrivateKey1024           = null;
    protected $rsaPublicKey1024            = null;
    protected $resultDataSet               = array();
    protected $storageRegister             = array();
    protected static $instance             = null;
    protected static $objectCount          = 0;
    protected $initializationVector        = null;

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
     * Decrypt Rijndael-256 AES Data Encryption Cipher with Cipher Block Chaining (CBC).
     *
     * @param  string  $encryptedString  The data to decrypt
     *
     * @return string|bool  The decrypted data
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
     * @return bool
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

        unset($offset, $seed1, $seed2, $cnfKey);

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
        return is_readable($this->VAULT_SETTINGS_DIRECTORY . '/' . $this->vaultFilename);
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
        $encryptionFileArray = $this->yaml->deserialize(
            $this->filesystem->read($this->VAULT_SETTINGS_DIRECTORY . '/' . static::ENCRYPTION_SETTINGS_FILE)
        );

        $release     = $encryptionFileArray['type']; // encryption
        $environment = $encryptionFileArray['default_environment']; // private
        $account     = 'seed_hash'; // seed_hash
        $key         = 'key'; // key

        $this->setProperty('hashKey', $encryptionFileArray[$release][$environment][$account]['key']);

        unset($release, $environment, $account, $key, $encryptionFileArray);

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
        $encryptionFileArray = $this->yaml->deserialize(
            $this->filesystem->read($this->VAULT_SETTINGS_DIRECTORY . '/' . static::ENCRYPTION_SETTINGS_FILE)
        );

        $release        = $encryptionFileArray['type']; // encryption
        $environment    = $encryptionFileArray['default_environment']; // private
        $accountPrivate = 'rsa_private_1024'; // rsa_private_1024
        $accountPublic  = 'rsa_public_1024'; // rsa_public_1024
        $key            = 'key'; // key

        $this->setProperty('rsaPrivateKey1024', $encryptionFileArray[$release][$environment][$accountPrivate]['key']);
        $this->setProperty('rsaPublicKey1024', $encryptionFileArray[$release]['public'][$accountPublic]['key']);

        unset($release, $environment, $accountPrivate, $accountPublic, $key, $encryptionFileArray);

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

        $this->setProperty(
            'initializationVector',
            mb_substr(sha1(implode(array_slice($this->getProperty('hashKey'), 2, 2))), 0, $ivsize, static::CHARSET)
        );

        return $this;
    }

    // --------------------------------------------------------------------------

    /* Interface Implementations */

    // --------------------------------------------------------------------------

    /**
     * Set ConfigurationVault to encryption mode
     *
     * @return ConfigurationVaultInterface
     *
     * @api
     */
    public function readRawVaultFileDataToResultDataSet()
    {
        $this->setProperty(
            'resultDataSet',
            $this->yaml->deserialize($this->filesystem->read($this->VAULT_SETTINGS_DIRECTORY . '/' . $this->vaultFilename))
        );

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Get environment account type settings.
     *
     * @return array
     */
    protected function getEnvironmentAccountType()
    {
        /* File type [database] */
        $release = $this->getProperty('resultDataSet')['type'];

        /* Default Environment [production] | User may ask for different environment. */
        $environment = null !== $this->getProperty('vaultFileDefaultEnvironment')
            ? $this->getProperty('vaultFileDefaultEnvironment')
            : $this->getProperty('resultDataSet')['default_environment'];

        /* Specific section [webadmin] */
        $account = $this->getProperty('vaultFileRequestedSection');

        return [$release, $environment, $account];
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
        $this->setVaultFilename($vaultFilename);

        if ($this->isString($vaultFileRequestedSection)) {
            $this->setVaultFileRequestedSection($vaultFileRequestedSection);
        }

        /* Extract the raw YAML file into $this->resultDataSet array.*/
        $this->readRawVaultFileDataToResultDataSet();

        if (null !== $this->getProperty('vaultFileRequestedSection')) {
            list($release, $environment, $account) = $this->getEnvironmentAccountType();
            $this->setRecordProperties($release, $environment, $account);

            true === $this->getProperty('resultDataSet')['is_encrypted']
                ? $this->setVaultRecordEncrypted()
                : $this->setVaultRecordEncrypted(false);

            if ($this->isVaultRecordEncrypted()) {
                $this->setCipherKey();
            }

        } elseif (null !== $this->vaultFileDefaultEnvironment) {
            /* File type [database] */
            $release = $this->resultDataSet['type'];

            /* Default Environment [production] | User may ask for different environment. */
            $environment = null !== $this->vaultFileDefaultEnvironment
                ? $this->vaultFileDefaultEnvironment
                : $this->resultDataSet['default_environment'];

            $this->setProperty('resultDataSet', $this->resultDataSet[$release][$environment]);
        }

        $vaultData = $this->getProperty('resultDataSet');

        /* Removing the last four elements from the array */
        $args = array_slice(array_keys($vaultData), 0, count(array_keys($vaultData)) - 4);

        foreach ($args as $argument) {
            if ($this->isVaultRecordEncrypted() === true) {
                $this->set($argument, ('' === trim($vaultData[$argument])
                    ? null
                    : $this->decrypt($vaultData[$argument])));
            } else {
                $this->set($argument, ('' === $vaultData[$argument]
                    ? null
                    : $vaultData[$argument]));
            }
        }

        unset($cnfVault, $seed, $cnfKey, $vaultData, $offset, $args);

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
    public function setAccountRoot($value)
    {
        $this->setProperty('ACCOUNT_ROOT', rtrim($value, '/'));

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
    public function reset()
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
        $this->setProperty('ACCOUNT_ROOT', realpath(__DIR__ . '/../../../../../../../../../../'));

        return $this;
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
