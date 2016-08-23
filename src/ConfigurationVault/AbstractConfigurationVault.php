<?php

/*
 * This file is part of the UCSDMath package.
 *
 * (c) 2015-2016 UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace UCSDMath\Configuration\ConfigurationVault;

use UCSDMath\Functions\ServiceFunctions;
use UCSDMath\Filesystem\FilesystemInterface;
use UCSDMath\Serialization\Yaml\YamlInterface;
use UCSDMath\Functions\ServiceFunctionsInterface;

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
 * (+) ConfigurationVaultInterface openVaultFile($vaultFilename, $requestedSection = null);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
abstract class AbstractConfigurationVault implements ConfigurationVaultInterface, ServiceFunctionsInterface
{
    /**
     * Constants.
     *
     * @var string VERSION The version number
     *
     * @api
     */
    const VERSION = '1.10.0';

    //--------------------------------------------------------------------------

    /**
     * Properties.
     *
     * @var    YamlInterface               $yaml                 The YamlInterface
     * @var    FilesystemInterface         $filesystem           The FilesystemInterface
     * @var    string                      $cipherKey            The encryption key
     * @var    array                       $hashKey              The list of hash strings
     * @var    array                       $resultDataSet        The result data set
     * @var    string                      $vaultFilename        The requested configuration settings file
     * @var    string                      $vaultFileType        The configuration file type
     * @var    string                      $vaultRecordId        The configuration file record id
     * @var    string                      $vaultRecordUUID      The configuration file record uuid
     * @var    string                      $vaultRecordDate      The configuration file record date
     * @var    string                      $rsaPublicKey1024     The public key
     * @var    string                      $rsaPrivateKey1024    The private key
     * @var    string                      $theAccountRootPath   The absolute path to the account root (e.g., not web root)
     * @var    string                      $initializationVector The primitive used for Cipher Block Chaining (CBC)
     * @var    string                      $vaultRecordEncrypted The status of record encryption
     * @var    array                       $vaultEnvironments    The list of provided categories
     * @var    string                      $vaultSettingsDir     The configuration directory location
     * @var    string                      $defaultSection       The default section
     * @var    string                      $requestedSection     The user requested section
     * @var    string                      $defaultEnvironment   The default category environment
     * @static ConfigurationVaultInterface $instance             The static instance ConfigurationVaultInterface
     * @static int                         $objectCount          The static count of ConfigurationVaultInterface
     * @var    array                       $storageRegister      The stored set of data structures used by this class
     */
    protected $yaml                 = null;
    protected $filesystem           = null;
    protected $cipherKey            = null;
    protected $environment          = null;
    protected $account              = null;
    protected $release              = null;
    protected $hashKey              = [];
    protected $resultDataSet        = [];
    protected $vaultFilename        = null;
    protected $vaultFileType        = null;
    protected $vaultRecordId        = null;
    protected $vaultRecordUUID      = null;
    protected $vaultRecordDate      = null;
    protected $rsaPublicKey1024     = null;
    protected $rsaPrivateKey1024    = null;
    protected $theAccountRootPath   = null;
    protected $initializationVector = null;
    protected $vaultRecordEncrypted = false;
    protected $vaultEnvironments    = [];
    protected $vaultSettingsDir     = null;
    protected $defaultSection       = null;
    protected $requestedSection     = null;
    protected $defaultEnvironment   = null;
    protected static $instance      = null;
    protected static $objectCount   = 0;
    protected $storageRegister      = [];

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
        $this->setProperty('filesystem', $filesystem)
            ->setProperty('yaml', $yaml)
                ->setVaultSettingsDirectory(realpath(__DIR__ . '/../../../../../../../../../../.external-configuration-settings'))
                    ->setAccountRoot(realpath(__DIR__ . '/../../../../../../../../../../'))
                        ->setHashKey()
                            ->setRsaPrivateKeys()
                                ->setInitializationVector();
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
     * @param bool $value The option to work with encrypted configuration data
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
     * Decrypt Rijndael-256 Data Encryption Cipher with Cipher Block Chaining (CBC).
     *
     * @param string $encryptedString The data to decrypt
     *
     * @return string The decrypted data
     */
    protected function decrypt(string $encryptedString, string $key = null): string
    {
        return trim(mcrypt_decrypt(
            MCRYPT_RIJNDAEL_256,
            (null === $key ? $this->getProperty('cipherKey') : $this->setCipherKey($key)->getProperty('cipherKey')),
            base64_decode($encryptedString),
            MCRYPT_MODE_CBC,
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
    protected function setCipherKey(string $key = null): ConfigurationVaultInterface
    {
        $offset = (int) substr($this->vaultRecordDate, -2) / 1; // 0-59 seconds for offset
        $seed1 = mb_substr(implode(array_slice($this->getProperty('hashKey'), 0, 2)), $offset, 32, static::CHARSET);
        $seed2 = $this->vaultRecordUUID;
        $cnfKey = null === $key ? mb_strtoupper(mb_substr(sha1($seed1 . $seed2), 0, 32, static::CHARSET), static::CHARSET) : $key;
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
        $encryptionFileArray = $this->yaml->deserialize($this->filesystem->read($this->vaultSettingsDir . '/' . static::ENCRYPTION_SETTINGS_FILE));
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
        $encryptionFileArray = $this->yaml->deserialize($this->filesystem->read($this->vaultSettingsDir . '/' . static::ENCRYPTION_SETTINGS_FILE));
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
        $ivSize = (int) mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC);
        $this->setProperty('initializationVector', mb_substr(sha1(implode(array_slice($this->getProperty('hashKey'), 2, 2))), 0, $ivSize, static::CHARSET));

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Open configuration file settings.
     *
     * @param string $vaultFilename             The specific configuration to open. (e.g., 'Database')
     * @param string $requestedSection The specific file section (e.g., 'webadmin')
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function openVaultFile(string $vaultFilename, string $requestedSection = null): ConfigurationVaultInterface
    {
        /* Extract the raw YAML file into array and store in $this->resultDataSet */
        $this->setVaultFilename($vaultFilename);
        $this->setVaultFileRequestedSection($requestedSection);
        $this->loadVaultSettingsFile();
        $this->setEnvironmentAccountType();

        if (null !== $this->getProperty('requestedSection')) {
            $this->setRecordProperties($this->release, $this->environment, $this->account);
            $this->setVaultRecordEncrypted($this->getProperty('resultDataSet')['is_encrypted']);
            $this->setCipherKey();
        } elseif (null !== $this->defaultEnvironment) {
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
     * @param array $arguments The specific list of arguments to set
     * @param array $vaultData The raw dataset from the vault file (YAML)
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
        $this->environment = null !== $this->getProperty('defaultEnvironment')
            ? $this->getProperty('defaultEnvironment')
            : $this->getProperty('resultDataSet')['default_environment'];

        /* Specific section [webadmin] */
        $this->account = $this->getProperty('requestedSection');

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
            $this->yaml->deserialize($this->filesystem->read($this->vaultSettingsDir . '/' . $this->vaultFilename))
        );

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Set the database record properties.
     *
     * @param string $release     The release collection type (e.g., 'database', 'account', 'smtp')
     * @param string $environment The operating environment (e.g., 'development', 'staging', 'production')
     * @param string $account     The specific section of data to open (e.g., 'webadmin', 'webuser', 'wwwdyn')
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
     * @param string $value The directory path to the account root (e.g., outside of web root)
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
     * @param string $value The vault file name to open (e.g., 'database', 'account', 'encryption')
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
     * @param string $requestedSection The default section name to pull from the vault file
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultFileRequestedSection(string $requestedSection = null): ConfigurationVaultInterface
    {
        $this->isString($requestedSection)
            ? $this->setProperty('requestedSection', trim($requestedSection))
            : $this->setProperty('requestedSection', null);

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Set the location of the vault directory (e.g., '/home/www/.external-configuration-settings/').
     *
     * @param string $value The default location path to the configuration settings directory
     *
     * @return ConfigurationVaultInterface The current instance
     *
     * @api
     */
    public function setVaultSettingsDirectory(string $value): ConfigurationVaultInterface
    {
        $this->setProperty('vaultSettingsDir', rtrim($value, '/'));

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Method implementations inserted:
     *
     * Method list: (+) @api, (-) protected or private visibility.
     *
     * (+) array all();
     * (+) object init();
     * (+) string version();
     * (+) bool isString($str);
     * (+) bool has(string $key);
     * (+) string getClassName();
     * (+) int getInstanceCount();
     * (+) array getClassInterfaces();
     * (+) mixed getConst(string $key);
     * (+) bool isValidUuid(string $uuid);
     * (+) bool isValidEmail(string $email);
     * (+) bool isValidSHA512(string $hash);
     * (+) mixed __call($callback, $parameters);
     * (+) bool doesFunctionExist($functionName);
     * (+) bool isStringKey(string $str, array $keys);
     * (+) mixed get(string $key, string $subkey = null);
     * (+) mixed getProperty(string $name, string $key = null);
     * (+) object set(string $key, $value, string $subkey = null);
     * (+) object setProperty(string $name, $value, string $key = null);
     * (-) Exception throwExceptionError(array $error);
     * (-) InvalidArgumentException throwInvalidArgumentExceptionError(array $error);
     */
    use ServiceFunctions;

    //--------------------------------------------------------------------------
}
