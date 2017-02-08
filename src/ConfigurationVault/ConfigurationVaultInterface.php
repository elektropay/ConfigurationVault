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
    public const DEFAULT_MIN_HASHIDS_LENGTH       = 30;
    public const DEFAULT_MIN_HASHIDS_MAP_STEPS    = 5;
    public const DEFAULT_ENCRYPTION_KEY_BYTE_SIZE = 32;
    public const VAULTED                          = '::privately-vaulted::';
    public const DEFAULT_VAULT_SIZE               = 50;
    public const THE_RAW_VAULT_DATA               = -68;

    //--------------------------------------------------------------------------
}
