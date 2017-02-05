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
 * VaultServiceMethods provides a common set of implementations where needed. The VaultServiceMethods
 * trait and the VaultServiceMethodsInterface should be paired together.
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
trait VaultServiceMethods
{
    /**
     * Properties.
     */

    //--------------------------------------------------------------------------

    /**
     * Abstract Method Requirements.
     */

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
     * Set the core seed hash as an array
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setCoreSeedHashArray(): ConfigurationVaultInterface
    {
        /* type: encryption, default_environment: private */
        list($release, $environment) = [ $this->encryptionSettingsRawData['type'], $this->encryptionSettingsRawData['default_environment']];
        list($hash, $uuid, $date) = [
            join($this->encryptionSettingsRawData[$release][$environment]['core_seed_hash']['data']),
            trim($this->encryptionSettingsRawData[$release][$environment]['core_seed_hash']['uuid']),
            trim($this->encryptionSettingsRawData[$release][$environment]['core_seed_hash']['date'])
        ];
        list(, $time) = explode(' ', $date);
        list($hours, $minutes, $seconds) = array_map('intval', explode(':', $time));

        return $this
            ->setProperty('coreSeedHashArray', $hash, 'hash')
                ->setProperty('coreSeedHashArray', $hours, 'hours')
                    ->setProperty('coreSeedHashArray', $minutes, 'minutes')
                        ->setProperty('coreSeedHashArray', $seconds, 'seconds')
                            ->setProperty('coreSeedHashArray', $uuid, 'uuid');
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
        list($release, $environment) = [ $this->encryptionSettingsRawData['type'], $this->encryptionSettingsRawData['default_environment']];
        list($hash, $uuid, $date, $map) = [
            join($this->encryptionSettingsRawData[$release][$environment]['initialization_vector']['data']),
            trim($this->encryptionSettingsRawData[$release][$environment]['initialization_vector']['uuid']),
            trim($this->encryptionSettingsRawData[$release][$environment]['initialization_vector']['date']),
            join($this->encryptionSettingsRawData[$release][$environment]['initialization_vector']['map'])
        ];
        list(, $time) = explode(' ', $date);
        list($hours, $minutes, $seconds) = array_map('intval', explode(':', $time));

        return $this
            ->setProperty('initializationVectorArray', $hash, 'hash')
                ->setProperty('initializationVectorArray', $map, 'map')
                    ->setProperty('initializationVectorArray', $hours, 'hours')
                        ->setProperty('initializationVectorArray', $minutes, 'minutes')
                            ->setProperty('initializationVectorArray', $seconds, 'seconds')
                                ->setProperty('initializationVectorArray', $uuid, 'uuid');
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
        list($release, $environment) = [ $this->encryptionSettingsRawData['type'], $this->encryptionSettingsRawData['default_environment']];
        list($hash, $uuid, $date) = [
            join($this->encryptionSettingsRawData[$release][$environment]['primary_hash']['data']),
            trim($this->encryptionSettingsRawData[$release][$environment]['primary_hash']['uuid']),
            trim($this->encryptionSettingsRawData[$release][$environment]['primary_hash']['date'])
        ];
        list(, $time) = explode(' ', $date);
        list($hours, $minutes, $seconds) = array_map('intval', explode(':', $time));

        return $this
            ->setProperty('primaryHashArray', $hash, 'hash')
                ->setProperty('primaryHashArray', $hours, 'hours')
                    ->setProperty('primaryHashArray', $minutes, 'minutes')
                        ->setProperty('primaryHashArray', $seconds, 'seconds')
                            ->setProperty('primaryHashArray', $uuid, 'uuid');
    }

    //--------------------------------------------------------------------------

    /**
     * Render the Ambit string.
     *
     * @param string $payload The string being encrypted
     *
     * @return string Returns the Ambit
     */
    protected function renderAmbit(string $payload): array
    {
        list($dataSize, $ivSalt, $keySalt) = [
            $this->stringSize($payload),
            $this->getRandomInt(),
            $this->getRandomInt()
        ];

        return [
            'hash'     => $this->hashids->encode([$dataSize, $ivSalt, $keySalt]),
            'dataSize' => $dataSize,
            'ivSalt'   => $ivSalt,
            'keySalt'  => $keySalt
        ];
    }

    //--------------------------------------------------------------------------

    /**
     * Hashids encode.
     *
     * @param int|string|array $numerical The numerical integer or array to encoded
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
     * Set the RSA Private and Public Keys.
     *
     * @return ConfigurationVaultInterface The current instance
     */
    protected function setRsaPublicPrivateKeys(): ConfigurationVaultInterface
    {
        list($release, $environment) = [
            $this->encryptionSettingsRawData['type'], // encryption
            $this->encryptionSettingsRawData['default_environment'] // private
        ];

        return $this
            ->setProperty(
                'rsaPrivateKey4096',
                $this->encryptionSettingsRawData[$release][$environment]['private_key_4096']['data']
            )
            ->setProperty(
                'rsaPublicKey4096',
                $this->encryptionSettingsRawData[$release][$environment]['public_key_4096']['data']
            );
    }



    //--------------------------------------------------------------------------
}
