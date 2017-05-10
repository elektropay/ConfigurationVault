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

/**
 * ServiceSupportOperations is the default implementation of {@link ServiceSupportOperationsInterface} which
 * provides routine ConfigurationVault methods that are commonly used in the framework.
 *
 * {@link ServiceSupportOperations} is a trait method implimentation requirement used in this framework.
 * This set is specifically used in ConfigurationVault classes.
 *
 *    use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\ServiceSupportOperations;
 *    use UCSDMath\Configuration\ConfigurationVault\ExtendedOperations\ServiceSupportOperationsInterface;
 *
 * ServiceSupportOperations provides a common set of implementations where needed. The ServiceSupportOperations
 * trait and the ServiceSupportOperationsInterface should be paired together.
 *
 * Method list: (+) @api, (-) protected or private visibility.
 *
 * (+) string getUuid(bool $isUpper = true);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
trait ServiceSupportOperations
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
     * Return a unique v4 UUID (requires: ^PHP7).
     *
     * Generate random block of data and change the individual byte positions.
     * Decided not to use mt_rand() as a number generator (experienced collisions).
     *
     * According to RFC 4122 - Section 4.4, you need to change the following
     *    1) time_hi_and_version (bits 4-7 of 7th octet),
     *    2) clock_seq_hi_and_reserved (bit 6 & 7 of 9th octet)
     *
     * All of the other 122 bits should be sufficiently random.
     * {@see http://tools.ietf.org/html/rfc4122#section-4.4}
     *
     * @param bool $isUpper The option to modify case [upper, lower]
     *
     * @return string The random UUID4
     *
     * @api
     */
    public function getUuid(bool $isUpper = true): string
    {
        /* Generate from PHP 7 Secure Random Generator */
        $data = random_bytes(16);
        assert(strlen($data) === 16);
        $data[6] = chr(ord($data[6]) & static::CLEAR_VERSION | static::UUID4_VERSION);
        $data[8] = chr(ord($data[8]) & static::CLEAR_VARIANT | static::RFC_BIT_SIZE);

        return true === $isUpper
            ? strtoupper(vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4)))
            : vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    //--------------------------------------------------------------------------
}
