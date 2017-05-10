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
 * ServiceSupportOperationsInterface is the interface implemented by all ConfigurationVault classes.
 *
 * Method list: (+) @api.
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 *
 * @api
 */
interface ServiceSupportOperationsInterface
{
    /**
     * Constants.
     *
     * @var string CLEAR_VERSION The UUID specification clears bits 12-15 of version byte (15: 0000 1111)
     * @var string UUID4_VERSION The UUID choice to generate version 4 (64: 0100 0000)
     * @var string CLEAR_VARIANT The UUID clearing all relevant bits of variant byte with AND (63: 0011 1111)
     * @var string RFC_BIT_SIZE  The UUID required bit size of 128 for the UUID v.4 (RFC 4122) (128: 1000 0000)
     */
    public const CLEAR_VERSION = 0x0f;
    public const UUID4_VERSION = 0x40;
    public const CLEAR_VARIANT = 0x3f;
    public const RFC_BIT_SIZE  = 0x80;

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
    public function getUuid(bool $isUpper = true): string;

    //--------------------------------------------------------------------------
}
