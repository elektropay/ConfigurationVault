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

use UCSDMath\Filesystem\Filesystem;
use UCSDMath\Serialization\Yaml\Yaml;
use UCSDMath\Configuration\ConfigurationVault\ConfigurationVault;

require('/home/link/public_html/sso/1/assets/php/vendor/autoload.php');

/**
 * A function for opening ConfigurationVault information in GLOBAL namespace.
 *
 *    Example:
 *    $configVault = openConfigVault();
 *    $host     = $configVault->get('database_host');
 *    $username = $configVault->get('database_username');
 *    $password = $configVault->get('database_password');
 *    $database = $configVault->get('database_name');
 *    $arrayAll = $configVault->all();
 *
 * @param string $designator  The configVault designator (e.g.,'webadmin','webuser')
 * @param string $account     The configVault account type (e.g.,'Database','SMTP')
 *
 * @return The current ConfigurationVault instance
 *
 * @api
 */
function openConfigVault(string $designator = 'webadmin', string $account = 'Database')
{
    $configVault = new ConfigurationVault(new Filesystem(), new Yaml());
    $configVault->reset()->openVaultFile($account, $designator);

    return $configVault;
}
