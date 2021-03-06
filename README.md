# ConfigurationVault
<table border="0">
  <tr>
    <td width="300"><img height="240" width="290" alt="UCSDMath - Mathlink" src="https://github.com/ucsdmath/ConfigurationVault/blob/master/resource/img/configuration-vault.png"></td>
    <td><h3>A Development Project in PHP</h3><p><strong>UCSDMath</strong> provides a testing framework for general internal Intranet software applications for the UCSD, Department of Mathematics. This is used for development and testing only. [not for production]</p>
<table width="550"><tr><td width="120"><b>Travis CI</b></td><td width="250"><b>SensioLabs</b></td><td width="180"><b>Dependencies</b></td></tr><tr>
    <td width="120" align="center">
        <a href="https://travis-ci.org/ucsdmath/ConfigurationVault">
        <img src="https://travis-ci.org/ucsdmath/ConfigurationVault.svg?branch=master" style="float: left; margin: 0px 0px 10px 10px;"></a><br>
        <a href="https://www.codacy.com/app/ucsdmath-project/ConfigurationVault">
        <img src="https://api.codacy.com/project/badge/Grade/3d6afd20add84d1ea3d5b206ddf4dea6"></a><br>
        <a href="https://scrutinizer-ci.com/g/ucsdmath/ConfigurationVault/?branch=master">
        <img src="https://img.shields.io/scrutinizer/g/ucsdmath/ConfigurationVault.svg"></a>
    </td>
    <td width="250" align="center">
        <a href="https://insight.sensiolabs.com/projects/3c0c312e-c234-4844-86d3-46ca9fc5e856">
        <img src="https://insight.sensiolabs.com/projects/3c0c312e-c234-4844-86d3-46ca9fc5e856/big.png" style="float: right; margin: 0px 0px 10px 10px;" width="212" height="51"></a><br>
        <a href="https://travis-ci.org/ucsdmath/ConfigurationVault"><img src="https://img.shields.io/badge/PHP-%207.2%20Tested%20-33cc33.svg"></a>
    </td>
    <td width="180" align="center">
        <a href="https://codeclimate.com/github/ucsdmath/ConfigurationVault">
        <img src="https://codeclimate.com/github/ucsdmath/ConfigurationVault/badges/gpa.svg"></a><br>
        <a href="https://travis-ci.org/ucsdmath/ConfigurationVault">
        <img src="http://php7ready.timesplinter.ch/ucsdmath/ConfigurationVault/badge.svg"></a>
</td></tr></table>
</td></tr></table>
<table width="890"><tr>
    <td width="116" align="center"><b>Scrutinizer</b></td>
    <td width="122" align="center"><b>Latest</b></td>
    <td width="108" align="center"><b>PHP</b></td>
    <td width="150" align="center"><b>Usage</b></td>
    <td width="142" align="center"><b>Development</b></td>
    <td width="142" align="center"><b>Code Quality</b></td>
    <td width="110" align="center"><b>License</b></td>
</tr>
<tr>
    <td valign="top" width="116" align="center">
        <a href="https://scrutinizer-ci.com/g/ucsdmath/ConfigurationVault/build-status/master">
        <img src="https://scrutinizer-ci.com/g/ucsdmath/ConfigurationVault/badges/build.png?b=master"></a></td>
    <td valign="top" width="122" align="center">
        <a href="https://packagist.org/packages/ucsdmath/configuration-vault">
        <img src="https://poser.pugx.org/ucsdmath/configuration-vault/v/stable"></a></td>
    <td valign="top" width="108" align="center">
        <a href="https://php.net/">
        <img src="https://img.shields.io/badge/PHP-%3E%3D%207.1.3-8892BF.svg"></a></td>
    <td valign="top" width="150" align="center">
        <a href="https://packagist.org/packages/ucsdmath/configuration-vault">
        <img src="https://poser.pugx.org/ucsdmath/configuration-vault/downloads"></a></td>
    <td valign="top" width="142" align="center">
        <a href="https://packagist.org/packages/ucsdmath/configuration-vault">
        <img src="https://poser.pugx.org/ucsdmath/configuration-vault/v/unstable"></a></td>
    <td valign="top" width="142" align="center">
        <a href="https://scrutinizer-ci.com/g/ucsdmath/ConfigurationVault/?branch=master">
        <img src="https://scrutinizer-ci.com/g/ucsdmath/ConfigurationVault/badges/quality-score.png?b=master"></a></td>
    <td valign="top" width="110" align="center">
        <a href="https://packagist.org/packages/ucsdmath/configuration-vault">
        <img src="https://poser.pugx.org/ucsdmath/configuration-vault/license"></a></td>
</tr></table>

ConfigurationVault is a testing and development library only. This is not to be used in a production.
Many features of this component have not been developed but are planned for future implementation.  UCSDMath components are written to be adapters of great developments such as Symfony, Twig, Doctrine, etc. This is a learning and experimental library only.

## Best Practice

It is best to not hard-code database credentials into PHP files, especially PHP files served to the public. If PHP exposes raw PHP code to HTTP clients due to a bug or server misconfiguration, your database credentials are naked for the world to see. Instead, move your database credentials into a configuration file above the document root.

ConfigurationVault can allow database credentials and other sensitive information to be stored and retrieved in a way that scales well. Requesting a key name will return the associated array of information. The storage of the information can be placed anywhere on the server or system and is preferred to be placed outside of the web (i.e., document root) space. We wanted to add the option of decrypting information held in storage if required.

## What to use this for?
- database credentials
- system account credentials
- SMTP mail credentials
- other sensitive information not held in PHP files

Copy this software from:
- [Packagist.org](https://packagist.org/packages/ucsdmath/ConfigurationVault)
- [Github.com](https://github.com/ucsdmath/ConfigurationVault)

## Installation using [Composer](http://getcomposer.org/)
You can install the class ```ConfigurationVault``` with Composer and Packagist by
adding the ucsdmath/configuration-vault package to your composer.json file:

```
"require": {
    "php": "^7.1",
    "ucsdmath/configuration-vault": "dev-master"
},
```
Or you can add the class directly from the terminal prompt:

```bash
$ composer require ucsdmath/configuration-vault
```

## Usage

``` php
$vault = new \UCSDMath\ConfigurationVault\ConfigurationVault();
```

## Documentation

No documentation site available at this time.
<!-- [Check out the documentation](http://math.ucsd.edu/~deisner/documentation/ConfigurationVault/) -->

## Testing

``` bash
$ phpunit
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email deisner@ucsd.edu instead of using the issue tracker.

## Credits

- [Daryl Eisner](https://github.com/UCSDMath)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
