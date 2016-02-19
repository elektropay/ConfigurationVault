# ConfigurationVault
<table border="0">
  <tr>
    <td width="310"><img height="160" width="310"alt="UCSDMath - Mathlink" src="https://github.com/ucsdmath/Testing/blob/master/ucsdmath-logo.png"></td>
    <td><h3>A Development Project in PHP</h3>
        <p><strong>UCSDMath</strong> provides a testing framework for general internal Intranet software applications for the UCSD, Department of Mathematics. This is used for development and testing only. [not for production]</p>
    </td>
  </tr>
</table>
---
[![Latest Stable Version](https://poser.pugx.org/ucsdmath/configuration-vault/v/stable)](https://packagist.org/packages/ucsdmath/configuration-vault)
[![License](https://poser.pugx.org/ucsdmath/configuration-vault/license)](https://packagist.org/packages/ucsdmath/configuration-vault)
[![Total Downloads](https://poser.pugx.org/ucsdmath/configuration-vault/downloads)](https://packagist.org/packages/ucsdmath/configuration-vault)
[![Latest Unstable Version](https://poser.pugx.org/ucsdmath/configuration-vault/v/unstable)](https://packagist.org/packages/ucsdmath/configuration-vault)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/ucsdmath/ConfigurationVault/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/ucsdmath/ConfigurationVault/?branch=master)
[![Build Status](https://scrutinizer-ci.com/g/ucsdmath/ConfigurationVault/badges/build.png?b=master)](https://scrutinizer-ci.com/g/ucsdmath/ConfigurationVault/build-status/master)

ConfigurationVault is a testing and development library only. This is not to be used in a production.

## Installation using [Composer](http://getcomposer.org/)
You can install the class ```ConfigurationVault``` with Composer and Packagist by
adding the ucsdmath/configuration-vault package to your composer.json file:

```
"require": {
    "php": "^7.0",
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
