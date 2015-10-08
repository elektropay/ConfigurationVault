<?php/* * This file is part of the UCSDMath package. * * (c) UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu> * * For the full copyright and license information, please view the LICENSE * file that was distributed with this source code. */namespace UCSDMath\Configuration\ConfigurationVault;use UCSDMath\Filesystem\FilesystemInterface;use UCSDMath\Serialization\Yaml\YamlInterface;/** * ConfigurationVault is the default implementation of {@link ConfigurationVaultInterface} which * provides routine configuration-vault methods that are commonly used throughout the framework. * * @author Daryl Eisner <deisner@ucsd.edu> * * @api */class ConfigurationVault extends AbstractConfigurationVault implements ConfigurationVaultInterface{    /**     * Constants.     *     * @var string VERSION  A version number     *     * @api     */    const VERSION = '1.3.0';    // --------------------------------------------------------------------------    /**     * Properties.     */    // --------------------------------------------------------------------------    /**     * Constructor.     *     * @param FilesystemInterface  $filesystem A FilesystemInterface Interface instance     * @param YamlInterface        $yaml       A YamlInterface Interface instance     *     * @api     */    public function __construct(        FilesystemInterface $filesystem,        YamlInterface $yaml    ) {        parent::__construct($filesystem, $yaml);    }}