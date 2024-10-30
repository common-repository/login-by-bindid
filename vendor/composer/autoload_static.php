<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitbfa69205bf7fa82ad5914d248bbf1649
{
    public static $prefixLengthsPsr4 = array (
        'F' => 
        array (
            'Firebase\\JWT\\' => 13,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Firebase\\JWT\\' => 
        array (
            0 => __DIR__ . '/..' . '/firebase/php-jwt/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitbfa69205bf7fa82ad5914d248bbf1649::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitbfa69205bf7fa82ad5914d248bbf1649::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInitbfa69205bf7fa82ad5914d248bbf1649::$classMap;

        }, null, ClassLoader::class);
    }
}
