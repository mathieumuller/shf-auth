<?php

namespace   AuthBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;

class AuthExtension extends Extension implements PrependExtensionInterface
{
    public function prepend(ContainerBuilder $container)
    {
        $configs = $container->getExtensionConfig($this->getAlias());
        $config = $this->processConfiguration(new Configuration(), $configs);

        $bundles = $container->getParameter('kernel.bundles');
        //prepend assetic
        if (true === isset($bundles['BeSimpleSsoAuthBundle'])) {
            $this->configureBeSimpleSsoAuth($container, $config);
        }
        $container->setParameter('be_simple.sso_auth.client.option.curlopt_ssl_verifypeer.value', false);
        $container->setParameter('be_simple.sso_auth.client.option.curlopt_sslversion.value', 'CURL_SSLVERSION_TLSv1');
    }

    public function configureBeSimpleSsoAuth(ContainerBuilder $container, $config)
    {
        $casmanager = [
            'protocol' => ['id' => 'cas', 'version' => 2],
            'server' => ['id' => 'cas', 'login_url' => $config['cas_login_url'], 'logout_url' => $config['cas_logout_url'], 'validation_url' => $config['cas_validation_url']],
        ];

        foreach ($container->getExtensions() as $name => $extension) {
            switch ($name) {
                case 'be_simple_sso_auth':
                    $container->prependExtensionConfig($name, ['cas_manager' => $casmanager]);
                    break;
                default:
                    break;
            }
        }
    }

    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);
        $loader = new YamlFileLoader(
            $container,
            new FileLocator(__DIR__.'/../Resources/config')
        );

        $loader->load('services.yml');
        $configuratorDefinition = $container->getDefinition('shf.auth.configurator');
        $configuratorDefinition->addMethodCall('setConfig', [$config]);
        $container->setParameter('be_simple.sso_auth.client.option.curlopt_ssl_verifypeer.value', false);
        $container->setParameter('be_simple.sso_auth.client.option.curlopt_sslversion.value', 'CURL_SSLVERSION_TLSv1');
    }
}
