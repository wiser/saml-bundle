<?php

namespace Wiser\SamlBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\DependencyInjection\ConfigurableExtension;
use Wiser\SamlBundle\EventListener\Security\SamlLogoutSubscriber;
use Wiser\SamlBundle\Security\Http\Authenticator\SamlAuthenticator;

class WiserSamlExtension extends ConfigurableExtension
{
    protected function loadInternal(array $mergedConfig, ContainerBuilder $container): void
    {
        $loader = new YamlFileLoader($container, new FileLocator(dirname(__DIR__).'/Resources/config'));
        $loader->load('services.yaml');

        $definition = $container->getDefinition(SamlAuthenticator::class);
        $definition->addArgument($mergedConfig['entity_id']);
        $definition->addArgument($mergedConfig['idp_url']);
        $definition->addArgument($mergedConfig['login_path']);
        $definition->addArgument($mergedConfig['check_path']);

        $definition = $container->getDefinition(SamlLogoutSubscriber::class);
        $definition->addArgument($mergedConfig['entity_id']);
        $definition->addArgument($mergedConfig['idp_url']);
    }
}