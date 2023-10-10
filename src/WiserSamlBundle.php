<?php

namespace Wiser\SamlBundle;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationSuccessHandler;
use Wiser\SamlBundle\Security\SamlAuthenticationSuccessHandler;
use Wiser\SamlBundle\Security\SamlAuthenticator;
use Wiser\SamlBundle\Security\SamlLogoutSubscriber;

class WiserSamlBundle extends Bundle
{
}