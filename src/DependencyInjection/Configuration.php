<?php

namespace Wiser\SamlBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder('wiser_saml');

        $treeBuilder->getRootNode()
                ->children()
                    ->scalarNode('entity_id')->isRequired()->cannotBeEmpty()->end()
                    ->scalarNode('idp_url')->isRequired()->cannotBeEmpty()->end()
                    ->scalarNode('login_path')->defaultValue('saml_login')->end()
                    ->scalarNode('check_path')->defaultValue('saml_acs')->end()
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }

}