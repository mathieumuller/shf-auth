<?php

namespace AuthBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $casNode = $treeBuilder->root('auth');

        $casNode
            ->children()
                ->scalarNode('cas_login_url')->defaultValue('https://icas.shf.eu/cas-int/login?locale=fr')->end()
                ->scalarNode('cas_logout_url')->defaultValue('https://icas.shf.eu/cas-int/logout?locale=fr')->end()
                ->scalarNode('cas_validation_url')->defaultValue('https://icas.shf.eu/cas-int/serviceValidate')->end()
                ->scalarNode('route_login_success_user')->defaultValue('mouvements_utilisateur')->end()
                ->scalarNode('route_login_success_admin')->defaultValue('admin_comptes_list')->end()
           ->end();

        return $treeBuilder;
    }
}
