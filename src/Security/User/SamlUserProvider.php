<?php

namespace Wiser\SamlBundle\Security\User;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class SamlUserProvider implements UserProviderInterface
{
    /**
     * @inheritDoc
     */
    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        return new SamlUser($identifier);
    }

    /**
     * @inheritDoc
     */
    public function loadUserByUsername(string $username): UserInterface
    {
        return $this->loadUserByIdentifier($username);
    }

    /**
     * @inheritDoc
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        return $user;
    }

    /**
     * @inheritDoc
     */
    public function supportsClass(string $class): bool
    {
        return $class === SamlUser::class;
    }
}