<?php

namespace Wiser\SamlBundle\Security\User;

use InvalidArgumentException;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class SamlUser implements UserInterface, EquatableInterface
{
    private string $userIdentifier;

    private array $roles;

    private string $lastName;

    private string $firstName;

    private string $displayName;

    private string $emailAddress;

    private array $extraFields;

    public function __construct(string $userIdentifier, array $roles = [])
    {
        $this->userIdentifier = $userIdentifier;
        $this->roles = $roles;
    }

    public function __toString(): string
    {
        return $this->getUserIdentifier();
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getPassword(): ?string
    {
        return null;
    }

    public function getSalt(): ?string
    {
        return null;
    }

    /**
     * Returns the identifier for this user (e.g. its username or email address).
     */
    public function getUserIdentifier(): string
    {
        return $this->userIdentifier;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials(): void
    {
    }

    public function getUsername(): string
    {
        return $this->displayName;
    }

    public function setExtraFields(array $extraFields): SamlUser
    {
        $this->extraFields = $extraFields;

        return $this;
    }

    public function getExtraFields(): array
    {
        return $this->extraFields;
    }

    public function getLastName(): string
    {
        return $this->lastName;
    }

    public function setLastName(string $lastName): SamlUser
    {
        $this->lastName = $lastName;
        return $this;
    }

    public function getFirstName(): string
    {
        return $this->firstName;
    }

    public function setFirstName(string $firstName): SamlUser
    {
        $this->firstName = $firstName;
        return $this;
    }

    public function getDisplayName(): string
    {
        return $this->displayName;
    }

    public function setDisplayName(string $displayName): SamlUser
    {
        $this->displayName = $displayName;
        return $this;
    }

    public function getEmailAddress(): string
    {
        return $this->emailAddress;
    }

    public function setEmailAddress(string $emailAddress): SamlUser
    {
        $this->emailAddress = $emailAddress;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function isEqualTo(UserInterface $user): bool
    {
        if (!$user instanceof self) {
            return false;
        }

        if ($this->getPassword() !== $user->getPassword()) {
            return false;
        }

        if ($this->getSalt() !== $user->getSalt()) {
            return false;
        }

        $currentRoles = array_map('strval', $this->getRoles());
        $newRoles = array_map('strval', (array) $user->getRoles());
        $rolesChanged = count($currentRoles) !== count($newRoles) || count($currentRoles) !== count(array_intersect($currentRoles, $newRoles));
        if ($rolesChanged) {
            return false;
        }

        if ($this->getUserIdentifier() !== $user->getUserIdentifier()) {
            return false;
        }

        return true;
    }
}
