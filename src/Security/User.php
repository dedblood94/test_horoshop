<?php
namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;

 class User implements UserInterface
{
    private $username;
    private $roles;

    public function __construct(string $username, array $roles)
    {
        $this->username = $username;
        $this->roles = $roles;
    }
    public function getUserIdentifier(): string
    {
         return $this->username;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function eraseCredentials()
    {

    }
}
