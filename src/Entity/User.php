<?php

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: '`user`')]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 8)]
    private ?string $login = null;

    #[ORM\Column(length: 256)]
    private ?int $phone = null;

    #[ORM\Column(length: 256)]
    private ?string $pass = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getLogin(): ?string
    {
        return $this->login;
    }

    public function setLogin(string $login): static
    {
        $this->login = $login;

        return $this;
    }

    public function getPhone(): ?int
    {
        return $this->phone;
    }

    /**
     * @return string|null
     */
    public function getPass(): ?string
    {
        return $this->pass;
    }
    public function setPhone(int $phone): static
    {
        $this->phone = $phone;

        return $this;
    }
    public function setPassword(string $pass): self
    {
        $this->pass = password_hash($pass, PASSWORD_BCRYPT);
        return $this;
    }
}
