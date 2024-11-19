<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<User>
 */
class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findById(int $id): ?User
    {
        return $this->find($id);
    }

    public function save(User $user, bool $flush = true): void
    {
        $this->_em->persist($user);
        if ($flush) {
            $this->_em->flush();
        }
    }

    public function delete(User $user, bool $flush = true): void
    {
        $this->_em->remove($user);
        if ($flush) {
            $this->_em->flush();
        }
    }

    public function isLoginTaken(string $login): bool
    {
        return $this->findOneBy(['login' => $login]) !== null;
    }

    public function isPhoneTaken(string $phone): bool
    {
        return $this->findOneBy(['phone' => $phone]) !== null;
    }

    public function isPasswordTaken(string $pass): bool
    {
        return $this->findOneBy(['pass' => $pass]) !== null;
    }

    public function isPasswordHashTaken(string $hashedPassword): bool
    {
        $users = $this->createQueryBuilder('u')
            ->select('u.pass')
            ->getQuery()
            ->getResult();

        foreach ($users as $user) {
            if (password_verify($hashedPassword, $user['pass'])) {
                return true;
            }
        }

        return false;
    }
}
