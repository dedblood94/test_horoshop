<?php

namespace App\Controller\v1\api\users;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/v1/api/users', name: 'v1_api_users_')]
class UserConroller extends AbstractController
{
    private $userRepository;
    private $entityManager;

    public function __construct(UserRepository $userRepository, EntityManagerInterface $entityManager)
    {
        $this->userRepository = $userRepository;
        $this->entityManager = $entityManager;
    }

    #[Route('', name: 'get_by_id', methods: ['GET'])]
    public function getUserById(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $id = $data['id'] ?? null;

        if (!$id || !is_numeric($id)) {
            return $this->json(['error' => 'Invalid or missing ID parameter'], 400);
        }

        $currentUser = $this->getUser();
        if (!$currentUser) {
            return $this->json(['error' => 'Access denied: user not authenticated'], 401);
        }

        $roles = $currentUser->getRoles();

        if (in_array('ROLE_USER', $roles)) {
                return $this->json(['error' => 'Access denied'], 403);
        } elseif (!in_array('ROLE_ADMIN', $roles)) {
            return $this->json(['error' => 'Access denied'], 403);
        }

        $user = $this->userRepository->find($id);
        if (!$user) {
            return $this->json(['error' => 'User not found'], 404);
        }

        return $this->json([
            'login' => $user->getLogin(),
            'phone' => $user->getPhone(),
        ]);
    }

    #[Route('', name: 'create', methods: ['POST'])]
    public function create(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        $errors = $this->validateUserData($data);
        if (!empty($errors)) {
            return $this->json(['errors' => $errors], 400);
        }

        $user = new User();
        $user->setLogin($data['login']);
        $user->setPassword(password_hash($data['pass'], PASSWORD_BCRYPT));
        $user->setPhone($data['phone']);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $this->json([
            'id' => $user->getId(),
            'login' => $user->getLogin(),
            'phone' => $user->getPhone(),
        ], 201);
    }

    #[Route('', name: 'update', methods: ['PUT'])]
    public function update(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $id = $data['id'] ?? null;

        if (!$id || !is_numeric($id)) {
            return $this->json(['error' => 'Invalid or missing ID parameter'], 400);
        }

        $user = $this->userRepository->find($id);
        if (!$user) {
            return $this->json(['error' => 'User not found'], 404);
        }

        $currentUser = $this->getUser();
        if (in_array('ROLE_USER', $currentUser->getRoles()) && $user->getId() !== $currentUser->getId()) {
            return $this->json(['error' => 'Access denied'], 403);
        }

        $errors = $this->validateUserData($data, [], $user->getId());
        if (!empty($errors)) {
            return $this->json(['errors' => $errors], 400);
        }

        $user->setLogin($data['login']);
        $user->setPassword(password_hash($data['pass'], PASSWORD_BCRYPT));
        $user->setPhone($data['phone']);

        $this->entityManager->flush();

        return $this->json([
            'id' => $user->getId(),
            'login' => $user->getLogin(),
            'phone' => $user->getPhone(),
        ]);
    }

    #[Route('', name: 'delete', methods: ['DELETE'])]
    public function delete(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $id = $data['id'] ?? null;

        if (!$id || !is_numeric($id)) {
            return $this->json(['error' => 'Invalid or missing ID parameter'], 400);
        }

        $user = $this->userRepository->find($id);
        if (!$user) {
            return $this->json(['error' => 'User not found'], 404);
        }

        $this->entityManager->remove($user);
        $this->entityManager->flush();

        return $this->json(['message' => 'User deleted successfully']);
    }

    private function validateUserData(array $data, array $excludeFields = [], ?int $excludeId = null): array
    {
        $errors = [];

        if (!in_array('login', $excludeFields)) {
            if (empty($data['login'])) {
                $errors['login'] = 'Login is required';
            } elseif (strlen($data['login']) > 8) {
                $errors['login'] = 'Login must be 8 characters or less';
            } elseif ($this->userRepository->isLoginTaken($data['login']) && $this->isNotSameUser($data['login'], 'login', $excludeId)) {
                $errors['login'] = 'Login already exists';
            }
        }

        if (!in_array('phone', $excludeFields)) {
            if (empty($data['phone'])) {
                $errors['phone'] = 'Phone is required';
            } elseif (strlen($data['phone']) > 8) {
                $errors['phone'] = 'Phone must be 8 characters or less';
            } elseif (!ctype_digit($data['phone'])) {
                $errors['phone'] = 'Phone must contain only digits';
            } elseif ($this->userRepository->isPhoneTaken($data['phone']) && $this->isNotSameUser($data['phone'], 'phone', $excludeId)) {
                $errors['phone'] = 'Phone already exists';
            }
        }

        if (!in_array('pass', $excludeFields)) {
            if (empty($data['pass'])) {
                $errors['pass'] = 'Password is required';
            } elseif (strlen($data['pass']) > 8) {
                $errors['pass'] = 'Password must be 8 characters or less';
            }
        }

        return $errors;
    }

    private function isNotSameUser(string $value, string $field, ?int $excludeId = null): bool
    {
        $user = $this->userRepository->findOneBy([$field => $value]);
        return $user && $user->getId() !== $excludeId;
    }
}