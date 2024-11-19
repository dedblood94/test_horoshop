<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use App\Security\User;

class BearerAuthenticator extends AbstractAuthenticator
{
    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): Passport
    {
        $authorizationHeader = $request->headers->get('Authorization');
        if (!$authorizationHeader || !str_starts_with($authorizationHeader, 'Bearer ')) {
            throw new AuthenticationException('No Bearer token provided');
        }

        $token = substr($authorizationHeader, 7);

        // Проверка токена и возврат соответствующего пользователя
        if ($token === 'Admin') {
            return new SelfValidatingPassport(new UserBadge('Admin', function ($token) {
                return new User('Admin', ['ROLE_ADMIN']);
            }));
        }

        if ($token === 'User') {
            return new SelfValidatingPassport(new UserBadge('User', function ($token) {
                return new User('User', ['ROLE_USER']);
            }));
        }

        throw new AuthenticationException('Invalid token');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?JsonResponse
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): JsonResponse
    {
        return new JsonResponse(['error' => 'Authentication failed: ' . $exception->getMessage()], 401);
    }
}
