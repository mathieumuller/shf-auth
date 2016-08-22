<?php

namespace AuthBundle\Service;

use Symfony\Component\Security\Core\Encoder\EncoderFactory;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use AppBundle\Entity\Utilisateur;
use AppBundle\Security\User\AuthUser;

class SecurityHandler
{
    protected $tokenStorage;
    protected $router;
    protected $encoderFactory;
    protected $requestStack;
    protected $eventDispatcher;
    protected $userProvider;

    public function __construct($tokenStorage, $router, EncoderFactory $encoderFactory, $requestStack, $eventDispatcher, $userProvider)
    {
        $this->tokenStorage = $tokenStorage;
        $this->router = $router;
        $this->encoderFactory = $encoderFactory;
        $this->requestStack = $requestStack;
        $this->eventDispatcher = $eventDispatcher;
        $this->userProvider = $userProvider;
    }

    public function getAuthUser()
    {
        if (null === $token = $this->tokenStorage->getToken()) {
            return;
        }

        if (!is_object($user = $token->getUser())) {
            // e.g. anonymous authentication
            return;
        }

        return $user;
    }

    public function loadAuthUser(Utilisateur $utilisateur)
    {
        return $this->userProvider->loadUserByUsername($utilisateur->getEmail());
    }

    public function recreateUserToken(AuthUser $user, $password = null)
    {
        $token = new \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken($user, $password, 'main', $user->getRoles());
        $this->tokenStorage->setToken($token);

        return $token;
    }

    public function getEncodedPassword($rawPwd, $salt)
    {
        $encoder = $this->encoderFactory->getEncoder(new AuthUser());
        $encodedPassword = $encoder->encodePassword($rawPwd, $salt);

        return $encodedPassword;
    }

    public function generateSalt()
    {
        return base64_encode(uniqid(mt_rand(), true));
    }

    public function logUser(AuthUser $user)
    {
        $token = $this->recreateUserToken($user);

        $request = $this->requestStack->getCurrentRequest();
        $event = new InteractiveLoginEvent($request, $token);

        $this->eventDispatcher->dispatch('security.interactive_login', $event);
    }

    public function isPasswordValid(Utilisateur $utilisateur, $rawPwd)
    {
        $encoder = $this->encoderFactory->getEncoder(new AuthUser());

        return $encoder->isPasswordValid($utilisateur->getMotDePasse(), $rawPwd, $utilisateur->getSel());
    }
}
