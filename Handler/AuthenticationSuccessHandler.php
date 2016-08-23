<?php

namespace Shf\AuthBundle\Handler;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Logout\LogoutSuccessHandlerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\RouterInterface;
use Doctrine\ORM\EntityManager;
use Shf\AuthBundle\Security\User\UserProvider;
use Shf\AuthBundle\Service\Configurator;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Custom authentication success handler.
 */
class AuthenticationSuccessHandler implements AuthenticationSuccessHandlerInterface, LogoutSuccessHandlerInterface
{
    private $router;
    private $authorizationChecker;
    private $configurator;

    /**
     * Constructor.
     *
     * @param RouterInterface $router
     * @param EntityManager   $em
     */
    public function __construct(RouterInterface $router, $tokenStorage, $eventDispatcher, UserProvider $userProvider, $authorizationChecker, Configurator $configurator)
    {
        $this->router = $router;
        $this->tokenStorage = $tokenStorage;
        $this->eventDispatcher = $eventDispatcher;
        $this->userProvider = $userProvider;
        $this->authorizationChecker = $authorizationChecker;
        $this->configurator = $configurator;
    }

    /**
     * This is called when an interactive authentication attempt succeeds. This
     * is called by authentication listeners inheriting from AbstractAuthenticationListener.
     *
     * @param Request        $request
     * @param TokenInterface $token
     *
     * @return Response The response to return
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        $authUser = $this->tokenStorage->getToken()->getUser();

        $authUser->eraseCredentials();

        if (!empty($request->getSession()->get('redirect_to_payment'))) {
            $route = $request->getSession()->get('redirect_to_payment');
            $request->getSession()->remove('redirect_to_payment');

            return new RedirectResponse($route);
        }

        if (!empty($request->getSession()->get('redirect_to_fcs'))) {
            $url = $this->router->generate('link_fcs_account');

            return new RedirectResponse($url);
        }

        return new RedirectResponse($this->router->generate('redirect_login'));
    }

    public function onLogoutSuccess(Request $request)
    {
        $response = new RedirectResponse($this->configurator->get('cas_logout_url').'&service='.$this->router->generate('login', [], UrlGeneratorInterface::ABSOLUTE_URL));

        return $response;
    }
}
