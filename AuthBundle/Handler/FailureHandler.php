<?php

namespace Shf\AuthBundle\Handler;

use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Core\Event\AuthenticationFailureEvent;

/**
 * AuthenticationFailureHandler.
 *
 * @author Dev Lexik <dev@lexik.fr>
 */
class FailureHandler implements AuthenticationFailureHandlerInterface
{
    /**
     * @var EventDispatcherInterface
     */

    /**
     * @param EventDispatcherInterface $dispatcher
     */
    public function __construct($tokenStorage)
    {
        $this->tokenStorage = $tokenStorage;
    }
    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $data = array(
            'code' => $exception->getCode(),
            'message' => $exception->getMessage(),
        );

        $event = new AuthenticationFailureEvent($this->tokenStorage->getToken(), $exception);
        $event->setResponse(new JsonResponse($data, self::RESPONSE_CODE));

        return $event->getResponse();
    }
}
