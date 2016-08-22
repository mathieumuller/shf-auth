<?php

namespace AuthBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Security\Core\SecurityContext;
use AppBundle\Entity\Compte;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\ParamConverter;

class SecurityController extends Controller
{
    /**
     * @Route("/connexion", name="login", options={"expose": true})
     */
    public function loginAction(Request $request)
    {
        // If customer is logged, we redirect him
        if ($this->getUser()) {
            return $this->redirectLoginAction($request);
        }

        $session = $request->getSession();

        // get the login error if there is one
        if ($request->attributes->has(SecurityContext::AUTHENTICATION_ERROR)) {
            $error = $request->attributes->get(SecurityContext::AUTHENTICATION_ERROR);
        } else {
            $error = $session->get(SecurityContext::AUTHENTICATION_ERROR);
            $session->remove(SecurityContext::AUTHENTICATION_ERROR);
        }

        return $this->render('AuthBundle:security:login.html.twig', [
            // last username entered by the user
            'cas_login_url' => $this->get('shf.auth.configurator')->get('cas_login_url'),
            'last_username' => $session->get(SecurityContext::LAST_USERNAME),
            'error' => $error,
        ]);
    }

    /**
     * @Route("/acces-refuse/", name="access_denied", options={"expose": true})
     */
    public function accessDeniedAction(Request $request)
    {
        throw $this->createAccessDeniedException('Vous ne disposez pas des autorisations nécessaires pour accéder à ce contenu.');
    }

    /**
     * @Route("/switch-compte/{account}", name="switch_account")
     * @ParamConverter("account", class="AppBundle:Compte")
     */
    public function switchAccountAction(Compte $account, Request $request)
    {
        if (!$this->getUser()->getAccounts()->contains($account)) {
            throw new \Exception('You tried to cheat!!!');
        }
        $this->get('session')->set('account', $account);

        return $this->redirectLoginAction($request);
    }

    /**
     * @Route("/redirect-login", name="redirect_login")
     */
    public function redirectLoginAction(Request $request)
    {
        if ($this->container->get('shf.security_handler')->getAuthUser()->hasRole('ROLE_ADMIN')) {
            return $this->redirectToRoute($this->get('shf.auth.configurator')->get('route_login_success_admin'), [], 301);
        }

        return $this->redirectToRoute($this->get('shf.auth.configurator')->get('route_login_success_user'), [], 301);
    }
}
