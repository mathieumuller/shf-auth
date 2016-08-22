<?php

namespace AuthBundle\Security\User;

use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\DependencyInjection\ContainerInterface as Container;
use AppBundle\Entity\Utilisateur;
use AppBundle\Entity\Association;
use AppBundle\Entity\Groupe;
use AppBundle\Entity\CompteAssociation;
use Doctrine\Common\Collections\ArrayCollection;

class UserProvider implements UserProviderInterface
{
    const ROLE_USER = 'ROLE_USER';
    const ROLE_ADMIN = 'ROLE_ADMIN';

    private $container;

    public function __construct(Container $container)
    {
        $this->container = $container;
    }

    /*
     * La variable $username ne représente pas véritablement le nom d'utilisateur.
     * Il s'agit de la propriété utilisée par Symfony permettant d'authentifier un utilisateur avec son mot de passe.
     * Dans notre cas, username contient soit l'email (connexion via CAS), soir son identifiant SIRE
     */
    public function loadUserByUsername($username)
    {
        $groupes = Utilisateur::GROUPES;

        // CAS authentication
        if (!is_numeric($username)) {
            if (!$utilisateur = $this->container->get('shf.utilisateur_manager')->findOneBy(['email' => $username, 'statut' => true])) {
                throw new \Exception($this->container->get('translator')->trans('user.login_failed'));
            }
        } else {
            // SIRE Authentication
        }

        if (count($utilisateur->getGroupes()) == 0) {
            throw new \Exception($this->container->get('translator')->trans('user.access_forbidden'));
        }

        $authUser = $this->copyUserValues($utilisateur);
        $authUser = $this->setUserAccounts($authUser, $utilisateur);
        $authUser = $this->setRolesAndGroups($authUser, $utilisateur);
        // CAS or SIRE authentication
        $authUser->setConnectedFrom(!is_numeric($username) ? 'cas' : 'sire');

        return $authUser;
    }

    public function refreshUser(UserInterface $authUser)
    {
        if (!$authUser instanceof UserInterface) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($authUser)));
        }

        return $this->loadUserByUsername($authUser->getUsername());
    }

    public function supportsClass($class)
    {
        return $class === 'AppBundle\Security\User\AuthUser';
    }

    protected function copyUserValues($user)
    {
        $authUser = new AuthUser();
        $authUser
            ->setId($user->getId())
            ->setEmail($user->getEmail())
            ->setUsername($user->getEmail())
            ->setSalt($user->getSel()) //Maybe not required with CAS
            ->setPassword($user->getMotDePasse()) //Maybe not required with CAS
            ->setEmailIsValid($user->emailIsValid())
            ->setValidationDate($user->getDateValidation())
        ;

        return $authUser;
    }

    protected function setUserAccounts($authUser, $user)
    {
        if ($compte = $user->getCompte()) {
            $authUser->addAccount($compte);
        }

        $associations = new ArrayCollection(array_merge(
            $user->getAnrAssociations()->toArray(),
            $user->getAreAssociations()->toArray()
        ));

        $associations->forAll(function ($idx, $association) use ($authUser) {
            $authUser->addAccount($association->getCompte());

            return $authUser;
        });

        if (!empty($sessionAccount = $this->container->get('session')->get('account'))) {
            $authUser->setSessionAccount($this->container->get('shf.compte_manager')->find($sessionAccount));
        } else {
            if (!$authUser->getAccounts()->isEmpty()) {
                $authUser->setSessionAccount($authUser->getAccounts()->first());
                $this->container->get('session')->set('account', $authUser->getSessionAccount()->getId());
            }
        }

        return $authUser;
    }

    protected function setRolesAndGroups($authUser, $user)
    {
        if ($user->hasGroup('utilisateur')) {
            $authUser->addRole(self::ROLE_USER)
                ->setSessionRole(self::ROLE_USER)
            ;
        }

        if ($user->hasGroup('admin')) {
            $authUser->removeRole(self::ROLE_USER)
                ->addRole(self::ROLE_ADMIN)
                ->setSessionRole(self::ROLE_ADMIN)
            ;
        }

        if (($account = $authUser->getSessionAccount()) instanceof CompteAssociation) {
            $type = $account->getAssociation()->getType();
            if ($type === Association::TYPE_ANR) {
                $groupKey = Groupe::GROUPE_ADMIN_ANR;
            } elseif ($type === Association::TYPE_ARE) {
                $groupKey = Groupe::GROUPE_ADMIN_ARE;
            }
            $authUser->addGroup($groupKey)
                ->addSessionGroup($groupKey)
            ;
        }

        foreach ($user->getGroupes() as $groupe) {
            $groupeKey = $groupe->getKey();
            if (!in_array($groupeKey, ['utilisateur', 'admin'])) {
                $authUser->addGroup($groupeKey);
                if ($authUser->getSessionGroups()->isEmpty()) {
                    $authUser->addSessionGroup($groupeKey);
                }
            }
        }

        return $authUser;
    }
}
