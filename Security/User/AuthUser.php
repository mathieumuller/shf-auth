<?php

namespace Shf\AuthBundle\Security\User;

use AppBundle\Entity\Compte;
use AppBundle\Entity\Groupe;
use Symfony\Component\Security\Core\User\AdvancedUserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Doctrine\Common\Collections\ArrayCollection;

class AuthUser implements AdvancedUserInterface, EquatableInterface, \Serializable
{
    protected $id;
    protected $fullName;
    protected $username;
    protected $email;
    protected $password;
    protected $salt;
    protected $connectedFrom;
    protected $validationDate;
    protected $roles;
    protected $groups;
    protected $emailIsValid;
    protected $accounts;
    protected $sessionAccount;
    protected $sessionRole;
    protected $sessionGroups;

    public function __construct()
    {
        $this->accounts = new ArrayCollection();
        $this->roles = [];
        $this->groups = new ArrayCollection();
        $this->sessionGroups = new ArrayCollection();
    }

    /**
     * Returns the name to display for the user.
     *
     * @return string
     */
    public function getDisplayName()
    {
        if ($this->sessionAccount) {
            $type = $this->sessionAccount->getType();
            if (in_array($type, [Compte::TYPE_ASSOCIATION, Compte::TYPE_PRO])) {
                return $this->sessionAccount->getRaisonSociale();
            } elseif ($type === Compte::TYPE_PARTICULIER) {
                return $this->sessionAccount->getPrenom().' '.$this->sessionAccount->getNom();
            } else {
                throw new \Exception('Unknown account type');
            }
        } else {
            return $this->username;
        }
    }

    /**
     * Erase the user credentials.
     */
    public function eraseCredentials()
    {
        $this->setPassword(null);
        $this->setSalt(null);
    }

    public function isAdmin()
    {
        return $this->hasRole(UserProvider::ROLE_ADMIN);
    }
    public function isANRAdmin()
    {
        return $this->hasGroup(Groupe::GROUPE_ADMIN_ANR);
    }
    public function isAREAdmin()
    {
        return $this->hasGroup(Groupe::GROUPE_ADMIN_ARE);
    }

    public function isAccountNonExpired()
    {
        return true;
    }

    public function isAccountNonLocked()
    {
        return true;
    }

    public function isCredentialsNonExpired()
    {
        return true;
    }

    public function isEnabled()
    {
        return true;
    }

    public function serialize()
    {
        return serialize(array(
            $this->id,
            $this->password,
            $this->username,
            $this->fullName,
            $this->email,
            $this->validationDate,
            $this->roles,
            $this->emailIsValid,
        ));
    }

    public function unserialize($serialized)
    {
        list(
            $this->id,
            $this->password,
            $this->username,
            $this->fullName,
            $this->email,
            $this->validationDate,
            $this->roles,
            $this->emailIsValid) = unserialize($serialized);
    }

    public function isEqualTo(UserInterface $user)
    {
        return $this->getUsername() === $user->getUsername();
    }

    /**
     * Get user available roles.
     *
     * @return ArrayCollection
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * Adds a role to user roles.
     *
     * @param string $role
     *
     * @return AuthUser
     */
    public function addRole($role)
    {
        if (!in_array($role, $this->roles)) {
            $this->roles[] = $role;
        }

        return $this;
    }

    /**
     * Removes a role to user roles.
     *
     * @param string $role
     *
     * @return AuthUser
     */
    public function removeRole($role)
    {
        if ($key = array_search($role, $this->roles)) {
            unset($this->roles[$key]);
        }

        return $this;
    }

    /**
     * Check if user has a role.
     *
     * @param string $role
     *
     * @return bool
     */
    public function hasRole($role)
    {
        return in_array($role, $this->roles);
    }

    /**
     * Get user available groups.
     *
     * @return ArrayCollection
     */
    public function getGroups()
    {
        return $this->groups;
    }

    /**
     * Adds a group to user groups.
     *
     * @param string $group
     *
     * @return AuthUser
     */
    public function addGroup($group)
    {
        if (!$this->groups->contains($group)) {
            $this->groups->add($group);
        }

        return $this;
    }

    /**
     * Removes a group to user groups.
     *
     * @param string $group
     *
     * @return AuthUser
     */
    public function removeGroup($group)
    {
        $this->groups->removeElement($group);

        return $this;
    }

    public function isAdhesionManager()
    {
        return $this->hasGroup([Groupe::GROUPE_ADMIN, Groupe::GROUPE_ADMIN_ANR, Groupe::GROUPE_ADMIN_ARE]);
    }

    public function isAssociationAdministrator()
    {
        return !$this->isAdmin() && $this->hasGroup([Groupe::GROUPE_ADMIN_ANR, Groupe::GROUPE_ADMIN_ARE]);
    }

    /**
     * Check if user has a group or all given groups.
     *
     * @param string $group
     *
     * @return bool
     */
    public function hasGroup($groupes, $strict = false)
    {
        // The super admin is considered has having all groups
        if ($this->hasRole(UserProvider::ROLE_ADMIN)) {
            return true;
        }
        if ($groupes instanceof ArrayCollection) {
            $groupes = $groupes->toArray();
        }
        if (!is_array($groupes)) {
            $groupes = [$groupes];
        }

        $userGroups = $this->sessionGroups;
        $count = 0;

        foreach ($groupes as $grp) {
            if ($userGroups->contains($grp)) {
                ++$count;
            }
        }

        return $strict ? $count == $groupes->count() : $count > 0;
    }

    /**
     * Get user available accounts.
     *
     * @return ArrayCollection
     */
    public function getAccounts()
    {
        return $this->accounts;
    }

    /**
     * Adds a group to user accounts.
     *
     * @param Compte $account
     *
     * @return AuthUser
     */
    public function addAccount(Compte $account)
    {
        if (!$this->accounts->contains($account)) {
            $this->accounts->add($account);
        }

        return $this;
    }

    /**
     * Removes a account to user accounts.
     *
     * @param Compte $account
     *
     * @return AuthUser
     */
    public function removeAccount(Compte $account)
    {
        $this->accounts->removeElement($account);

        return $this;
    }

    /**
     * Check if user has an account.
     *
     * @return bool
     */
    public function hasAccount()
    {
        return !$this->accounts->isEmpty();
    }

    /**
     * Get the name of the user.
     *
     * @return string
     */
    public function getFullName()
    {
        return $this->fullName;
    }

    /**
     * Set the name of the user.
     *
     * @return AuthUser
     */
    public function setFullName($fullName)
    {
        $this->fullName = $fullName;

        return $this;
    }

    /**
     * Gets the value of username.
     *
     * @return mixed
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Sets the value of username.
     *
     * @param mixed $username the username
     *
     * @return self
     */
    public function setUsername($username)
    {
        $this->username = $username;

        return $this;
    }

    /**
     * Gets the value of id.
     *
     * @return mixed
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Sets the value of id.
     *
     * @param mixed $id the id
     *
     * @return self
     */
    public function setId($id)
    {
        $this->id = $id;

        return $this;
    }

    /**
     * Gets the value of email.
     *
     * @return mixed
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * Sets the value of email.
     *
     * @param mixed $email the email
     *
     * @return self
     */
    public function setEmail($email)
    {
        $this->email = $email;

        return $this;
    }

    /**
     * Gets the value of password.
     *
     * @return mixed
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Sets the value of password.
     *
     * @param mixed $password the password
     *
     * @return self
     */
    public function setPassword($password)
    {
        $this->password = $password;

        return $this;
    }

    /**
     * Gets the value of salt.
     *
     * @return mixed
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * Sets the value of salt.
     *
     * @param mixed $salt the salt
     *
     * @return self
     */
    public function setSalt($salt)
    {
        $this->salt = $salt;

        return $this;
    }

    /**
     * Gets the value of connectedFrom.
     *
     * @return mixed
     */
    public function getConnectedFrom()
    {
        return $this->connectedFrom;
    }

    /**
     * Sets the value of connectedFrom.
     *
     * @param mixed $connectedFrom the connected from
     *
     * @return self
     */
    public function setConnectedFrom($connectedFrom)
    {
        $this->connectedFrom = $connectedFrom;

        return $this;
    }

    /**
     * Gets the value of validationDate.
     *
     * @return mixed
     */
    public function getValidationDate()
    {
        return $this->validationDate;
    }

    /**
     * Sets the value of validationDate.
     *
     * @param mixed $validationDate the validation date
     *
     * @return self
     */
    public function setValidationDate($validationDate)
    {
        $this->validationDate = $validationDate;

        return $this;
    }

    /**
     * Gets the value of emailIsValid.
     *
     * @return mixed
     */
    public function getEmailIsValid()
    {
        return $this->emailIsValid;
    }

    /**
     * Sets the value of emailIsValid.
     *
     * @param mixed $emailIsValid the email is valid
     *
     * @return self
     */
    public function setEmailIsValid($emailIsValid)
    {
        $this->emailIsValid = $emailIsValid;

        return $this;
    }

    /**
     * Gets the value of sessionAccount.
     *
     * @return mixed
     */
    public function getSessionAccount()
    {
        return $this->sessionAccount;
    }

    /**
     * Sets the value of sessionAccount.
     *
     * @param mixed $sessionAccount the session account
     *
     * @return self
     */
    public function setSessionAccount(Compte $sessionAccount)
    {
        $this->sessionAccount = $sessionAccount;

        return $this;
    }

    /**
     * Gets the value of sessionRole.
     *
     * @return mixed
     */
    public function getSessionRole()
    {
        return $this->sessionRole;
    }

    /**
     * Sets the value of sessionRole.
     *
     * @param mixed $sessionRole the session role
     *
     * @return self
     */
    public function setSessionRole($sessionRole)
    {
        $this->sessionRole = $sessionRole;

        return $this;
    }

    /**
     * Gets the value of sessionGroups.
     *
     * @return mixed
     */
    public function getSessionGroups()
    {
        return $this->sessionGroups;
    }

    /**
     * Adds a value of sessionGroups.
     *
     * @param mixed $sessionGroups the session groups
     *
     * @return self
     */
    public function addSessionGroup($sessionGroup)
    {
        if (!$this->sessionGroups->contains($sessionGroup)) {
            $this->sessionGroups->add($sessionGroup);
        }

        return $this;
    }

    /**
     * Removes a value of sessionGroups.
     *
     * @param mixed $sessionGroups the session groups
     *
     * @return self
     */
    public function removeSessionGroup($sessionGroup)
    {
        $this->sessionGroups->removeElement($sessionGroup);

        return $this;
    }
}
