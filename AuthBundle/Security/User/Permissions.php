<?php

namespace AuthBundle\Security\User;

use AppBundle\Entity\Role;
use AppBundle\Entity\Groupe;
use AppBundle\Entity\Compte;

class Permissions
{
    protected $role;
    protected $group;
    protected $account;

    public function hasRole($role)
    {
        return $role == $this->role;
    }

    public function hasGroup($group)
    {
        if ($this->hasRole(UserProvider::ROLE_ADMIN)) {
            return true;
        }

        return $group instanceof Groupe ? $group == $this->group : $this->group->getKey() == strtolower($group);
    }

    /**
     * Gets the value of role.
     *
     * @return mixed
     */
    public function getRole()
    {
        return $this->role;
    }

    /**
     * Sets the value of role.
     *
     * @param mixed $role the role
     *
     * @return self
     */
    public function setRole($role)
    {
        $this->role = $role;

        return $this;
    }

    /**
     * Gets the value of group.
     *
     * @return mixed
     */
    public function getGroup()
    {
        return $this->group;
    }

    /**
     * Sets the value of group.
     *
     * @param mixed $group the group
     *
     * @return self
     */
    public function setGroup($group)
    {
        $this->group = $group;

        return $this;
    }

    /**
     * Gets the value of account.
     *
     * @return mixed
     */
    public function getAccount()
    {
        return $this->account;
    }

    /**
     * Sets the value of account.
     *
     * @param mixed $account the account
     *
     * @return self
     */
    public function setAccount(Compte $account)
    {
        $this->account = $account;

        return $this;
    }
}
