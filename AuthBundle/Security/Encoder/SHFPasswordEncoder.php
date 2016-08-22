<?php

namespace AuthBundle\Security\Encoder;

use Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder;

class SHFPasswordEncoder extends MessageDigestPasswordEncoder
{
    const ALGO = 'sha512';
    const ITERATIONS = 1;

    public function encodePassword($raw, $salt)
    {
        if ($this->isPasswordTooLong($raw)) {
            throw new BadCredentialsException('Invalid password.');
        }

        if (!in_array(self::ALGO, hash_algos(), true)) {
            throw new \LogicException(sprintf('The algorithm "%s" is not supported.', self::ALGO));
        }

        $salted = $salt.$raw; // Make the salted password with Shiro used by CAS server.
        $digest = hash(self::ALGO, $salted, true);

        // "stretch" hash
        for ($i = 1; $i < self::ITERATIONS; ++$i) {
            $digest = hash(self::ALGO, $digest.$salted, true);
        }

        return bin2hex($digest);
    }
}
