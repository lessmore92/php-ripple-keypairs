<?php
/**
 * User: Lessmore92
 * Date: 1/7/2021
 * Time: 12:58 PM
 */

namespace Lessmore92\RippleKeypairs;

use Lessmore92\Buffer\Buffer;

class Utils
{
    public static function computePublicKeyHash(Buffer $publicKeyBytes)
    {
        $hash160 = hash('ripemd160', hash('sha256', $publicKeyBytes->getBinary(), true));
        return Buffer::hex($hash160);
    }
}
