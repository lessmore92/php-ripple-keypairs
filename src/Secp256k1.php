<?php
/**
 * User: Lessmore92
 * Date: 1/7/2021
 * Time: 12:58 PM
 */

namespace Lessmore92\RippleKeypairs;

use BN\BN;
use Elliptic\Curve\ShortCurve;
use Elliptic\Curve\ShortCurve\Point;
use Elliptic\EC;
use Exception;
use Lessmore92\Buffer\Buffer;

class Secp256k1
{
    public $ec;
    /**
     * @var ShortCurve $curve
     */
    private $curve;

    public function __construct()
    {
        $this->ec    = new EC('secp256k1');
        $this->curve = $this->ec->curve;
    }

    public function derivePrivateKey(Buffer $entropy)
    {
        $privateGen = $this->deriveScalar($entropy);

        /**
         * @var Point $publicGen
         */
        $publicGen = $this->curve->g->mul($privateGen);
        $pub       = Buffer::hex($publicGen->encode('hex', true));

        $private = $this->deriveScalar($pub, 0);
        $private = $private->add($privateGen)
                           ->mod($this->curve->n)
        ;
        return $private;
    }

    /**
     * @param $bytes
     * @param null $index
     * @return BN
     * @throws Exception
     */
    public function deriveScalar(Buffer $bytes, $index = null)
    {
        $_bytes = $bytes->getDecimal();
        $_bytes = array_map(function ($item) {
            return sprintf('%02X', $item);
        }, $_bytes);

        for ($i = 0; $i < 0xffffffff; $i++)
        {
            array_push($_bytes, sprintf('%08X', $i));

            if (!is_null($index))
            {
                array_push($_bytes, sprintf('%08X', $index));
            }
            $bytes       = array_map('hex2bin', $_bytes);
            $hash        = hash('sha512', join($bytes));
            $first256Bit = substr($hash, 0, 64);
            $bigNumber   = new BN($first256Bit, 16);

            if ($bigNumber->cmpn(0) > 0 && $bigNumber->cmp($this->curve->n) < 0)
            {
                return $bigNumber;
            }
        }

        throw new Exception('impossible unicorn ;)');
    }

    public function accountPublicFromPublicGenerator(Buffer $publicGenBytes)
    {
        $rootPubPoint = $this->curve->decodePoint($publicGenBytes->getBinary());
        $scalar       = $this->deriveScalar($publicGenBytes, 0);
        $point        = $this->curve->g->mul($scalar);
        $offset       = $rootPubPoint->add($point);
        return $offset->encodeCompressed('hex');
    }
}
