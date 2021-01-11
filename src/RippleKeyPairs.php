<?php
/**
 * User: Lessmore92
 * Date: 1/6/2021
 * Time: 1:52 AM
 */

namespace Lessmore92\RippleKeypairs;

use Exception;
use Lessmore92\Buffer\Buffer;
use Lessmore92\RippleAddressCodec\RippleAddressCodec;

class RippleKeyPairs
{
    private $addressCodec;
    /**
     * @var Secp256k1
     */
    private $secp256k1;

    public function __construct()
    {
        $this->addressCodec = new RippleAddressCodec();
        $this->secp256k1    = new Secp256k1();
    }

    public function generateSeed(Buffer $entropy = null, $algorithm = null)
    {
        if (!is_null($entropy))
        {
            if ($entropy->getSize() < 16)
            {
                throw new Exception('entropy too short');
            }
        }
        else
        {
            $entropy = Buffer::hex(unpack('H*hex', random_bytes(16))['hex']);
        }

        $type = $algorithm === 'ed25519' ? 'ed25519' : 'secp256k1';
        return $this->addressCodec->encodeSeed($entropy, $type);
    }

    public function deriveKeypair(string $seed)
    {
        $decodeSeed = $this->addressCodec->decodeSeed($seed);

        $prefix     = '00';
        $privateKey = $prefix . strtoupper($this->secp256k1->derivePrivateKey($decodeSeed['bytes'])
                                                           ->toString(16, 64));

        $publicKey = $this->secp256k1->ec->keyFromPrivate(substr($privateKey, 2))
                                         ->getPublic(true, 'hex')
        ;
        return ['private' => strtoupper($privateKey), 'public' => strtoupper($publicKey)];
    }

    public function sign($message, string $privateKey)
    {
        $message = substr(hash('sha512', $message), 0, 64);
        $keypair = $this->secp256k1->ec->keyFromPrivate($privateKey);
        $sign    = $keypair->sign($message, ["canonical" => true]);

        $hex = array_map(function ($item) {
            return sprintf('%02X', $item);
        }, $sign->toDER());

        return strtoupper(join($hex));
    }

    public function verify($message, $signature, string $publicKey)
    {
        $message = substr(hash('sha512', $message), 0, 64);
        $keypair = $this->secp256k1->ec->keyFromPublic($publicKey, 'hex');
        return $keypair->verify($message, $signature);
    }

    public function deriveAddress($publicKey)
    {
        return $this->deriveAddressFromBytes(Buffer::hex($publicKey));
    }

    public function deriveAddressFromBytes(Buffer $bytes)
    {
        $hash = Utils::computePublicKeyHash($bytes);
        return $this->addressCodec->encodeAccountID($hash);
    }

    public function deriveNodeAddress($publicKey)
    {
        $generatorBytes     = $this->addressCodec->decodeNodePublic($publicKey);
        $accountPublicBytes = $this->secp256k1->accountPublicFromPublicGenerator($generatorBytes);
        return $this->deriveAddressFromBytes(Buffer::hex($accountPublicBytes));
    }

    public function decodeSeed(string $seed)
    {
        return $this->addressCodec->decodeSeed($seed);
    }
}
