package com.mohnish.serverlessmessenger.security

import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.ec.CustomNamedCurves
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * BIP-340 Schnorr signing for Nostr's secp256k1 identity.
 *
 * This key is intentionally separate from DeviceIdentityManager:
 * - DeviceIdentityManager = P-256 Android Keystore identity
 * - NostrCrypto = secp256k1/BIP-340 rendezvous identity
 */
object NostrCrypto {

    private val curve: X9ECParameters =
        CustomNamedCurves.getByName("secp256k1")
            ?: error("secp256k1 curve unavailable")

    private val generator = curve.g
    private val order = curve.n

    private val secureRandom = SecureRandom()

    data class KeyPair(
        val privateKey: ByteArray,
        val publicKey: ByteArray
    )

    fun generateKeyPair(): KeyPair {
        val privateKey = ByteArray(32)

        while (true) {
            secureRandom.nextBytes(privateKey)

            val d = BigInteger(1, privateKey)

            if (d.signum() > 0 && d < order) {
                return KeyPair(
                    privateKey = privateKey.copyOf(),
                    publicKey = publicKey(privateKey)
                )
            }
        }
    }

    fun publicKey(privateKey: ByteArray): ByteArray {
        require(privateKey.size == 32)

        val d = BigInteger(1, privateKey)

        require(d.signum() > 0 && d < order) {
            "Invalid secp256k1 private key"
        }

        val point =
            generator.multiply(d).normalize()

        return to32Bytes(
            point.affineXCoord.toBigInteger()
        )
    }

    /**
     * BIP-340 Schnorr signature.
     *
     * The message must be exactly 32 bytes.
     */
    fun sign(
        privateKey: ByteArray,
        message32: ByteArray
    ): ByteArray {
        require(privateKey.size == 32)
        require(message32.size == 32)

        val d0 = BigInteger(1, privateKey)

        require(d0.signum() > 0 && d0 < order) {
            "Invalid secp256k1 private key"
        }

        val p0 =
            generator.multiply(d0).normalize()

        val px =
            to32Bytes(p0.affineXCoord.toBigInteger())

        val d =
            if (p0.affineYCoord.toBigInteger().testBit(0)) {
                order.subtract(d0)
            } else {
                d0
            }

        val auxRand = ByteArray(32)
        secureRandom.nextBytes(auxRand)

        val t =
            xor(
                to32Bytes(d),
                taggedHash("BIP0340/aux", auxRand)
            )

        val nonceInput =
            t + px + message32

        var k0 =
            BigInteger(
                1,
                taggedHash(
                    "BIP0340/nonce",
                    nonceInput
                )
            ).mod(order)

        require(k0.signum() != 0) {
            "BIP-340 nonce generation failed"
        }

        val r0 =
            generator.multiply(k0).normalize()

        val k =
            if (r0.affineYCoord.toBigInteger().testBit(0)) {
                order.subtract(k0)
            } else {
                k0
            }

        val rx =
            to32Bytes(r0.affineXCoord.toBigInteger())

        val e =
            BigInteger(
                1,
                taggedHash(
                    "BIP0340/challenge",
                    rx + px + message32
                )
            ).mod(order)

        val s =
            k.add(e.multiply(d)).mod(order)

        return rx + to32Bytes(s)
    }

    /**
     * Verify a BIP-340 signature.
     */
    fun verify(
        publicKey: ByteArray,
        message32: ByteArray,
        signature: ByteArray
    ): Boolean {
        if (publicKey.size != 32) return false
        if (message32.size != 32) return false
        if (signature.size != 64) return false

        return runCatching {
            val px = BigInteger(1, publicKey)
            val r = BigInteger(1, signature.copyOfRange(0, 32))
            val s = BigInteger(1, signature.copyOfRange(32, 64))

            val fieldPrime =
                curve.curve.field.characteristic

            if (px >= fieldPrime) return false
            if (r >= fieldPrime) return false
            if (s >= order) return false

            /*
             * Prefix 02 = compressed secp256k1 point with even Y.
             * BIP-340 public keys are x-only, so the even-Y representative
             * is the required point.
             */
            val compressedPublicKey =
                byteArrayOf(0x02) + publicKey

            val point =
                curve.curve
                    .decodePoint(compressedPublicKey)
                    .normalize()

            val e =
                BigInteger(
                    1,
                    taggedHash(
                        "BIP0340/challenge",
                        signature.copyOfRange(0, 32) +
                            publicKey +
                            message32
                    )
                ).mod(order)

            val rPoint =
                generator
                    .multiply(s)
                    .add(
                        point.multiply(
                            order.subtract(e)
                        )
                    )
                    .normalize()

            if (rPoint.isInfinity) return false

            if (
                rPoint.affineYCoord
                    .toBigInteger()
                    .testBit(0)
            ) {
                return false
            }

            rPoint.affineXCoord.toBigInteger() == r
        }.getOrDefault(false)
    }

    private fun taggedHash(
        tag: String,
        data: ByteArray
    ): ByteArray {
        val tagHash =
            sha256(tag.toByteArray(Charsets.UTF_8))

        return sha256(
            tagHash +
                tagHash +
                data
        )
    }

    private fun sha256(
        data: ByteArray
    ): ByteArray {
        return MessageDigest
            .getInstance("SHA-256")
            .digest(data)
    }

    private fun xor(
        a: ByteArray,
        b: ByteArray
    ): ByteArray {
        require(a.size == b.size)

        return ByteArray(a.size) { index ->
            (a[index].toInt() xor b[index].toInt()).toByte()
        }
    }

    private fun to32Bytes(
        value: BigInteger
    ): ByteArray {
        val raw = value.toByteArray()

        return when {
            raw.size == 32 -> raw

            raw.size == 33 &&
                raw[0].toInt() == 0 -> {
                raw.copyOfRange(1, 33)
            }

            raw.size < 32 -> {
                ByteArray(32 - raw.size) + raw
            }

            else -> {
                raw.copyOfRange(
                    raw.size - 32,
                    raw.size
                )
            }
        }
    }
}
