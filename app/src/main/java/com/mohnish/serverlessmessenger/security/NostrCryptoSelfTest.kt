package com.mohnish.serverlessmessenger.security

import java.security.MessageDigest

object NostrCryptoSelfTest {

    fun run(): String {
        val keys = NostrCrypto.generateKeyPair()

        val message =
            MessageDigest
                .getInstance("SHA-256")
                .digest(
                    "serverless-messenger-test"
                        .toByteArray(Charsets.UTF_8)
                )

        val signature =
            NostrCrypto.sign(
                privateKey = keys.privateKey,
                message32 = message
            )

        check(keys.privateKey.size == 32)
        check(keys.publicKey.size == 32)
        check(signature.size == 64)

        check(
            NostrCrypto.verify(
                publicKey = keys.publicKey,
                message32 = message,
                signature = signature
            )
        ) {
            "Valid BIP-340 signature failed verification"
        }

        val tamperedMessage =
            message.copyOf().also {
                it[0] = (it[0].toInt() xor 1).toByte()
            }

        check(
            !NostrCrypto.verify(
                publicKey = keys.publicKey,
                message32 = tamperedMessage,
                signature = signature
            )
        ) {
            "Tampered message incorrectly verified"
        }

        return "NOSTR_CRYPTO_OK"
    }
}
