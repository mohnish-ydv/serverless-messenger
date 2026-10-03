package com.mohnish.serverlessmessenger.security

import android.util.Base64
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

object SignalingCrypto {

    private const val VERSION = 1
    private const val KEY_SIZE_BYTES = 32
    private const val IV_SIZE_BYTES = 12
    private const val TAG_SIZE_BITS = 128

    private const val DOMAIN =
        "serverless-messenger-signaling-v1"

    fun encrypt(
        senderIdentityId: String,
        recipientIdentityId: String,
        recipientAgreementPublicKeyBase64: String,
        plaintext: String
    ): String {
        val peerPublicKey =
            decodePublicKey(recipientAgreementPublicKeyBase64)

        val sharedSecret =
            deriveSharedSecret(peerPublicKey)

        val key =
            deriveKey(
                sharedSecret = sharedSecret,
                senderIdentityId = senderIdentityId,
                recipientIdentityId = recipientIdentityId
            )

        val iv =
            Random.nextBytes(IV_SIZE_BYTES)

        val aad =
            canonicalAad(
                senderIdentityId,
                recipientIdentityId
            )

        val cipher =
            Cipher.getInstance("AES/GCM/NoPadding")

        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(TAG_SIZE_BITS, iv)
        )

        cipher.updateAAD(
            aad.toByteArray(StandardCharsets.UTF_8)
        )

        val ciphertext =
            cipher.doFinal(
                plaintext.toByteArray(StandardCharsets.UTF_8)
            )

        return JSONObject()
            .put("version", VERSION)
            .put("sender_identity_id", senderIdentityId)
            .put("recipient_identity_id", recipientIdentityId)
            .put(
                "iv",
                Base64.encodeToString(
                    iv,
                    Base64.NO_WRAP
                )
            )
            .put(
                "ciphertext",
                Base64.encodeToString(
                    ciphertext,
                    Base64.NO_WRAP
                )
            )
            .toString()
    }

    fun decrypt(
        recipientIdentityId: String,
        senderIdentityId: String,
        senderAgreementPublicKeyBase64: String,
        envelope: String
    ): String? {
        return try {
            val json =
                JSONObject(envelope)

            if (
                json.optInt("version", 0) != VERSION
            ) {
                return null
            }

            val envelopeSender =
                json.optString("sender_identity_id")

            val envelopeRecipient =
                json.optString("recipient_identity_id")

            if (
                envelopeSender != senderIdentityId ||
                envelopeRecipient != recipientIdentityId
            ) {
                return null
            }

            val peerPublicKey =
                decodePublicKey(
                    senderAgreementPublicKeyBase64
                )

            val sharedSecret =
                deriveSharedSecret(peerPublicKey)

            val key =
                deriveKey(
                    sharedSecret = sharedSecret,
                    senderIdentityId = senderIdentityId,
                    recipientIdentityId = recipientIdentityId
                )

            val iv =
                Base64.decode(
                    json.getString("iv"),
                    Base64.NO_WRAP
                )

            val ciphertext =
                Base64.decode(
                    json.getString("ciphertext"),
                    Base64.NO_WRAP
                )

            if (iv.size != IV_SIZE_BYTES) {
                return null
            }

            val aad =
                canonicalAad(
                    senderIdentityId,
                    recipientIdentityId
                )

            val cipher =
                Cipher.getInstance("AES/GCM/NoPadding")

            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(TAG_SIZE_BITS, iv)
            )

            cipher.updateAAD(
                aad.toByteArray(StandardCharsets.UTF_8)
            )

            String(
                cipher.doFinal(ciphertext),
                StandardCharsets.UTF_8
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun deriveSharedSecret(
        peerPublicKey: PublicKey
    ): ByteArray {
        val agreement =
            KeyAgreement.getInstance("ECDH")

        agreement.init(
            DeviceIdentityManager.getAgreementPrivateKey()
        )

        agreement.doPhase(
            peerPublicKey,
            true
        )

        return agreement.generateSecret()
    }

    private fun deriveKey(
        sharedSecret: ByteArray,
        senderIdentityId: String,
        recipientIdentityId: String
    ): ByteArray {
        val material =
            buildString {
                append(DOMAIN)
                append(":")
                append(senderIdentityId)
                append(":")
                append(recipientIdentityId)
                append(":")
            }.toByteArray(StandardCharsets.UTF_8)

        val digest =
            MessageDigest.getInstance("SHA-256")

        digest.update(material)
        digest.update(sharedSecret)

        return digest.digest()
            .copyOf(KEY_SIZE_BYTES)
    }

    private fun canonicalAad(
        senderIdentityId: String,
        recipientIdentityId: String
    ): String =
        "$DOMAIN:$senderIdentityId:$recipientIdentityId"

    private fun decodePublicKey(
        value: String
    ): PublicKey {
        val encoded =
            Base64.decode(
                value,
                Base64.DEFAULT
            )

        val factory =
            KeyFactory.getInstance("EC")

        return factory.generatePublic(
            X509EncodedKeySpec(encoded)
        )
    }
}
