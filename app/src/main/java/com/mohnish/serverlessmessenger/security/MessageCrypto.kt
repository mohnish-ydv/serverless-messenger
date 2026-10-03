package com.mohnish.serverlessmessenger.security

import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class EncryptedMessagePacket(
    val id: String,
    val senderIdentityId: String,
    val recipientIdentityId: String,
    val senderAgreementPublicKey: String,
    val recipientAgreementPublicKey: String,
    val timestamp: Long,
    val nonce: String,
    val ciphertext: String,
    val signature: String
)

data class DecryptedMessage(
    val id: String,
    val senderIdentityId: String,
    val recipientIdentityId: String,
    val timestamp: Long,
    val text: String,
    val envelope: MessageEnvelope
)

object MessageCrypto {

    private const val AES_ALGORITHM = "AES/GCM/NoPadding"
    private const val ECDH_ALGORITHM = "ECDH"
    private const val HMAC_ALGORITHM = "HmacSHA256"

    fun encrypt(
        context: android.content.Context,
        text: String,
        recipientIdentityId: String,
        recipientAgreementPublicKeyBase64: String
    ): EncryptedMessagePacket {
        return encrypt(
            context = context,
            envelope = MessageEnvelope.text(text),
            recipientIdentityId = recipientIdentityId,
            recipientAgreementPublicKeyBase64 =
                recipientAgreementPublicKeyBase64
        )
    }

    fun encrypt(
        context: android.content.Context,
        envelope: MessageEnvelope,
        recipientIdentityId: String,
        recipientAgreementPublicKeyBase64: String
    ): EncryptedMessagePacket {

        val identity =
            DeviceIdentityManager.getOrCreate(context)

        val recipientPublicKey =
            decodePublicKey(
                recipientAgreementPublicKeyBase64
            )

        val sharedSecret =
            deriveSharedSecret(recipientPublicKey)

        val encryptionKey =
            deriveEncryptionKey(
                sharedSecret = sharedSecret,
                senderIdentityId = identity.identityId,
                recipientIdentityId = recipientIdentityId
            )

        val nonce =
            ByteArray(12).also {
                java.security.SecureRandom().nextBytes(it)
            }

        val cipher =
            Cipher.getInstance(AES_ALGORITHM)

        cipher.init(
            Cipher.ENCRYPT_MODE,
            encryptionKey,
            GCMParameterSpec(128, nonce)
        )

        val ciphertext =
            cipher.doFinal(
                envelope
                    .toJson()
                    .toByteArray(StandardCharsets.UTF_8)
            )

        val id =
            java.util.UUID.randomUUID().toString()

        val timestamp =
            System.currentTimeMillis()

        val encodedNonce =
            encode(nonce)

        val encodedCiphertext =
            encode(ciphertext)

        val packetData =
            canonicalPacket(
                id = id,
                senderIdentityId =
                    identity.identityId,
                recipientIdentityId =
                    recipientIdentityId,
                senderAgreementPublicKey =
                    identity.agreementPublicKeyBase64,
                recipientAgreementPublicKey =
                    recipientAgreementPublicKeyBase64,
                timestamp = timestamp,
                nonce = encodedNonce,
                ciphertext = encodedCiphertext
            )

        val signature =
            DeviceIdentityManager.sign(packetData)

        return EncryptedMessagePacket(
            id = id,
            senderIdentityId =
                identity.identityId,
            recipientIdentityId =
                recipientIdentityId,
            senderAgreementPublicKey =
                identity.agreementPublicKeyBase64,
            recipientAgreementPublicKey =
                recipientAgreementPublicKeyBase64,
            timestamp = timestamp,
            nonce = encodedNonce,
            ciphertext = encodedCiphertext,
            signature = encode(signature)
        )
    }

    fun decrypt(
        context: android.content.Context,
        packet: EncryptedMessagePacket
    ): DecryptedMessage {

        val identity =
            DeviceIdentityManager.getOrCreate(context)

        require(
            packet.senderIdentityId !=
                identity.identityId ||
                packet.recipientIdentityId ==
                    identity.identityId
        ) {
            "Message is not addressed to this device"
        }

        val peerAgreementPublicKey =
            if (
                packet.recipientIdentityId ==
                identity.identityId
            ) {
                packet.senderAgreementPublicKey
            } else {
                packet.recipientAgreementPublicKey
            }

        val peerPublicKey =
            decodePublicKey(
                peerAgreementPublicKey
            )

        val sharedSecret =
            deriveSharedSecret(peerPublicKey)

        val encryptionKey =
            deriveEncryptionKey(
                sharedSecret = sharedSecret,
                senderIdentityId =
                    packet.senderIdentityId,
                recipientIdentityId =
                    packet.recipientIdentityId
            )

        val nonce =
            decode(packet.nonce)

        val ciphertext =
            decode(packet.ciphertext)

        val cipher =
            Cipher.getInstance(AES_ALGORITHM)

        cipher.init(
            Cipher.DECRYPT_MODE,
            encryptionKey,
            GCMParameterSpec(128, nonce)
        )

        val plaintext =
            cipher.doFinal(ciphertext)

        val plaintextText =
            String(
                plaintext,
                StandardCharsets.UTF_8
            )

        /*
         * New messages contain a versioned JSON envelope.
         *
         * If parsing fails, this is an older v0.1 plaintext message.
         * Keeping that fallback means existing conversations remain
         * readable after upgrading the app.
         */
        val envelope =
            MessageEnvelope.fromJson(
                plaintextText
            ) ?: MessageEnvelope.text(
                plaintextText
            )

        return DecryptedMessage(
            id = packet.id,
            senderIdentityId =
                packet.senderIdentityId,
            recipientIdentityId =
                packet.recipientIdentityId,
            timestamp =
                packet.timestamp,
            text =
                envelope.text,
            envelope =
                envelope
        )
    }

    fun verifyPacket(
        packet: EncryptedMessagePacket,
        senderSigningPublicKeyBase64: String
    ): Boolean {

        return try {
            val publicKey =
                decodePublicKey(
                    senderSigningPublicKeyBase64
                )

            DeviceIdentityManager.verify(
                publicKey = publicKey,
                data = packetBytes(packet),
                signature = decode(packet.signature)
            )
        } catch (_: Exception) {
            false
        }
    }

    fun packetBytes(
        packet: EncryptedMessagePacket
    ): ByteArray {

        return canonicalPacket(
            id = packet.id,
            senderIdentityId =
                packet.senderIdentityId,
            recipientIdentityId =
                packet.recipientIdentityId,
            senderAgreementPublicKey =
                packet.senderAgreementPublicKey,
            recipientAgreementPublicKey =
                packet.recipientAgreementPublicKey,
            timestamp =
                packet.timestamp,
            nonce =
                packet.nonce,
            ciphertext =
                packet.ciphertext
        )
    }

    private fun deriveSharedSecret(
        peerPublicKey: PublicKey
    ): ByteArray {

        val agreement =
            KeyAgreement.getInstance(
                ECDH_ALGORITHM
            )

        agreement.init(
            DeviceIdentityManager
                .getAgreementPrivateKey()
        )

        agreement.doPhase(
            peerPublicKey,
            true
        )

        return agreement.generateSecret()
    }

    private fun deriveEncryptionKey(
        sharedSecret: ByteArray,
        senderIdentityId: String,
        recipientIdentityId: String
    ): SecretKeySpec {

        val context =
            "serverless-message-v1:" +
                senderIdentityId +
                ":" +
                recipientIdentityId

        val mac =
            Mac.getInstance(
                HMAC_ALGORITHM
            )

        mac.init(
            SecretKeySpec(
                sharedSecret,
                HMAC_ALGORITHM
            )
        )

        val key =
            mac.doFinal(
                context.toByteArray(
                    StandardCharsets.UTF_8
                )
            )

        return SecretKeySpec(
            key.copyOf(32),
            "AES"
        )
    }

    private fun canonicalPacket(
        id: String,
        senderIdentityId: String,
        recipientIdentityId: String,
        senderAgreementPublicKey: String,
        recipientAgreementPublicKey: String,
        timestamp: Long,
        nonce: String,
        ciphertext: String
    ): ByteArray {

        return (
            "serverless-message-v1:" +
                id + ":" +
                senderIdentityId + ":" +
                recipientIdentityId + ":" +
                senderAgreementPublicKey + ":" +
                recipientAgreementPublicKey + ":" +
                timestamp + ":" +
                nonce + ":" +
                ciphertext
            ).toByteArray(
                StandardCharsets.UTF_8
            )
    }

    private fun decodePublicKey(
        value: String
    ): PublicKey {

        val bytes =
            java.util.Base64
                .getDecoder()
                .decode(value)

        return KeyFactory
            .getInstance("EC")
            .generatePublic(
                X509EncodedKeySpec(bytes)
            )
    }

    private fun encode(
        bytes: ByteArray
    ): String {

        return java.util.Base64
            .getEncoder()
            .encodeToString(bytes)
    }

    private fun decode(
        value: String
    ): ByteArray {

        return java.util.Base64
            .getDecoder()
            .decode(value)
    }
}
