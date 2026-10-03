package com.mohnish.serverlessmessenger.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

data class DeviceIdentity(
    val publicKey: PublicKey,
    val publicKeyBase64: String,
    val identityId: String,
    val agreementPublicKey: PublicKey,
    val agreementPublicKeyBase64: String,
    val nostrPublicKeyHex: String
)

data class IdentityInvite(
    val protocol: String,
    val version: Int,
    val identityId: String,
    val username: String,
    val publicKeyBase64: String,
    val agreementPublicKeyBase64: String,
    val nostrPublicKeyHex: String,
    val signatureBase64: String
)

object DeviceIdentityManager {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    private const val SIGNING_KEY_ALIAS =
        "serverless_device_identity"

    private const val AGREEMENT_KEY_ALIAS =
        "serverless_device_agreement"

    private const val PROTOCOL = "serverless"

    private const val VERSION = 4

    fun getOrCreate(
        context: Context
    ): DeviceIdentity {
        val keyStore = getKeyStore()

        if (!keyStore.containsAlias(SIGNING_KEY_ALIAS)) {
            generateSigningIdentity()
        }

        if (!keyStore.containsAlias(AGREEMENT_KEY_ALIAS)) {
            generateAgreementIdentity()
        }

        val signingCertificate =
            keyStore.getCertificate(SIGNING_KEY_ALIAS)
                ?: error("Signing identity certificate is missing")

        val agreementCertificate =
            keyStore.getCertificate(AGREEMENT_KEY_ALIAS)
                ?: error("Agreement identity certificate is missing")

        val publicKey = signingCertificate.publicKey
        val agreementPublicKey = agreementCertificate.publicKey

        val publicKeyBase64 =
            Base64.getEncoder().encodeToString(publicKey.encoded)

        val agreementPublicKeyBase64 =
            Base64.getEncoder().encodeToString(agreementPublicKey.encoded)

        val identityId =
            createIdentityId(publicKey.encoded)

        return DeviceIdentity(
            publicKey = publicKey,
            publicKeyBase64 = publicKeyBase64,
            identityId = identityId,
            agreementPublicKey = agreementPublicKey,
            agreementPublicKeyBase64 = agreementPublicKeyBase64,
            nostrPublicKeyHex =
                NostrIdentityManager.publicKeyHex(
                    NostrIdentityManager
                        .getOrCreate(context)
                        .publicKey
                )
        )
    }

    private fun canonicalIdentityData(
        identityId: String,
        username: String,
        publicKeyBase64: String,
        agreementPublicKeyBase64: String,
        nostrPublicKeyHex: String
    ): ByteArray {
        return "$PROTOCOL:v$VERSION:$identityId:$username:$publicKeyBase64:$agreementPublicKeyBase64:$nostrPublicKeyHex"
            .toByteArray(StandardCharsets.UTF_8)
    }

    suspend fun createInvitePayload(
        context: android.content.Context,
        username: String
    ): String {
        val cleanUsername = username.trim()

        require(
            cleanUsername.matches(
                Regex("[A-Za-z0-9_]{3,20}")
            )
        ) {
            "Invalid username"
        }

        val identity = getOrCreate(context)
        val nostrPublicKeyHex =
            identity.nostrPublicKeyHex

        val dataToSign = canonicalIdentityData(
            identityId = identity.identityId,
            username = cleanUsername,
            publicKeyBase64 = identity.publicKeyBase64,
            agreementPublicKeyBase64 =
                identity.agreementPublicKeyBase64,
            nostrPublicKeyHex = nostrPublicKeyHex
        )

        val signature = Signature.getInstance(
            "SHA256withECDSA"
        ).apply {
            initSign(getSigningPrivateKey())
            update(dataToSign)
        }.sign()

        val signatureBase64 =
            Base64.getEncoder().encodeToString(signature)

        return JSONObject().apply {
            put("protocol", PROTOCOL)
            put("version", VERSION)
            put("identity_id", identity.identityId)
            put("username", cleanUsername)
            put("public_key", identity.publicKeyBase64)
            put(
                "agreement_public_key",
                identity.agreementPublicKeyBase64
            )
            put("nostr_public_key", nostrPublicKeyHex)
            put("signature", signatureBase64)
        }.toString()
    }

    fun verifyInvitePayload(
        payload: String
    ): IdentityInvite {

        val json = JSONObject(payload)

        val protocol = json.getString("protocol")
        val version = json.getInt("version")
        val identityId = json.getString("identity_id")
        val username = json.getString("username")
        val publicKeyBase64 = json.getString("public_key")
        val agreementPublicKeyBase64 =
            json.getString("agreement_public_key")
        val nostrPublicKeyHex =
            json.getString("nostr_public_key")
        val signatureBase64 = json.getString("signature")

        require(protocol == PROTOCOL) {
            "Unsupported protocol"
        }

        require(version == VERSION) {
            "Unsupported protocol version"
        }

        require(
            username.matches(
                Regex("[A-Za-z0-9_]{3,20}")
            )
        ) {
            "Invalid username"
        }

        require(
            nostrPublicKeyHex.matches(
                Regex("[0-9a-fA-F]{64}")
            )
        ) {
            "Invalid Nostr public key"
        }

        val publicKeyBytes =
            Base64.getDecoder().decode(publicKeyBase64)

        val publicKey =
            KeyFactory.getInstance("EC")
                .generatePublic(
                    X509EncodedKeySpec(publicKeyBytes)
                )

        val calculatedIdentityId =
            createIdentityId(publicKey.encoded)

        require(calculatedIdentityId == identityId) {
            "Identity ID does not match public key"
        }

        val agreementKeyBytes =
            Base64.getDecoder()
                .decode(agreementPublicKeyBase64)

        val agreementPublicKey =
            KeyFactory.getInstance("EC")
                .generatePublic(
                    X509EncodedKeySpec(agreementKeyBytes)
                )

        val signatureBytes =
            Base64.getDecoder()
                .decode(signatureBase64)

        val validSignature =
            Signature.getInstance(
                "SHA256withECDSA"
            ).apply {
                initVerify(publicKey)
                update(
                    canonicalIdentityData(
                        identityId = identityId,
                        username = username,
                        publicKeyBase64 = publicKeyBase64,
                        agreementPublicKeyBase64 =
                            agreementPublicKeyBase64,
                        nostrPublicKeyHex =
                            nostrPublicKeyHex
                    )
                )
            }.verify(signatureBytes)

        require(validSignature) {
            "Invalid identity signature"
        }

        return IdentityInvite(
            protocol = protocol,
            version = version,
            identityId = identityId,
            username = username,
            publicKeyBase64 = publicKeyBase64,
            agreementPublicKeyBase64 =
                agreementPublicKeyBase64,
            nostrPublicKeyHex = nostrPublicKeyHex,
            signatureBase64 = signatureBase64
        )
    }

    fun sign(data: ByteArray): ByteArray {
        return Signature.getInstance(
            "SHA256withECDSA"
        ).apply {
            initSign(getSigningPrivateKey())
            update(data)
        }.sign()
    }

    fun verify(
        publicKey: PublicKey,
        data: ByteArray,
        signature: ByteArray
    ): Boolean {
        return Signature.getInstance(
            "SHA256withECDSA"
        ).apply {
            initVerify(publicKey)
            update(data)
        }.verify(signature)
    }

    fun getAgreementPrivateKey(): PrivateKey {
        val keyStore = getKeyStore()

        return keyStore.getKey(
            AGREEMENT_KEY_ALIAS,
            null
        ) as? PrivateKey
            ?: error("Agreement private key is missing")
    }

    private fun generateSigningIdentity() {
        val generator =
            KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE
            )

        generator.initialize(
            KeyGenParameterSpec.Builder(
                SIGNING_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or
                    KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(
                    ECGenParameterSpec("secp256r1")
                )
                .setDigests(
                    KeyProperties.DIGEST_SHA256
                )
                .build()
        )

        generator.generateKeyPair()
    }

    private fun generateAgreementIdentity() {
        val generator =
            KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE
            )

        generator.initialize(
            KeyGenParameterSpec.Builder(
                AGREEMENT_KEY_ALIAS,
                KeyProperties.PURPOSE_AGREE_KEY
            )
                .setAlgorithmParameterSpec(
                    ECGenParameterSpec("secp256r1")
                )
                .build()
        )

        generator.generateKeyPair()
    }

    private fun getSigningPrivateKey(): PrivateKey {
        val keyStore = getKeyStore()

        return keyStore.getKey(
            SIGNING_KEY_ALIAS,
            null
        ) as? PrivateKey
            ?: error("Signing private key is missing")
    }

    private fun getKeyStore(): KeyStore {
        return KeyStore.getInstance(
            ANDROID_KEYSTORE
        ).apply {
            load(null)
        }
    }

    private fun createIdentityId(
        publicKeyBytes: ByteArray
    ): String {
        val digest =
            MessageDigest.getInstance("SHA-256")
                .digest(publicKeyBytes)

        return digest
            .take(16)
            .joinToString("") {
                "%02X".format(it)
            }
    }
}
