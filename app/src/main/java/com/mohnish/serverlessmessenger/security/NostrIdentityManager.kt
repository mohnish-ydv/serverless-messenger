package com.mohnish.serverlessmessenger.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class NostrIdentity(
    val privateKey: ByteArray,
    val publicKey: ByteArray
)

object NostrIdentityManager {

    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "serverless_nostr_wrap_key"
    private const val FILE_NAME = "serverless_nostr_identity"

    private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"

    /**
     * Returns the device's persistent Nostr identity.
     *
     * The private key is encrypted at rest with an AES-GCM key
     * held inside Android Keystore.
     */
    fun getOrCreate(context: Context): NostrIdentity {
        val appContext = context.applicationContext
        val file = File(appContext.filesDir, FILE_NAME)

        if (file.exists()) {
            val privateKey = decryptPrivateKey(
                file.readText()
            )

            require(privateKey.size == 32) {
                "Stored Nostr private key is invalid"
            }

            return NostrIdentity(
                privateKey = privateKey,
                publicKey = NostrCrypto.publicKey(privateKey)
            )
        }

        val generated = NostrCrypto.generateKeyPair()

        file.writeText(
            encryptPrivateKey(
                generated.privateKey
            )
        )

        return NostrIdentity(
            privateKey = generated.privateKey,
            publicKey = generated.publicKey
        )
    }

    private fun getOrCreateWrappingKey(): SecretKey {
        val keyStore =
            KeyStore.getInstance(KEYSTORE).apply {
                load(null)
            }

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val generator =
                KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    KEYSTORE
                )

            generator.init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or
                        KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(
                        KeyProperties.BLOCK_MODE_GCM
                    )
                    .setEncryptionPaddings(
                        KeyProperties.ENCRYPTION_PADDING_NONE
                    )
                    .build()
            )

            generator.generateKey()
        }

        return keyStore.getKey(
            KEY_ALIAS,
            null
        ) as? SecretKey
            ?: error("Nostr wrapping key is missing")
    }

    private fun encryptPrivateKey(
        privateKey: ByteArray
    ): String {
        require(privateKey.size == 32)

        val cipher =
            Cipher.getInstance(AES_TRANSFORMATION)

        cipher.init(
            Cipher.ENCRYPT_MODE,
            getOrCreateWrappingKey()
        )

        return JSONObject().apply {
            put(
                "version",
                1
            )
            put(
                "iv",
                Base64.getEncoder().encodeToString(
                    cipher.iv
                )
            )
            put(
                "ciphertext",
                Base64.getEncoder().encodeToString(
                    cipher.doFinal(privateKey)
                )
            )
        }.toString()
    }

    private fun decryptPrivateKey(
        stored: String
    ): ByteArray {
        val payload = JSONObject(stored)

        require(
            payload.optInt("version", 1) == 1
        ) {
            "Unsupported Nostr identity version"
        }

        val iv =
            Base64.getDecoder().decode(
                payload.getString("iv")
            )

        val ciphertext =
            Base64.getDecoder().decode(
                payload.getString("ciphertext")
            )

        val cipher =
            Cipher.getInstance(AES_TRANSFORMATION)

        cipher.init(
            Cipher.DECRYPT_MODE,
            getOrCreateWrappingKey(),
            GCMParameterSpec(128, iv)
        )

        return cipher.doFinal(ciphertext)
    }

    fun publicKeyHex(
        publicKey: ByteArray
    ): String {
        require(publicKey.size == 32)

        return publicKey.joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }
    }
}
