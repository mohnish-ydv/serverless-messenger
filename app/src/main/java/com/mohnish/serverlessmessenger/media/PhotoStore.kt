package com.mohnish.serverlessmessenger.media

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID

data class StoredPhoto(
    val id: String,
    val file: File,
    val mimeType: String
)

data class EncodedPhoto(
    val id: String,
    val mimeType: String,
    val base64: String
)

class PhotoStore(
    private val context: Context
) {
    companion object {
        const val MAX_SEND_BYTES = 16 * 1024
    }

    private val photoDirectory: File
        get() = File(
            context.filesDir,
            "media/photos"
        ).apply {
            mkdirs()
        }

    fun importPhoto(uri: Uri): StoredPhoto? {
        val resolver = context.contentResolver

        val mimeType =
            resolver.getType(uri) ?: "image/*"

        val id = UUID.randomUUID().toString()

        val extension =
            when (mimeType.lowercase()) {
                "image/jpeg" -> "jpg"
                "image/png" -> "png"
                "image/webp" -> "webp"
                "image/heic" -> "heic"
                "image/heif" -> "heif"
                else -> "img"
            }

        val file = File(
            photoDirectory,
            "$id.$extension"
        )

        return runCatching {
            resolver.openInputStream(uri).use { input ->
                requireNotNull(input) {
                    "Unable to open selected photo"
                }

                file.outputStream().use { output ->
                    input.copyTo(output)
                }
            }

            StoredPhoto(
                id = id,
                file = file,
                mimeType = mimeType
            )
        }.getOrElse {
            file.delete()
            null
        }
    }

    fun encodeForMessage(
        photo: StoredPhoto
    ): EncodedPhoto? {
        return runCatching {
            val originalBytes =
                photo.file.readBytes()

            /*
             * If the selected photo is already small enough,
             * preserve it exactly. Do not recompress it.
             */
            if (originalBytes.size <= MAX_SEND_BYTES) {
                return@runCatching EncodedPhoto(
                    id = photo.id,
                    mimeType = photo.mimeType,
                    base64 =
                        Base64.encodeToString(
                            originalBytes,
                            Base64.NO_WRAP
                        )
                )
            }

            val bitmap =
                BitmapFactory.decodeByteArray(
                    originalBytes,
                    0,
                    originalBytes.size
                ) ?: return@runCatching null

            try {
                var quality = 85
                var compressed: ByteArray? = null

                while (quality >= 20) {
                    val output =
                        ByteArrayOutputStream()

                    val success =
                        bitmap.compress(
                            Bitmap.CompressFormat.JPEG,
                            quality,
                            output
                        )

                    if (!success) {
                        return@runCatching null
                    }

                    val bytes =
                        output.toByteArray()

                    if (bytes.size <= MAX_SEND_BYTES) {
                        compressed = bytes
                        break
                    }

                    quality -= 5
                }

                val bytes =
                    compressed ?: return@runCatching null

                EncodedPhoto(
                    id = photo.id,
                    mimeType = "image/jpeg",
                    base64 =
                        Base64.encodeToString(
                            bytes,
                            Base64.NO_WRAP
                        )
                )
            } finally {
                bitmap.recycle()
            }
        }.getOrNull()
    }
}
