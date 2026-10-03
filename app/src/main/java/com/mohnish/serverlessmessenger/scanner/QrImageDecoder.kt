package com.mohnish.serverlessmessenger.scanner

import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer

object QrImageDecoder {

    fun decode(
        context: Context,
        uri: Uri
    ): String {
        val bitmap =
            context.contentResolver
                .openInputStream(uri)
                ?.use { input ->
                    BitmapFactory.decodeStream(input)
                }
                ?: throw IllegalArgumentException(
                    "Unable to open the selected image."
                )

        try {
            if (bitmap.width <= 0 || bitmap.height <= 0) {
                throw IllegalArgumentException(
                    "The selected image is invalid."
                )
            }

            val pixels =
                IntArray(bitmap.width * bitmap.height)

            bitmap.getPixels(
                pixels,
                0,
                bitmap.width,
                0,
                0,
                bitmap.width,
                bitmap.height
            )

            val source =
                RGBLuminanceSource(
                    bitmap.width,
                    bitmap.height,
                    pixels
                )

            val binary =
                BinaryBitmap(
                    HybridBinarizer(source)
                )

            return MultiFormatReader()
                .decode(binary)
                .text
        } finally {
            bitmap.recycle()
        }
    }
}
