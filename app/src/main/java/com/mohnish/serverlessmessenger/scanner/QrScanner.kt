package com.mohnish.serverlessmessenger.scanner

import android.annotation.SuppressLint
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
fun QrScanner(
    enabled: Boolean = true,
    onResult: (String) -> Unit,
    onError: (String) -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    val previewView = remember {
        PreviewView(context).apply {
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }

    val executor = remember {
        Executors.newSingleThreadExecutor()
    }

    val found = remember {
        AtomicBoolean(false)
    }

    DisposableEffect(Unit) {
        onDispose {
            executor.shutdown()
        }
    }

    LaunchedEffect(enabled) {
        if (!enabled) return@LaunchedEffect

        found.set(false)

        val cameraProviderFuture =
            ProcessCameraProvider.getInstance(context)

        cameraProviderFuture.addListener({
            try {
                val cameraProvider =
                    cameraProviderFuture.get()

                val preview = Preview.Builder()
                    .build()
                    .also {
                        it.surfaceProvider =
                            previewView.surfaceProvider
                    }

                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(
                        ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST
                    )
                    .build()

                analysis.setAnalyzer(executor) { imageProxy ->
                    if (!found.get()) {
                        decode(
                            imageProxy = imageProxy,
                            onResult = { value ->
                                if (found.compareAndSet(false, true)) {
                                    ContextCompat
                                        .getMainExecutor(context)
                                        .execute {
                                            onResult(value)
                                        }
                                }
                            }
                        )
                    } else {
                        imageProxy.close()
                    }
                }

                cameraProvider.unbindAll()

                cameraProvider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis
                )
            } catch (e: Exception) {
                ContextCompat
                    .getMainExecutor(context)
                    .execute {
                        onError(
                            e.message ?: "Unable to start camera"
                        )
                    }
            }
        }, ContextCompat.getMainExecutor(context))
    }

    Box(
        modifier = Modifier.fillMaxSize()
    ) {
        AndroidView(
            factory = { previewView },
            modifier = Modifier.fillMaxSize()
        )

        Text(
            text = "Point your camera at a Serverless QR",
            color = Color.White,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(
                    start = 24.dp,
                    end = 24.dp,
                    bottom = 32.dp
                )
                .background(
                    Color.Black.copy(alpha = 0.40f),
                    RoundedCornerShape(999.dp)
                )
                .padding(
                    horizontal = 18.dp,
                    vertical = 10.dp
                )
        )
    }
}

@SuppressLint("UnsafeOptInUsageError")
private fun decode(
    imageProxy: ImageProxy,
    onResult: (String) -> Unit
) {
    try {
        val image = imageProxy.image
            ?: return

        if (image.planes.isEmpty()) return

        val plane = image.planes[0]
        val buffer = plane.buffer

        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)

        val source = PlanarYUVLuminanceSource(
            bytes,
            plane.rowStride,
            image.width,
            0,
            0,
            image.width,
            image.height,
            false
        )

        val bitmap = BinaryBitmap(
            HybridBinarizer(source)
        )

        val reader = MultiFormatReader()

        reader.setHints(
            mapOf(
                DecodeHintType.POSSIBLE_FORMATS
                    to listOf(BarcodeFormat.QR_CODE),
                DecodeHintType.TRY_HARDER to true
            )
        )

        val result = try {
            reader.decodeWithState(bitmap)
        } catch (_: Exception) {
            null
        } finally {
            reader.reset()
        }

        result?.text?.let(onResult)
    } catch (_: Exception) {
        // Most camera frames do not contain a QR.
    } finally {
        imageProxy.close()
    }
}
