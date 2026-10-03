package com.mohnish.serverlessmessenger

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.mohnish.serverlessmessenger.ui.MessengerApp
import com.mohnish.serverlessmessenger.ui.theme.ServerlessMessengerTheme
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val previousExit = getPreviousExitDiagnostic()

        enableEdgeToEdge()

        setContent {
            ServerlessMessengerTheme {
                var showDiagnostic =
                    remember {
                        androidx.compose.runtime.mutableStateOf(
                            previousExit != null
                        )
                    }

                if (showDiagnostic.value && previousExit != null) {
                    val diagnosticText = remember {
                        previousExit
                    }

                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        color = MaterialTheme.colorScheme.background
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .verticalScroll(
                                    rememberScrollState()
                                )
                                .padding(24.dp),
                            verticalArrangement = Arrangement.spacedBy(16.dp)
                        ) {
                            Text(
                                text = "Previous Crash / Exit",
                                style = MaterialTheme.typography.headlineSmall
                            )

                            Text(
                                text = diagnosticText,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.fillMaxWidth()
                            )

                            Button(
                                onClick = {
                                    val clipboard =
                                        getSystemService(
                                            Context.CLIPBOARD_SERVICE
                                        ) as ClipboardManager

                                    clipboard.setPrimaryClip(
                                        ClipData.newPlainText(
                                            "Crash diagnostic",
                                            diagnosticText
                                        )
                                    )
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Copy diagnostic")
                            }

                            Button(
                                onClick = {
                                    showDiagnostic.value = false
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Continue to app")
                            }
                        }
                    }
                } else {
                    MessengerApp()
                }
            }
        }
    }

    private fun getPreviousExitDiagnostic(): String? {
        return try {
            val activityManager =
                getSystemService(
                    Context.ACTIVITY_SERVICE
                ) as ActivityManager

            val reasons =
                activityManager.getHistoricalProcessExitReasons(
                    packageName,
                    0,
                    5
                )

            if (reasons.isEmpty()) {
                null
            } else {
                buildString {
                    appendLine("=== COMPACT CRASH DIAGNOSTIC ===")
                    appendLine()

                    for ((index, reason) in reasons.withIndex()) {
                        appendLine("EXIT #${index + 1}")
                        appendLine("timestamp=${reason.timestamp}")
                        appendLine("reason=${reason.reason}")
                        appendLine("reasonName=${reasonName(reason.reason)}")
                        appendLine("status=${reason.status}")
                        appendLine("signalName=${signalName(reason.status)}")
                        appendLine("importance=${reason.importance}")
                        appendLine("description=${reason.description}")

                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                            try {
                                reason.getTraceInputStream()?.use { input ->
                                    val trace =
                                        readLimited(input, 64 * 1024)

                                    appendLine()
                                    appendLine("=== TRACE ===")

                                    appendLine(
                                        "TRACE BYTES=${trace.size}"
                                    )

                                    val nativeTerms =
                                        listOf(
                                            "libjingle",
                                            "PeerConnection",
                                            "setLocalDescription",
                                            "createAnswer",
                                            "createOffer",
                                            "DataChannel",
                                            "signaling_thread",
                                            "network_thread",
                                            "abort",
                                            "SIGABRT",
                                            "FATAL",
                                            "CHECK",
                                            "assert"
                                        )

                                    appendLine()
                                    appendLine(
                                        "=== NATIVE MATCH CONTEXT ==="
                                    )

                                    var matchCount = 0

                                    for (term in nativeTerms) {
                                        if (matchCount >= 30) {
                                            break
                                        }

                                        val termBytes =
                                            term.toByteArray(
                                                Charsets.US_ASCII
                                            )

                                        var offset =
                                            indexOfBytes(
                                                trace,
                                                termBytes
                                            )

                                        while (
                                            offset >= 0 &&
                                            matchCount < 30
                                        ) {
                                            val from =
                                                maxOf(
                                                    0,
                                                    offset - 180
                                                )

                                            val to =
                                                minOf(
                                                    trace.size,
                                                    offset +
                                                        termBytes.size +
                                                        220
                                                )

                                            appendLine()
                                            appendLine(
                                                "$term @ byte $offset"
                                            )
                                            appendLine(
                                                bytesToAsciiPreviewRange(
                                                    trace,
                                                    from,
                                                    to
                                                )
                                            )

                                            matchCount++

                                            offset =
                                                indexOfBytes(
                                                    trace,
                                                    termBytes,
                                                    offset + 1
                                                )
                                        }
                                    }

                                    if (matchCount == 0) {
                                        appendLine(
                                            "No raw ASCII native strings found."
                                        )
                                    }
                                }
                            } catch (t: Throwable) {
                                appendLine()
                                appendLine(
                                    "TRACE READ ERROR: " +
                                        t.javaClass.simpleName +
                                        ": " +
                                        (t.message ?: "")
                                )
                            }
                        }

                        appendLine()
                        appendLine("---")
                        appendLine()
                    }
                }
            }
        } catch (t: Throwable) {
            "=== COMPACT DIAGNOSTIC ERROR ===\n\n" +
                t.stackTraceToString()
        }
    }

    private fun readLimited(
        input: InputStream,
        maxBytes: Int
    ): ByteArray {
        val output =
            ByteArrayOutputStream(
                minOf(maxBytes, 64 * 1024)
            )

        val buffer = ByteArray(8192)

        var total = 0

        while (total < maxBytes) {
            val remaining = maxBytes - total

            val read =
                input.read(
                    buffer,
                    0,
                    minOf(
                        buffer.size,
                        remaining
                    )
                )

            if (read <= 0) {
                break
            }

            output.write(
                buffer,
                0,
                read
            )

            total += read
        }

        return output.toByteArray()
    }

    private fun formatTimestamp(
        timestamp: Long
    ): String {
        return try {
            SimpleDateFormat(
                "yyyy-MM-dd HH:mm:ss.SSS Z",
                Locale.US
            ).format(
                Date(timestamp)
            )
        } catch (_: Throwable) {
            timestamp.toString()
        }
    }

    private fun reasonName(
        reason: Int
    ): String {
        return when (reason) {
            ApplicationExitInfo.REASON_UNKNOWN ->
                "REASON_UNKNOWN"

            ApplicationExitInfo.REASON_EXIT_SELF ->
                "REASON_EXIT_SELF"

            ApplicationExitInfo.REASON_SIGNALED ->
                "REASON_SIGNALED"

            ApplicationExitInfo.REASON_LOW_MEMORY ->
                "REASON_LOW_MEMORY"

            ApplicationExitInfo.REASON_CRASH ->
                "REASON_CRASH"

            ApplicationExitInfo.REASON_CRASH_NATIVE ->
                "REASON_CRASH_NATIVE"

            ApplicationExitInfo.REASON_ANR ->
                "REASON_ANR"

            ApplicationExitInfo.REASON_INITIALIZATION_FAILURE ->
                "REASON_INITIALIZATION_FAILURE"

            ApplicationExitInfo.REASON_PERMISSION_CHANGE ->
                "REASON_PERMISSION_CHANGE"

            ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE ->
                "REASON_EXCESSIVE_RESOURCE_USAGE"

            ApplicationExitInfo.REASON_USER_REQUESTED ->
                "REASON_USER_REQUESTED"

            ApplicationExitInfo.REASON_USER_STOPPED ->
                "REASON_USER_STOPPED"

            ApplicationExitInfo.REASON_DEPENDENCY_DIED ->
                "REASON_DEPENDENCY_DIED"

            ApplicationExitInfo.REASON_OTHER ->
                "REASON_OTHER"

            else ->
                "REASON_UNKNOWN_CODE"
        }
    }

    private fun signalName(
        status: Int
    ): String {
        return when (status) {
            0 ->
                "STATUS_0"

            4 ->
                "SIGILL"

            6 ->
                "SIGABRT"

            7 ->
                "SIGBUS"

            8 ->
                "SIGFPE"

            9 ->
                "SIGKILL"

            11 ->
                "SIGSEGV"

            13 ->
                "SIGPIPE"

            15 ->
                "SIGTERM"

            else ->
                "SIGNAL_OR_EXIT_CODE_$status"
        }
    }

    private fun indexOfBytes(
        haystack: ByteArray,
        needle: ByteArray,
        start: Int = 0
    ): Int {
        if (needle.isEmpty()) {
            return start.coerceAtMost(haystack.size)
        }

        if (start < 0 || start >= haystack.size) {
            return -1
        }

        if (needle.size > haystack.size - start) {
            return -1
        }

        outer@ for (i in start..(haystack.size - needle.size)) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) {
                    continue@outer
                }
            }

            return i
        }

        return -1
    }

    private fun bytesToHexPreview(
        bytes: ByteArray
    ): String {
        if (bytes.isEmpty()) {
            return "(empty)"
        }

        val limit =
            minOf(
                bytes.size,
                HEX_PREVIEW_BYTES
            )

        return buildString {
            for (i in 0 until limit) {
                if (i > 0) {
                    append(' ')
                }

                append(
                    "%02X".format(
                        Locale.US,
                        bytes[i].toInt() and 0xFF
                    )
                )
            }

            if (bytes.size > limit) {
                append(
                    "\n... (${bytes.size - limit} more bytes)"
                )
            }
        }
    }

    private fun bytesToAsciiPreviewRange(
        bytes: ByteArray,
        start: Int,
        end: Int
    ): String {
        val from = start.coerceIn(0, bytes.size)
        val to = end.coerceIn(from, bytes.size)

        return buildString {
            for (i in from until to) {
                val value =
                    bytes[i].toInt() and 0xFF

                if (value in 32..126) {
                    append(value.toChar())
                } else {
                    append('.')
                }
            }
        }
    }

    private fun bytesToAsciiPreview(
        bytes: ByteArray
    ): String {
        if (bytes.isEmpty()) {
            return "(empty)"
        }

        val limit =
            minOf(
                bytes.size,
                ASCII_PREVIEW_BYTES
            )

        return buildString {
            for (i in 0 until limit) {
                val value =
                    bytes[i].toInt() and 0xFF

                if (value in 32..126) {
                    append(value.toChar())
                } else {
                    append('.')
                }
            }

            if (bytes.size > limit) {
                append(
                    "\n... (${bytes.size - limit} more bytes)"
                )
            }
        }
    }

    companion object {
        private const val MAX_TRACE_BYTES =
            512 * 1024

        private const val HEX_PREVIEW_BYTES =
            4096

        private const val ASCII_PREVIEW_BYTES =
            4096
    }
}
