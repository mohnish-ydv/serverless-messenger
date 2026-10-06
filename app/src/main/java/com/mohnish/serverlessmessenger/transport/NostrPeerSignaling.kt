package com.mohnish.serverlessmessenger.transport

import android.util.Log
import android.os.Handler
import android.os.Looper

import android.content.Context
import com.mohnish.serverlessmessenger.data.ContactDirectory
import com.mohnish.serverlessmessenger.security.MessageCrypto
import com.mohnish.serverlessmessenger.security.DeviceIdentityManager
import com.mohnish.serverlessmessenger.security.EncryptedMessagePacket
import com.mohnish.serverlessmessenger.security.NostrCrypto
import com.mohnish.serverlessmessenger.security.NostrIdentityManager
import com.mohnish.serverlessmessenger.security.SignalingCrypto
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID

class NostrPeerSignaling(
    context: Context,
    private val contactDirectory: ContactDirectory,
    private val relayUrl: String = DEFAULT_RELAY
) : PeerSignaling, EncryptedMessageTransport {

    private val appContext =
        context.applicationContext

    private val client =
        OkHttpClient.Builder()
            .protocols(listOf(okhttp3.Protocol.HTTP_1_1))
            .build()

    private val nostrIdentity =
        NostrIdentityManager.getOrCreate(appContext)

    private val localNostrPublicKey =
        NostrIdentityManager.publicKeyHex(
            nostrIdentity.publicKey
        )

    private val localIdentity =
        DeviceIdentityManager.getOrCreate(appContext)

    private val listeners =
        mutableMapOf<String, (PeerSignal) -> Unit>()

    private var incomingListener:
        ((
            peerId: String,
            signingPublicKeyBase64: String,
            agreementPublicKeyBase64: String,
            signal: PeerSignal
        ) -> Unit)? = null

    private var diagnosticListener:
        ((String) -> Unit)? = null

    private var messageListener:
        ((
            peerId: String,
            signingPublicKeyBase64: String,
            packet: EncryptedMessagePacket
        ) -> Unit)? = null

    private var messageConnectionListener:
        ((Boolean) -> Unit)? = null

    private fun diagnostic(
        message: String
    ) {
        Log.d(TAG, message)
        diagnosticListener?.invoke(message)
    }

    private val pendingEvents =
        mutableListOf<String>()

    private var socket: WebSocket? = null
    private var connected = false

    private val reconnectHandler =
        Handler(Looper.getMainLooper())

    private var reconnectAttempt = 0
    private var reconnectScheduled = false

    private val subscriptionId =
        "serverless-${UUID.randomUUID()}"

    @Synchronized
    override fun publish(
        peerId: String,
        signal: PeerSignal
    ) {
        Log.d(
            TAG,
            "publish peerId=$peerId signal=${signal.javaClass.simpleName}"
        )
        val contact =
            contactDirectory.get(peerId)

        if (contact == null) {
            Log.w(TAG, "publish aborted: contact not found peerId=$peerId")
            return
        }

        val recipientNostrKey =
            contact.nostrPublicKeyHex
                .trim()
                .lowercase()

        if (recipientNostrKey.length != 64) {
            return
        }

        val signalJson =
            encodeSignal(signal)

        val encryptedContent =
            SignalingCrypto.encrypt(
                senderIdentityId =
                    localIdentity.identityId,
                recipientIdentityId =
                    contact.identityId,
                recipientAgreementPublicKeyBase64 =
                    contact.agreementPublicKeyBase64,
                plaintext =
                    signalJson
            )

        val event =
            createEvent(
                recipientNostrKey =
                    recipientNostrKey,
                content =
                    encryptedContent
            )

        val message =
            JSONArray()
                .put("EVENT")
                .put(event)
                .toString()

        if (connected) {
            diagnostic(
                "PUBLISH EVENT — peerId=$peerId bytes=${message.length}"
            )

            val currentSocket = socket

            if (currentSocket == null) {
                diagnostic(
                    "PUBLISH FAILED — connected=true but socket=null"
                )
            } else {
                val sent = currentSocket.send(message)

                diagnostic(
                    if (sent) {
                        "PUBLISH SENT — websocket.send=true"
                    } else {
                        "PUBLISH FAILED — websocket.send=false"
                    }
                )
            }
        } else {
            diagnostic(
                "PUBLISH QUEUED — relay not connected peerId=$peerId"
            )

            pendingEvents += message
            connect()
        }
    }

    @Synchronized
    override fun setListener(
        peerId: String,
        listener: (PeerSignal) -> Unit
    ) {
        Log.d(TAG, "listener registered peerId=$peerId")
        listeners[peerId] = listener
        connect()
    }

    @Synchronized
    override fun publishMessage(
        peerId: String,
        packet: EncryptedMessagePacket
    ): Boolean {

        val contact =
            contactDirectory.get(peerId)
                ?: run {
                    diagnostic(
                        "MESSAGE PUBLISH ABORTED — contact not found peerId=$peerId"
                    )
                    return false
                }

        val recipientNostrKey =
            contact.nostrPublicKeyHex
                .trim()
                .lowercase()

        if (recipientNostrKey.length != 64) {
            diagnostic(
                "MESSAGE PUBLISH ABORTED — invalid recipient Nostr key"
            )
            return false
        }

        val packetJson =
            encodeMessagePacket(packet)

        /*
         * Outer encryption hides the MessageCrypto packet metadata
         * from the relay. The packet itself remains independently
         * authenticated/encrypted by MessageCrypto.
         */
        val encryptedContent =
            SignalingCrypto.encrypt(
                senderIdentityId =
                    localIdentity.identityId,
                recipientIdentityId =
                    contact.identityId,
                recipientAgreementPublicKeyBase64 =
                    contact.agreementPublicKeyBase64,
                plaintext =
                    packetJson
            )

        /*
         * The Nostr event can outlive the contact's locally stored
         * cryptographic metadata. Therefore carry the sender's CURRENT
         * identity keys beside the encrypted SignalingCrypto envelope.
         *
         * These fields are not trusted merely because they are present:
         * the agreement key is validated by successful outer decryption,
         * and the signing key is validated against MessageCrypto's
         * authenticated packet signature.
         *
         * SignalingCrypto.decrypt() ignores these extra JSON fields, so
         * this remains wire-compatible with the existing outer envelope.
         */
        val messageEnvelope =
            JSONObject(encryptedContent)
                .put(
                    "sender_signing_public_key",
                    localIdentity.publicKeyBase64
                )
                .put(
                    "sender_agreement_public_key",
                    localIdentity.agreementPublicKeyBase64
                )
                .toString()

        val event =
            createMessageEvent(
                recipientNostrKey =
                    recipientNostrKey,
                content =
                    messageEnvelope
            )

        val message =
            JSONArray()
                .put("EVENT")
                .put(event)
                .toString()

        /*
         * nos.lol rejects oversized events asynchronously with:
         * ["OK", eventId, false, "invalid: event too large: ..."]
         *
         * publishMessage() has a synchronous Boolean API, so perform
         * the same safety check before websocket.send(). This prevents
         * the UI from treating a relay-rejected media message as sent.
         */
        val messageBytes =
            message.toByteArray(StandardCharsets.UTF_8).size

        if (messageBytes > MAX_RELAY_EVENT_BYTES) {
            diagnostic(
                "MESSAGE PUBLISH ABORTED — event too large bytes=$messageBytes " +
                    "limit=$MAX_RELAY_EVENT_BYTES packet=${packet.id}"
            )
            return false
        }

        val currentSocket =
            socket

        if (
            !connected ||
            currentSocket == null
        ) {
            diagnostic(
                "MESSAGE PUBLISH DEFERRED — relay not connected peerId=$peerId"
            )

            /*
             * Do not queue here. PeerConnectionManager owns the durable
             * plaintext outbox and will retry after the relay connects.
             */
            connect()
            return false
        }

        val sent =
            currentSocket.send(message)

        diagnostic(
            if (sent) {
                "MESSAGE EVENT SENT — peerId=$peerId packet=${packet.id} " +
                    "eventId=${event.optString("id")}"
            } else {
                "MESSAGE EVENT SEND FAILED — peerId=$peerId " +
                    "eventId=${event.optString("id")}"
            }
        )

        return sent
    }

    @Synchronized
    override fun setMessageListener(
        listener: (
            peerId: String,
            signingPublicKeyBase64: String,
            packet: EncryptedMessagePacket
        ) -> Unit
    ) {
        messageListener = listener
        diagnostic("MESSAGE LISTENER REGISTERED")
        connect()
    }

    @Synchronized
    override fun setMessageConnectionListener(
        listener: (Boolean) -> Unit
    ) {
        messageConnectionListener = listener
    }

    fun testRelay(
        callback: (Boolean, String) -> Unit
    ) {
        val request =
            Request.Builder()
                .url(relayUrl)
                .build()

        client.newWebSocket(
            request,
            object : WebSocketListener() {

                override fun onOpen(
                    webSocket: WebSocket,
                    response: Response
                ) {
                    callback(
                        true,
                        "PASS: WebSocket connected HTTP ${response.code}"
                    )

                    webSocket.close(
                        1000,
                        "diagnostic complete"
                    )
                }

                override fun onFailure(
                    webSocket: WebSocket,
                    t: Throwable,
                    response: Response?
                ) {
                    callback(
                        false,
                        "FAIL: ${t::class.java.name}: ${t.message ?: "no message"}" +
                            " HTTP=${response?.code ?: "none"}"
                    )
                }
            }
        )
    }

    @Synchronized
    override fun setIncomingListener(
        listener: (
            peerId: String,
            signingPublicKeyBase64: String,
            agreementPublicKeyBase64: String,
            signal: PeerSignal
        ) -> Unit
    ) {
        diagnostic("GLOBAL INCOMING LISTENER REGISTERED")
        incomingListener = listener
        connect()
    }

    @Synchronized
    override fun setDiagnosticListener(
        listener: (String) -> Unit
    ) {
        diagnosticListener = listener
        diagnostic("diagnostic listener registered")
    }

    @Synchronized
    override fun removeListener(
        peerId: String
    ) {
        listeners.remove(peerId)

        if (listeners.isEmpty()) {
            socket?.close(
                1000,
                "no listeners"
            )

            socket = null
            connected = false
        }
    }

    @Synchronized
    private fun connect() {
        diagnostic("RELAY CONNECT REQUEST — connected=$connected socket=${socket != null}")
        if (
            connected ||
            socket != null
        ) {
            return
        }

        val request =
            Request.Builder()
                .url(relayUrl)
                .build()

        socket =
            client.newWebSocket(
                request,
                object : WebSocketListener() {

                    override fun onOpen(
                        webSocket: WebSocket,
                        response: Response
                    ) {
                        diagnostic("RELAY WEBSOCKET OPEN url=$relayUrl")

                        synchronized(
                            this@NostrPeerSignaling
                        ) {
                            connected = true
                            reconnectAttempt = 0
                            reconnectScheduled = false

                            messageConnectionListener?.invoke(true)

                            Log.d(
                                TAG,
                                "subscribing localNostr=$localNostrPublicKey"
                            )

                            subscribe(webSocket)

                            Log.d(
                                TAG,
                                "sending pending events count=${pendingEvents.size}"
                            )

                            pendingEvents.forEach {
                                webSocket.send(it)
                            }

                            pendingEvents.clear()
                        }
                    }

                    override fun onMessage(
                        webSocket: WebSocket,
                        text: String
                    ) {
                        Log.d(
                            TAG,
                            "relay message received bytes=${text.length}"
                        )

                        diagnostic(
                            "RELAY MESSAGE RECEIVED — $text"
                        )

                        handleRelayMessage(text)
                    }

                    override fun onFailure(
                        webSocket: WebSocket,
                        t: Throwable,
                        response: Response?
                    ) {
                        Log.e(
                            TAG,
                            "relay WebSocket FAILURE: ${t.message}",
                            t
                        )

                        synchronized(
                            this@NostrPeerSignaling
                        ) {
                            if (socket === webSocket) {
                                socket = null
                                connected = false
                                messageConnectionListener?.invoke(false)
                                scheduleReconnect()
                            }
                        }
                    }

                    override fun onClosed(
                        webSocket: WebSocket,
                        code: Int,
                        reason: String
                    ) {
                        Log.d(
                            TAG,
                            "relay WebSocket CLOSED code=$code reason=$reason"
                        )

                        synchronized(
                            this@NostrPeerSignaling
                        ) {
                            if (socket === webSocket) {
                                socket = null
                                connected = false
                                messageConnectionListener?.invoke(false)
                                scheduleReconnect()
                            }
                        }
                    }
                }
            )
    }

    @Synchronized
    private fun scheduleReconnect() {
        if (reconnectScheduled) return

        if (
            messageListener == null &&
            incomingListener == null
        ) {
            return
        }

        reconnectScheduled = true

        val delayMs =
            minOf(
                30_000L,
                1_000L shl minOf(reconnectAttempt, 5)
            )

        reconnectAttempt++

        diagnostic(
            "RELAY RECONNECT SCHEDULED — " +
                "delayMs=$delayMs attempt=$reconnectAttempt"
        )

        reconnectHandler.postDelayed({
            synchronized(this@NostrPeerSignaling) {
                reconnectScheduled = false

                if (
                    !connected &&
                    socket == null
                ) {
                    diagnostic(
                        "RELAY RECONNECT ATTEMPT — " +
                            "attempt=$reconnectAttempt"
                    )

                    connect()
                }
            }
        }, delayMs)
    }

    private fun subscribe(
        webSocket: WebSocket
    ) {
        diagnostic(
            "SUBSCRIBE START — localNostr=$localNostrPublicKey"
        )

        /*
         * Subscribe only by event kind.
         * Recipient filtering is performed locally by
         * handleRelayMessage()/hasRecipientTag().
         */
        val filter =
            JSONObject()
                .put(
                    "kinds",
                    JSONArray()
                        .put(SIGNAL_KIND)
                        .put(MESSAGE_KIND)
                )

        val request =
            JSONArray()
                .put("REQ")
                .put(subscriptionId)
                .put(filter)

        val requestText =
            request.toString()

        diagnostic(
            "SUBSCRIBE REQUEST — $requestText"
        )

        val sent =
            webSocket.send(requestText)

        diagnostic(
            if (sent) {
                "SUBSCRIBE SENT — websocket.send=true"
            } else {
                "SUBSCRIBE FAILED — websocket.send=false"
            }
        )
    }

    private fun handleRelayMessage(
        text: String
    ) {
        try {
            val message =
                JSONArray(text)

            if (message.length() < 2) {
                return
            }

            when (message.optString(0)) {

            "EOSE" -> {
                diagnostic(
                    "RELAY SUBSCRIPTION READY — sub=${message.optString(1)}"
                )
                return
            }

            "CLOSED" -> {
                diagnostic(
                    "RELAY SUBSCRIPTION CLOSED — sub=${message.optString(1)} " +
                        "reason=${message.optString(2)}"
                )
                return
            }

            "NOTICE" -> {
                diagnostic(
                    "RELAY NOTICE — ${message.optString(1)}"
                )
                return
            }
        }

        /*
             * Relay acknowledgements are:
             * ["OK", eventId, accepted, message]
             *
             * They are deliberately handled separately from incoming
             * EVENT messages. publishMessage() currently uses the
             * synchronous websocket.send() result, while this ACK is
             * still useful for diagnostics and future delivery state.
             */
            if (message.optString(0) == "OK") {
                val eventId =
                    message.optString(1)

                val accepted =
                    message.optBoolean(2, false)

                val reason =
                    message.optString(3)

                diagnostic(
                    if (accepted) {
                        "RELAY PUBLISH ACCEPTED — eventId=$eventId"
                    } else {
                        "RELAY PUBLISH REJECTED — eventId=$eventId reason=$reason"
                    }
                )
                return
            }

            if (
                message.optString(0) != "EVENT"
            ) {
                return
            }

            if (message.length() < 3) {
                return
            }

            val event =
                message.optJSONObject(2)
                    ?: return

            diagnostic("EVENT RECEIVED from relay")

            val eventKind =
                event.optInt("kind")

            if (
                eventKind != SIGNAL_KIND &&
                eventKind != MESSAGE_KIND
            ) {
                diagnostic(
                    "EVENT IGNORED — wrong kind=$eventKind"
                )
                return
            }

            val senderNostrKey =
                event.optString("pubkey")
                    .trim()
                    .lowercase()

            if (
                senderNostrKey.isBlank() ||
                senderNostrKey ==
                localNostrPublicKey
            ) {
                return
            }

            if (!verifyEvent(event)) {
                diagnostic("EVENT REJECTED — signature verification FAILED")
                return
            }

            diagnostic("EVENT SIGNATURE VERIFIED")

            /*
             * The Nostr p-tag is only a relay/routing hint.
             *
             * It can become stale when a device regenerates its
             * Nostr identity while an existing contact still contains
             * the previous public key. The actual recipient identity is
             * authenticated inside the encrypted payload, so do not
             * reject the event solely because the p-tag is stale.
             */
            if (hasRecipientTag(event)) {
                diagnostic("EVENT RECIPIENT TAG VERIFIED")
            } else {
                diagnostic(
                    "EVENT RECIPIENT TAG STALE/DIFFERENT — continuing to encrypted identity verification"
                )
            }

            /*
             * MESSAGE_KIND has its stable sender identity inside the
             * encrypted envelope itself. Do not resolve the sender
             * through the Nostr pubkey first: the contact may contain
             * an older Nostr key after identity rotation.
             *
             * Signal events still use the Nostr key to route the
             * WebRTC signaling path.
             */
            if (
                event.optInt("kind") == MESSAGE_KIND
            ) {
                handleMessageEvent(
                    event = event,
                    senderNostrKey = senderNostrKey
                )
                return
            }

            val sender =
                contactDirectory
                    .getByNostrPublicKey(
                        senderNostrKey
                    )
                    ?: run {
                        diagnostic(
                            "SIGNAL REJECTED — sender not in contact directory nostr=$senderNostrKey"
                        )
                        return
                    }

            diagnostic(
                "EVENT MAPPED TO CONTACT identityId=${sender.identityId}"
            )
            val decrypted =
                SignalingCrypto.decrypt(
                    recipientIdentityId =
                        localIdentity.identityId,
                    senderIdentityId =
                        sender.identityId,
                    senderAgreementPublicKeyBase64 =
                        sender.agreementPublicKeyBase64,
                    envelope =
                        event.optString("content")
                )
                    ?: run {
                        diagnostic("SIGNALING DECRYPT FAILED")
                        return
                    }

            diagnostic("SIGNALING DECRYPT OK")

            val signal =
                decodeSignal(decrypted)
                    ?: run {
                        diagnostic("SIGNAL DECODE FAILED")
                        return
                    }

            diagnostic(
                "SIGNAL DECODED type=${signal.javaClass.simpleName} sender=${sender.identityId}"
            )

            diagnostic(
                "ROUTING SIGNAL sender=${sender.identityId} listeners=${listeners.keys}"
            )

            val listener =
                listeners[sender.identityId]

            if (listener != null) {
                diagnostic(
                    "DELIVERING SIGNAL TO EXISTING PEER LISTENER"
                )
                listener.invoke(signal)
            } else {
                diagnostic(
                    "NO PEER LISTENER — checking global incoming listener"
                )

                val globalListener =
                    incomingListener

                if (globalListener == null) {
                    diagnostic(
                        "NO GLOBAL INCOMING LISTENER peer=${sender.identityId}"
                    )
                } else {
                    diagnostic(
                        "DELIVERING SIGNAL THROUGH GLOBAL INCOMING LISTENER"
                    )

                    globalListener.invoke(
                        sender.identityId,
                        sender.publicKeyBase64,
                        sender.agreementPublicKeyBase64,
                        signal
                    )
                }
            }

        } catch (e: Exception) {
            Log.e(
                TAG,
                "relay message processing exception: ${e.message}",
                e
            )
        }
    }

    private fun handleMessageEvent(
        event: JSONObject,
        senderNostrKey: String
    ) {
        try {
            val eventId =
                event.optString("id").trim()

            /*
             * The sender identity and CURRENT cryptographic keys are
             * carried beside the encrypted SignalingCrypto envelope.
             *
             * Do NOT resolve the sender through ContactDirectory here.
             * ContactDirectory can contain stale Nostr/agreement/signing
             * metadata after the peer regenerates an identity.
             */
            val envelope =
                JSONObject(
                    event.optString("content")
                )

            val senderIdentityId =
                envelope.optString(
                    "sender_identity_id"
                ).trim()

            val recipientIdentityId =
                envelope.optString(
                    "recipient_identity_id"
                ).trim()

            val senderSigningPublicKeyBase64 =
                envelope.optString(
                    "sender_signing_public_key"
                ).trim()

            val senderAgreementPublicKeyBase64 =
                envelope.optString(
                    "sender_agreement_public_key"
                ).trim()

            if (senderIdentityId.isBlank()) {
                diagnostic(
                    "MESSAGE REJECTED — missing sender_identity_id eventId=$eventId"
                )
                return
            }

            if (
                recipientIdentityId !=
                localIdentity.identityId
            ) {
                diagnostic(
                    "MESSAGE REJECTED — recipient identity mismatch " +
                        "eventId=$eventId envelopeRecipient=$recipientIdentityId " +
                        "local=${localIdentity.identityId}"
                )
                return
            }

            if (senderSigningPublicKeyBase64.isBlank()) {
                diagnostic(
                    "MESSAGE REJECTED — missing sender signing key " +
                        "eventId=$eventId identityId=$senderIdentityId"
                )
                return
            }

            if (senderAgreementPublicKeyBase64.isBlank()) {
                diagnostic(
                    "MESSAGE REJECTED — missing sender agreement key " +
                        "eventId=$eventId identityId=$senderIdentityId"
                )
                return
            }

            diagnostic(
                "MESSAGE SENDER METADATA — identityId=$senderIdentityId " +
                    "nostr=$senderNostrKey eventId=$eventId"
            )

            val outerPlaintext =
                SignalingCrypto.decrypt(
                    recipientIdentityId =
                        localIdentity.identityId,
                    senderIdentityId =
                        senderIdentityId,
                    senderAgreementPublicKeyBase64 =
                        senderAgreementPublicKeyBase64,
                    envelope =
                        event.optString("content")
                )
                    ?: run {
                        diagnostic(
                            "MESSAGE OUTER DECRYPT FAILED — " +
                                "eventId=$eventId identityId=$senderIdentityId"
                        )
                        return
                    }

            diagnostic(
                "MESSAGE OUTER DECRYPT OK — eventId=$eventId"
            )

            val packet =
                decodeMessagePacket(
                    outerPlaintext
                )
                    ?: run {
                        diagnostic(
                            "MESSAGE PACKET DECODE FAILED — eventId=$eventId"
                        )
                        return
                    }

            if (
                packet.senderIdentityId !=
                senderIdentityId ||
                packet.recipientIdentityId !=
                localIdentity.identityId
            ) {
                diagnostic(
                    "MESSAGE REJECTED — packet identity mismatch " +
                        "eventId=$eventId packet=${packet.id}"
                )
                return
            }

            /*
             * Bind the outer sender agreement key to the authenticated
             * MessageCrypto packet. This prevents a message from mixing
             * identity metadata from one key with packet metadata from
             * another key.
             */
            if (
                packet.senderAgreementPublicKey !=
                senderAgreementPublicKeyBase64
            ) {
                diagnostic(
                    "MESSAGE REJECTED — sender agreement key mismatch " +
                        "eventId=$eventId packet=${packet.id}"
                )
                return
            }

            diagnostic(
                "MESSAGE IDENTITY RECIPIENT VERIFIED — " +
                    "eventId=$eventId packet=${packet.id}"
            )

            val packetSignatureValid =
                MessageCrypto.verifyPacket(
                    packet =
                        packet,
                    senderSigningPublicKeyBase64 =
                        senderSigningPublicKeyBase64
                )

            if (!packetSignatureValid) {
                diagnostic(
                    "MESSAGE REJECTED — packet signature INVALID " +
                        "eventId=$eventId packet=${packet.id}"
                )
                return
            }

            diagnostic(
                "MESSAGE PACKET SIGNATURE VERIFIED — " +
                    "eventId=$eventId packet=${packet.id}"
            )

            /*
             * ContactDirectory is intentionally optional for delivery.
             *
             * If a matching contact exists, its public metadata may still
             * be useful to the UI, but stale contact records must never
             * prevent cryptographically valid messages from arriving.
             */
            val knownContact =
                contactDirectory.get(
                    senderIdentityId
                )

            if (knownContact == null) {
                diagnostic(
                    "MESSAGE CONTACT STALE/MISSING — delivering by stable identity " +
                        "identityId=$senderIdentityId"
                )
            } else {
                diagnostic(
                    "MESSAGE CONTACT FOUND — identityId=$senderIdentityId"
                )
            }

            messageListener?.invoke(
                senderIdentityId,
                senderSigningPublicKeyBase64,
                packet
            )

            diagnostic(
                "MESSAGE DELIVERED — peer=$senderIdentityId " +
                    "packet=${packet.id} eventId=$eventId"
            )
        } catch (e: Exception) {
            Log.e(
                TAG,
                "message event processing failed",
                e
            )

            diagnostic(
                "MESSAGE PROCESSING EXCEPTION — ${e::class.java.simpleName}: " +
                    "${e.message ?: "no message"}"
            )
        }
    }

    private fun encodeMessagePacket(
        packet: EncryptedMessagePacket
    ): String =
        JSONObject()
            .put("version", 1)
            .put("id", packet.id)
            .put(
                "sender_identity_id",
                packet.senderIdentityId
            )
            .put(
                "recipient_identity_id",
                packet.recipientIdentityId
            )
            .put(
                "sender_agreement_public_key",
                packet.senderAgreementPublicKey
            )
            .put(
                "recipient_agreement_public_key",
                packet.recipientAgreementPublicKey
            )
            .put(
                "timestamp",
                packet.timestamp
            )
            .put(
                "nonce",
                packet.nonce
            )
            .put(
                "ciphertext",
                packet.ciphertext
            )
            .put(
                "signature",
                packet.signature
            )
            .toString()

    private fun decodeMessagePacket(
        content: String
    ): EncryptedMessagePacket? {
        return try {
            val json =
                JSONObject(content)

            if (
                json.optInt("version", 0) != 1
            ) {
                return null
            }

            EncryptedMessagePacket(
                id =
                    json.getString("id"),
                senderIdentityId =
                    json.getString(
                        "sender_identity_id"
                    ),
                recipientIdentityId =
                    json.getString(
                        "recipient_identity_id"
                    ),
                senderAgreementPublicKey =
                    json.getString(
                        "sender_agreement_public_key"
                    ),
                recipientAgreementPublicKey =
                    json.getString(
                        "recipient_agreement_public_key"
                    ),
                timestamp =
                    json.getLong("timestamp"),
                nonce =
                    json.getString("nonce"),
                ciphertext =
                    json.getString("ciphertext"),
                signature =
                    json.getString("signature")
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun createMessageEvent(
        recipientNostrKey: String,
        content: String
    ): JSONObject {
        val createdAt =
            System.currentTimeMillis() / 1000

        val serialized =
            buildString {
                append("[0,")
                append(jsonQuote(localNostrPublicKey))
                append(",")
                append(createdAt)
                append(",")
                append(MESSAGE_KIND)
                append(",[[")
                append(jsonQuote("p"))
                append(",")
                append(jsonQuote(recipientNostrKey))
                append("]],")
                append(jsonQuote(content))
                append("]")
            }

        val eventId =
            sha256Hex(
                serialized.toByteArray(
                    StandardCharsets.UTF_8
                )
            )

        val signature =
            NostrCrypto.sign(
                nostrIdentity.privateKey,
                hexToBytes(eventId)
            )

        return JSONObject()
            .put("id", eventId)
            .put(
                "pubkey",
                localNostrPublicKey
            )
            .put(
                "created_at",
                createdAt
            )
            .put(
                "kind",
                MESSAGE_KIND
            )
            .put(
                "tags",
                JSONArray()
                    .put(
                        JSONArray()
                            .put("p")
                            .put(recipientNostrKey)
                    )
            )
            .put(
                "content",
                content
            )
            .put(
                "sig",
                bytesToHex(signature)
            )
    }

    private fun verifyEvent(
        event: JSONObject
    ): Boolean {
        val id =
            event.optString("id")

        val pubkey =
            event.optString("pubkey")

        val createdAt =
            event.optLong(
                "created_at",
                -1L
            )

        val kind =
            event.optInt(
                "kind",
                -1
            )

        val tags =
            event.optJSONArray("tags")
                ?: return false

        val content =
            event.optString("content")

        val serialized =
            buildString {
                append("[0,")
                append(jsonQuote(pubkey))
                append(",")
                append(createdAt)
                append(",")
                append(kind)
                append(",")
                append(tags.toString().replace("\\/","/"))
                append(",")
                append(jsonQuote(content))
                append("]")
            }

        val calculatedId =
            sha256Hex(
                serialized.toByteArray(
                    StandardCharsets.UTF_8
                )
            )

        diagnostic(
            "EVENT ID CHECK — calculated=$calculatedId received=$id match=${calculatedId == id}"
        )

        if (calculatedId != id) {
            diagnostic("EVENT REJECTED — event ID mismatch")
            return false
        }

        val signatureHex =
            event.optString("sig")

        if (signatureHex.length != 128) {
            return false
        }

        return NostrCrypto.verify(
            hexToBytes(pubkey),
            hexToBytes(id),
            hexToBytes(signatureHex)
        )
    }

    private fun hasRecipientTag(
        event: JSONObject
    ): Boolean {
        val tags =
            event.optJSONArray("tags")
                ?: return false

        val localKey =
            localNostrPublicKey
                .trim()
                .lowercase()

        diagnostic(
            "RECIPIENT TAG CHECK — localNostr=$localKey"
        )

        for (
            index in 0 until tags.length()
        ) {
            val tag =
                tags.optJSONArray(index)
                    ?: continue

            val tagType =
                tag.optString(0)
                    .trim()

            val tagValue =
                tag.optString(1)
                    .trim()
                    .lowercase()

            diagnostic(
                "RECIPIENT TAG — index=$index type=$tagType value=$tagValue match=${tagType == "p" && tagValue == localKey}"
            )

            if (
                tagType == "p" &&
                tagValue == localKey
            ) {
                return true
            }
        }

        return false
    }

    private fun encodeSignal(
        signal: PeerSignal
    ): String {
        val json =
            JSONObject()
                .put("version", 1)

        when (signal) {
            is PeerSignal.Description -> {
                json
                    .put(
                        "type",
                        "description"
                    )
                    .put(
                        "description_type",
                        signal.description.type
                    )
                    .put(
                        "sdp",
                        signal.description.sdp
                    )
            }

            is PeerSignal.IceCandidate -> {
                json
                    .put(
                        "type",
                        "ice"
                    )
                    .put(
                        "sdp_mid",
                        signal.candidate.sdpMid
                    )
                    .put(
                        "sdp_m_line_index",
                        signal.candidate.sdpMLineIndex
                    )
                    .put(
                        "candidate",
                        signal.candidate.candidate
                    )
            }
        }

        return json.toString()
    }

    private fun decodeSignal(
        content: String
    ): PeerSignal? {
        val json =
            JSONObject(content)

        if (
            json.optInt("version", 0) != 1
        ) {
            return null
        }

        return when (
            json.optString("type")
        ) {
            "description" ->
                PeerSignal.Description(
                    SignalingDescription(
                        type =
                            json.getString(
                                "description_type"
                            ),
                        sdp =
                            json.getString("sdp")
                    )
                )

            "ice" ->
                PeerSignal.IceCandidate(
                    SignalingIceCandidate(
                        sdpMid =
                            if (
                                json.isNull("sdp_mid")
                            ) {
                                null
                            } else {
                                json.optString(
                                    "sdp_mid"
                                )
                            },
                        sdpMLineIndex =
                            json.getInt(
                                "sdp_m_line_index"
                            ),
                        candidate =
                            json.getString(
                                "candidate"
                            )
                    )
                )

            else -> null
        }
    }

    private fun createEvent(
        recipientNostrKey: String,
        content: String
    ): JSONObject {
        val createdAt =
            System.currentTimeMillis() / 1000

        /*
         * NIP-01 event id serialization must be the exact
         * canonical JSON representation:
         *
         * [0, pubkey, created_at, kind, tags, content]
         *
         * In particular, "/" must NOT be escaped as "\/".
         * Android org.json serializers may escape "/" and therefore
         * must not be used for the bytes that are hashed.
         */
        val serialized =
            buildString {
                append("[0,")
                append(jsonQuote(localNostrPublicKey))
                append(",")
                append(createdAt)
                append(",")
                append(SIGNAL_KIND)
                append(",[[")
                append(jsonQuote("p"))
                append(",")
                append(jsonQuote(recipientNostrKey))
                append("]],")
                append(jsonQuote(content))
                append("]")
            }

        val eventId =
            sha256Hex(
                serialized.toByteArray(
                    StandardCharsets.UTF_8
                )
            )

        diagnostic(
            "NOSTR EVENT SERIALIZED — $serialized"
        )

        diagnostic(
            "NOSTR EVENT ID — $eventId"
        )

        diagnostic(
            "NOSTR EVENT PUBKEY — $localNostrPublicKey"
        )

        diagnostic(
            "NOSTR EVENT CREATED_AT — $createdAt"
        )

        val signature =
            NostrCrypto.sign(
                nostrIdentity.privateKey,
                hexToBytes(eventId)
            )

        val localSignatureVerification =
            NostrCrypto.verify(
                hexToBytes(localNostrPublicKey),
                hexToBytes(eventId),
                signature
            )

        diagnostic(
            "LOCAL SIGNATURE VERIFY — valid=$localSignatureVerification"
        )

        return JSONObject()
            .put("id", eventId)
            .put(
                "pubkey",
                localNostrPublicKey
            )
            .put(
                "created_at",
                createdAt
            )
            .put(
                "kind",
                SIGNAL_KIND
            )
            .put(
                "tags",
                JSONArray()
                    .put(
                        JSONArray()
                            .put("p")
                            .put(recipientNostrKey)
                    )
            )
            .put("content", content)
            .put(
                "sig",
                bytesToHex(signature)
            )
    }

    private fun jsonQuote(
        value: String
    ): String {
        val result =
            StringBuilder(value.length + 2)

        result.append('"')

        for (character in value) {
            when (character) {
                '"' -> {
                    result.append('\\')
                    result.append('"')
                }

                '\\' -> {
                    result.append('\\')
                    result.append('\\')
                }

                '\b' -> {
                    result.append('\\')
                    result.append('b')
                }

                '\u000C' -> {
                    result.append('\\')
                    result.append('f')
                }

                '\n' -> {
                    result.append('\\')
                    result.append('n')
                }

                '\r' -> {
                    result.append('\\')
                    result.append('r')
                }

                '\t' -> {
                    result.append('\\')
                    result.append('t')
                }

                else -> {
                    if (character.code < 0x20) {
                        result.append(
                            "\\u%04x".format(
                                character.code
                            )
                        )
                    } else {
                        result.append(character)
                    }
                }
            }
        }

        result.append('"')

        return result.toString()
    }

    private fun sha256Hex(
        bytes: ByteArray
    ): String {
        val digest =
            java.security.MessageDigest
                .getInstance("SHA-256")
                .digest(bytes)

        return bytesToHex(digest)
    }

    private fun hexToBytes(
        hex: String
    ): ByteArray {
        require(hex.length % 2 == 0) {
            "Hex string must have even length"
        }

        return ByteArray(hex.length / 2) { index ->
            hex.substring(
                index * 2,
                index * 2 + 2
            ).toInt(16).toByte()
        }
    }

    private fun bytesToHex(
        bytes: ByteArray
    ): String {
        return bytes.joinToString("") {
            "%02x".format(
                it.toInt() and 0xff
            )
        }
    }

    companion object {

        /*
         * Keep a safety margin below the relay's observed ~128 KiB
         * event limit. This is the serialized Nostr EVENT command size,
         * not the raw photo size.
         */
        private const val MAX_RELAY_EVENT_BYTES = 60 * 1024
        private const val TAG = "NostrPeerSignaling"

        private const val SIGNAL_KIND = 20001

        /*
         * Regular event kind: retained by compliant relays, unlike
         * 20000-29999 ephemeral events.
         */
        private const val MESSAGE_KIND = 7777

        private const val MESSAGE_HISTORY_LIMIT = 200

        private const val DEFAULT_RELAY =
            "wss://nos.lol"
    }
}
