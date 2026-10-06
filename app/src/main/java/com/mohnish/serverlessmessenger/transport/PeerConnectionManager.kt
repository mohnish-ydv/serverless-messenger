package com.mohnish.serverlessmessenger.transport

import android.content.Context
import android.util.Log
import com.mohnish.serverlessmessenger.data.MessageOutbox
import com.mohnish.serverlessmessenger.data.MessageStore
import com.mohnish.serverlessmessenger.security.EncryptedMessagePacket
import com.mohnish.serverlessmessenger.security.MessageCrypto
import com.mohnish.serverlessmessenger.security.MessageEnvelope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

data class PeerConnectionState(
    val peerId: String,
    val state: TransportState
)

class PeerConnectionManager(
    context: Context,
    private val messageStore: MessageStore,
    private val signaling: PeerSignaling,
    private val scope: CoroutineScope =
        CoroutineScope(
            SupervisorJob() +
                Dispatchers.IO
        )
) {

    companion object {
        private const val TAG =
            "PeerConnectionManager"
    }

    private data class PeerSession(
        val peerId: String,
        val signingPublicKeyBase64: String,
        val agreementPublicKeyBase64: String
    )

    private val appContext =
        context.applicationContext

    private val outbox =
        MessageOutbox(appContext)

    private val sessions =
        mutableMapOf<String, PeerSession>()

    private val webRtcTransports =
        mutableMapOf<String, WebRtcTransport>()

    private val diagnosticHistory =
        mutableListOf<Pair<String, String>>()

    private var diagnosticCallback:
        ((String, String) -> Unit)? = null

    private val messageTransport:
        EncryptedMessageTransport? =
        signaling as? EncryptedMessageTransport

    var onDiagnostic:
        ((String, String) -> Unit)?
        get() = diagnosticCallback
        set(value) {
            diagnosticCallback = value

            if (value != null) {
                synchronized(
                    diagnosticHistory
                ) {
                    diagnosticHistory.forEach {
                        (peerId, message) ->

                        value.invoke(
                            peerId,
                            message
                        )
                    }
                }
            }
        }

    var onStateChanged:
        ((PeerConnectionState) -> Unit)? =
        null

    var onMessageReceived:
        ((String, String) -> Unit)? =
        null

    init {

        /*
         * WebRTC negotiation signals arrive through the existing
         * encrypted Nostr signaling transport.
         */
        signaling.setIncomingListener {
                peerId,
                signingPublicKeyBase64,
                agreementPublicKeyBase64,
                signal ->

            handleWebRtcSignal(
                peerId = peerId,
                signingPublicKeyBase64 =
                    signingPublicKeyBase64,
                agreementPublicKeyBase64 =
                    agreementPublicKeyBase64,
                signal = signal
            )
        }

        val transport = messageTransport

        if (transport == null) {
            emitDiagnostic(
                "SYSTEM",
                "ERROR — signaling does not implement encrypted message transport"
            )
        } else {
            signaling.setDiagnosticListener { message ->
                Log.d(
                    TAG,
                    "NOSTR diagnostic: $message"
                )

                emitDiagnostic(
                    "NOSTR",
                    message
                )
            }

            transport.setMessageListener {
                    peerId,
                    signingPublicKeyBase64,
                    packet ->

                handleIncomingPacket(
                    peerId = peerId,
                    signingPublicKeyBase64 = signingPublicKeyBase64,
                    packet = packet
                )
            }

            transport.setMessageConnectionListener { connected ->

                val currentSessions =
                    synchronized(sessions) {
                        sessions.values.toList()
                    }

                if (connected) {
                    currentSessions.forEach { session ->
                        onStateChanged?.invoke(
                            PeerConnectionState(
                                peerId = session.peerId,
                                state = TransportState.CONNECTED
                            )
                        )

                        drainOutbox(session)
                    }
                } else {
                    currentSessions.forEach { session ->
                        onStateChanged?.invoke(
                            PeerConnectionState(
                                peerId = session.peerId,
                                state = TransportState.DISCONNECTED
                            )
                        )
                    }
                }
            }
        }
    }

    private fun emitDiagnostic(
        peerId: String,
        message: String
    ) {
        Log.d(
            TAG,
            "diagnostic peerId=$peerId message=$message"
        )

        synchronized(
            diagnosticHistory
        ) {
            diagnosticHistory.add(
                peerId to message
            )

            if (
                diagnosticHistory.size > 100
            ) {
                diagnosticHistory.removeAt(0)
            }
        }

        diagnosticCallback?.invoke(
            peerId,
            message
        )
    }

    private fun createWebRtcTransport(
        session: PeerSession
    ): WebRtcTransport {

        val existing =
            synchronized(webRtcTransports) {
                webRtcTransports[session.peerId]
            }

        if (existing != null) {
            return existing
        }

        val transport =
            WebRtcTransport(appContext)

        transport.onDiagnostic = { message ->
            emitDiagnostic(
                session.peerId,
                "WEBRTC — $message"
            )
        }

        transport.onStateChanged = { state ->
            emitDiagnostic(
                session.peerId,
                "WEBRTC STATE — ${state.name}"
            )

            onStateChanged?.invoke(
                PeerConnectionState(
                    peerId = session.peerId,
                    state = state
                )
            )
        }

        transport.onLocalDescription = { description ->
            emitDiagnostic(
                session.peerId,
                "WEBRTC LOCAL DESCRIPTION — ${description.type}"
            )

            signaling.publish(
                peerId = session.peerId,
                signal =
                    PeerSignal.Description(
                        description = description
                    )
            )
        }

        transport.onLocalIceCandidate = { candidate ->
            emitDiagnostic(
                session.peerId,
                "WEBRTC LOCAL ICE CANDIDATE"
            )

            signaling.publish(
                peerId = session.peerId,
                signal =
                    PeerSignal.IceCandidate(
                        candidate = candidate
                    )
            )
        }

        synchronized(webRtcTransports) {
            webRtcTransports[session.peerId] = transport
        }

        return transport
    }

    private fun handleWebRtcSignal(
        peerId: String,
        signingPublicKeyBase64: String,
        agreementPublicKeyBase64: String,
        signal: PeerSignal
    ) {
        /*
         * Nostr's WebSocket callback carries both WebRTC signaling
         * and normal messages. Never perform PeerConnection work
         * directly on that callback thread.
         */
        scope.launch {
            handleWebRtcSignalOnIo(
                peerId = peerId,
                signingPublicKeyBase64 = signingPublicKeyBase64,
                agreementPublicKeyBase64 = agreementPublicKeyBase64,
                signal = signal
            )
        }
    }

    private fun handleWebRtcSignalOnIo(
        peerId: String,
        signingPublicKeyBase64: String,
        agreementPublicKeyBase64: String,
        signal: PeerSignal
    ) {

        val session =
            synchronized(sessions) {
                sessions[peerId]
            }
                ?: PeerSession(
                    peerId = peerId,
                    signingPublicKeyBase64 =
                        signingPublicKeyBase64,
                    agreementPublicKeyBase64 =
                        agreementPublicKeyBase64
                ).also { newSession ->
                    synchronized(sessions) {
                        sessions[peerId] = newSession
                    }
                }

        val transport =
            createWebRtcTransport(session)

        when (signal) {

            is PeerSignal.Description -> {

                emitDiagnostic(
                    peerId,
                    "WEBRTC REMOTE DESCRIPTION — ${signal.description.type}"
                )

                when (
                    signal.description.type.lowercase()
                ) {

                    "offer" ->
                        transport.acceptOffer(
                            signal.description
                        )

                    "answer" ->
                        transport.acceptAnswer(
                            signal.description
                        )

                    else ->
                        emitDiagnostic(
                            peerId,
                            "WEBRTC UNKNOWN DESCRIPTION — ${signal.description.type}"
                        )
                }
            }

            is PeerSignal.IceCandidate -> {

                emitDiagnostic(
                    peerId,
                    "WEBRTC REMOTE ICE CANDIDATE"
                )

                transport.addRemoteIceCandidate(
                    signal.candidate
                )
            }
        }
    }

    /**
     * Registers a known contact as a messaging peer.
     *
     * No WebRTC connection is created.
     */
    fun connectToContact(
        peerId: String,
        signingPublicKeyBase64: String,
        agreementPublicKeyBase64: String
    ) {

        val session =
            PeerSession(
                peerId = peerId,
                signingPublicKeyBase64 =
                    signingPublicKeyBase64,
                agreementPublicKeyBase64 =
                    agreementPublicKeyBase64
            )

        synchronized(sessions) {
            sessions[peerId] = session
        }

        emitDiagnostic(
            peerId,
            "PEER SESSION READY — starting WebRTC"
        )

        /*
         * WebRTC signals use the single global incoming listener
         * registered in init().
         *
         * Do not install a per-peer Nostr listener here. The same
         * Nostr transport carries normal chat messages, so WebRTC
         * routing must not compete with the message transport.
         */

        val transport =
            createWebRtcTransport(session)

        onStateChanged?.invoke(
            PeerConnectionState(
                peerId = peerId,
                state = TransportState.CONNECTING
            )
        )

        emitDiagnostic(
            peerId,
            "WEBRTC — creating offer"
        )

        transport.createOffer()
    }

    /**
     * Compatibility API for the old WebRTC call sites.
     *
     * It now only registers the peer.
     */
    fun connect(
        peerId: String,
        signingPublicKeyBase64: String,
        agreementPublicKeyBase64: String
    ) {
        connectToContact(
            peerId =
                peerId,
            signingPublicKeyBase64 =
                signingPublicKeyBase64,
            agreementPublicKeyBase64 =
                agreementPublicKeyBase64
        )
    }

    /**
     * WebRTC is no longer used by the MVP.
     *
     * Kept only so existing callers do not break.
     */
    fun acceptIncomingOffer(
        peerId: String,
        signingPublicKeyBase64: String,
        agreementPublicKeyBase64: String,
        offer: SignalingDescription
    ) {

        val session =
            PeerSession(
                peerId = peerId,
                signingPublicKeyBase64 =
                    signingPublicKeyBase64,
                agreementPublicKeyBase64 =
                    agreementPublicKeyBase64
            )

        synchronized(sessions) {
            sessions[peerId] = session
        }

        val transport =
            createWebRtcTransport(session)

        emitDiagnostic(
            peerId,
            "WEBRTC — accepting incoming offer"
        )

        transport.acceptOffer(offer)
    }


    fun send(
        peerId: String,
        text: String
    ): Boolean {
        if (text.isBlank()) {
            return false
        }

        return send(
            peerId = peerId,
            envelope = MessageEnvelope.text(text)
        )
    }

    fun send(
        peerId: String,
        envelope: MessageEnvelope
    ): Boolean {

        val session =
            synchronized(
                sessions
            ) {
                sessions[peerId]
            }
                ?: run {
                    emitDiagnostic(
                        peerId,
                        "SEND ABORTED — NO PEER SESSION"
                    )
                    return false
                }

        if (
            envelope.type == MessageEnvelope.TYPE_TEXT &&
            envelope.text.isBlank()
        ) {
            return false
        }

        val packet =
            try {
                MessageCrypto.encrypt(
                    context =
                        appContext,
                    envelope =
                        envelope,
                    recipientIdentityId =
                        session.peerId,
                    recipientAgreementPublicKeyBase64 =
                        session.agreementPublicKeyBase64
                )
            } catch (e: Exception) {

                emitDiagnostic(
                    peerId,
                    "MESSAGE ENCRYPT FAILED — ${e.message}"
                )

                return false
            }

        val sent =
            messageTransport?.publishMessage(
                peerId =
                    peerId,
                packet =
                    packet
            )
                ?: false

        if (!sent) {
            return false
        }

        scope.launch {

            messageStore.addEncryptedMessage(
                conversationId =
                    peerId,
                packet =
                    packet,
                mine =
                    true,
                localText =
                    envelope.text,
                localEnvelope =
                    envelope
            )
        }

        emitDiagnostic(
            peerId,
            "MESSAGE PUBLISHED — packet=${packet.id} type=${envelope.type}"
        )

        onStateChanged?.invoke(
            PeerConnectionState(
                peerId =
                    peerId,
                state =
                    TransportState.CONNECTED
            )
        )

        return true
    }

    private fun publishControlEnvelope(
        peerId: String,
        envelope: MessageEnvelope
    ): Boolean {

        val session =
            synchronized(sessions) {
                sessions[peerId]
            }
                ?: return false

        val packet =
            runCatching {
                MessageCrypto.encrypt(
                    context =
                        appContext,
                    envelope =
                        envelope,
                    recipientIdentityId =
                        session.peerId,
                    recipientAgreementPublicKeyBase64 =
                        session.agreementPublicKeyBase64
                )
            }.getOrNull()
                ?: return false

        val sent =
            messageTransport?.publishMessage(
                peerId =
                    peerId,
                packet =
                    packet
            )
                ?: false

        if (sent) {
            emitDiagnostic(
                peerId,
                "CONTROL ENVELOPE PUBLISHED — type=${envelope.type} target=${envelope.targetMessageId}"
            )
        }

        return sent
    }

    fun sendReadAcks(
        peerId: String,
        messageIds: List<String>
    ) {
        if (messageIds.isEmpty()) {
            return
        }

        scope.launch {
            messageIds.forEach { messageId ->
                publishControlEnvelope(
                    peerId = peerId,
                    envelope =
                        MessageEnvelope(
                            type =
                                MessageEnvelope.TYPE_READ_ACK,
                            targetMessageId =
                                messageId
                        )
                )
            }
        }
    }

    fun sendEdit(
        peerId: String,
        messageId: String,
        newText: String
    ): Boolean {
        if (newText.isBlank()) {
            return false
        }

        val sent =
            publishControlEnvelope(
                peerId = peerId,
                envelope =
                    MessageEnvelope(
                        type =
                            MessageEnvelope.TYPE_EDIT,
                        text =
                            newText,
                        targetMessageId =
                            messageId
                    )
            )

        if (sent) {
            scope.launch {
                messageStore.editMessage(
                    conversationId = peerId,
                    messageId = messageId,
                    newText = newText
                )
            }

            emitDiagnostic(
                peerId,
                "EDIT PUBLISHED — target=$messageId"
            )
        }

        return sent
    }

    fun sendDelete(
        peerId: String,
        messageId: String
    ): Boolean {
        val sent =
            publishControlEnvelope(
                peerId = peerId,
                envelope =
                    MessageEnvelope(
                        type =
                            MessageEnvelope.TYPE_DELETE,
                        targetMessageId =
                            messageId
                    )
            )

        if (sent) {
            scope.launch {
                messageStore.deleteMessage(
                    conversationId = peerId,
                    messageId = messageId
                )
            }

            emitDiagnostic(
                peerId,
                "DELETE PUBLISHED — target=$messageId"
            )
        }

        return sent
    }

    fun sendReaction(
        peerId: String,
        messageId: String,
        reaction: String
    ): Boolean {
        if (reaction.isBlank()) {
            return false
        }

        val sent =
            publishControlEnvelope(
                peerId = peerId,
                envelope =
                    MessageEnvelope(
                        type =
                            MessageEnvelope.TYPE_REACTION,
                        targetMessageId =
                            messageId,
                        reaction =
                            reaction
                    )
            )

        if (sent) {
            scope.launch {
                messageStore.setReaction(
                    conversationId = peerId,
                    messageId = messageId,
                    reaction = reaction
                )
            }

            emitDiagnostic(
                peerId,
                "REACTION PUBLISHED — target=$messageId reaction=$reaction"
            )
        }

        return sent
    }

    private fun drainOutbox(
        session: PeerSession
    ) {
        scope.launch {

            val pending =
                outbox.forPeer(
                    session.peerId
                )

            for (item in pending) {

                if (
                    item.text.isBlank() &&
                    item.envelope.mediaBase64.isNullOrBlank()
                ) {
                    outbox.remove(
                        item.id
                    )
                    continue
                }

                val packet =
                    runCatching {
                        MessageCrypto.encrypt(
                            context =
                                appContext,
                            envelope =
                                item.envelope,
                            recipientIdentityId =
                                session.peerId,
                            recipientAgreementPublicKeyBase64 =
                                session.agreementPublicKeyBase64
                        )
                    }.getOrNull()
                        ?: continue

                val sent =
                    messageTransport?.publishMessage(
                        peerId =
                            session.peerId,
                        packet =
                            packet
                    )
                        ?: false

                if (!sent) {
                    break
                }

                messageStore.addEncryptedMessage(
                    conversationId =
                        session.peerId,
                    packet =
                        packet,
                    mine =
                        true,
                    localText =
                        item.envelope.text,
                    localEnvelope =
                        item.envelope
                )

                outbox.remove(
                    item.id
                )

                emitDiagnostic(
                    session.peerId,
                    "OUTBOX MESSAGE PUBLISHED — packet=${packet.id}"
                )
            }
        }
    }

    private fun handleIncomingPacket(
        peerId: String,
        signingPublicKeyBase64: String,
        packet: EncryptedMessagePacket
    ) {

        if (
            !MessageCrypto.verifyPacket(
                packet =
                    packet,
                senderSigningPublicKeyBase64 =
                    signingPublicKeyBase64
            )
        ) {
            emitDiagnostic(
                peerId,
                "INCOMING MESSAGE REJECTED — device signature invalid"
            )
            return
        }

        val decrypted =
            runCatching {
                MessageCrypto.decrypt(
                    context =
                        appContext,
                    packet =
                        packet
                )
            }.getOrNull()
                ?: run {
                    emitDiagnostic(
                        peerId,
                        "INCOMING MESSAGE REJECTED — decrypt failed"
                    )
                    return
                }

        val envelope = decrypted.envelope

        when (envelope.type) {

            MessageEnvelope.TYPE_EDIT -> {
                val targetMessageId =
                    envelope.targetMessageId

                if (!targetMessageId.isNullOrBlank()) {
                    scope.launch {
                        messageStore.applyRemoteEdit(
                            conversationId = peerId,
                            messageId = targetMessageId,
                            newText = envelope.text
                        )

                        emitDiagnostic(
                            peerId,
                            "REMOTE EDIT APPLIED — target=$targetMessageId"
                        )

                        onMessageReceived?.invoke(
                            peerId,
                            envelope.text
                        )
                    }
                }

                return
            }

            MessageEnvelope.TYPE_DELETE -> {
                val targetMessageId =
                    envelope.targetMessageId

                if (!targetMessageId.isNullOrBlank()) {
                    scope.launch {
                        messageStore.applyRemoteDelete(
                            conversationId = peerId,
                            messageId = targetMessageId
                        )

                        emitDiagnostic(
                            peerId,
                            "REMOTE DELETE APPLIED — target=$targetMessageId"
                        )

                        onMessageReceived?.invoke(
                            peerId,
                            "This message was deleted"
                        )
                    }
                }

                return
            }

            MessageEnvelope.TYPE_REACTION -> {
                val targetMessageId =
                    envelope.targetMessageId

                val reaction =
                    envelope.reaction

                if (
                    !targetMessageId.isNullOrBlank() &&
                    !reaction.isNullOrBlank()
                ) {
                    scope.launch {
                        messageStore.applyRemoteReaction(
                            conversationId = peerId,
                            messageId = targetMessageId,
                            reaction = reaction
                        )

                        emitDiagnostic(
                            peerId,
                            "REMOTE REACTION APPLIED — target=$targetMessageId reaction=$reaction"
                        )

                        onMessageReceived?.invoke(
                            peerId,
                            reaction
                        )
                    }
                }

                return
            }

            MessageEnvelope.TYPE_DELIVERY_ACK -> {
                val targetMessageId =
                    envelope.targetMessageId

                if (!targetMessageId.isNullOrBlank()) {
                    scope.launch {
                        messageStore.markMessageDelivered(
                            conversationId = peerId,
                            messageId = targetMessageId
                        )
                    }

                    emitDiagnostic(
                        peerId,
                        "DELIVERY ACK RECEIVED — target=$targetMessageId"
                    )
                }

                return
            }

            MessageEnvelope.TYPE_READ_ACK -> {
                val targetMessageId =
                    envelope.targetMessageId

                if (!targetMessageId.isNullOrBlank()) {
                    scope.launch {
                        messageStore.markMessageRead(
                            conversationId = peerId,
                            messageId = targetMessageId
                        )
                    }

                    emitDiagnostic(
                        peerId,
                        "READ ACK RECEIVED — target=$targetMessageId"
                    )
                }

                return
            }
        }

        scope.launch {

            messageStore.addEncryptedMessage(
                conversationId =
                    peerId,
                packet =
                    packet,
                mine =
                    false,
                localText =
                    decrypted.text,
                localEnvelope =
                    envelope
            )

            publishControlEnvelope(
                peerId = peerId,
                envelope =
                    MessageEnvelope(
                        type =
                            MessageEnvelope.TYPE_DELIVERY_ACK,
                        targetMessageId =
                            packet.id
                    )
            )

            onMessageReceived?.invoke(
                peerId,
                decrypted.text
            )
        }

        emitDiagnostic(
            peerId,
            "INCOMING MESSAGE ACCEPTED — packet=${packet.id} type=${envelope.type}"
        )
    }

    fun close(
        peerId: String
    ) {

        synchronized(
            sessions
        ) {
            sessions.remove(
                peerId
            )
        }

        onStateChanged?.invoke(
            PeerConnectionState(
                peerId =
                    peerId,
                state =
                    TransportState.DISCONNECTED
            )
        )
    }

    fun closeAll() {

        val peers =
            synchronized(
                sessions
            ) {
                sessions.keys.toList()
            }

        peers.forEach {
            close(it)
        }
    }
}
