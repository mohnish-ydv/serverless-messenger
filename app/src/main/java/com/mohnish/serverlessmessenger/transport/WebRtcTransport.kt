package com.mohnish.serverlessmessenger.transport

import android.content.Context
import android.util.Log
import org.webrtc.DataChannel
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.MediaConstraints
import org.webrtc.SessionDescription

enum class TransportState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    FAILED
}

data class TransportMessage(
    val bytes: ByteArray
)

data class SignalingDescription(
    val type: String,
    val sdp: String
)

data class SignalingIceCandidate(
    val sdpMid: String?,
    val sdpMLineIndex: Int,
    val candidate: String
)

class WebRtcTransport(
    private val context: Context
) {

    /**
     * Human-readable transport diagnostics for the UI.
     */
    var onDiagnostic: ((String) -> Unit)? = null

    private fun diagnostic(message: String) {
        Log.d("WebRtcTransport", message)
        onDiagnostic?.invoke(message)

        /*
         * Persist diagnostics synchronously.
         *
         * Native WebRTC crashes can terminate the process before
         * Logcat/ApplicationExitInfo gives us the preceding messages.
         */
        try {
            context.openFileOutput(
                "webrtc-diagnostic.txt",
                Context.MODE_APPEND
            ).bufferedWriter().use { writer ->
                writer.appendLine(message)
            }
        } catch (_: Exception) {
            // Diagnostics must never affect WebRTC execution.
        }
    }

    companion object {
        private const val TAG = "WebRtcTransport"
        @Volatile
        private var initialized = false

        private fun initializeWebRtc(context: Context) {
            if (initialized) return

            synchronized(this) {
                if (initialized) return


                PeerConnectionFactory.initialize(
                    PeerConnectionFactory.InitializationOptions
                        .builder(context.applicationContext)
                        .createInitializationOptions()
                )


                initialized = true
            }
        }
    }

    private val factory: PeerConnectionFactory

    private var peerConnection: PeerConnection? = null
    private var dataChannel: DataChannel? = null

    private var dataChannelCreated = false
    private var renegotiationInProgress = false

    private val pendingRemoteIceCandidates =
        mutableListOf<SignalingIceCandidate>()

    private var remoteDescriptionSet = false

    var state: TransportState =
        TransportState.DISCONNECTED
        private set

    var onStateChanged:
        ((TransportState) -> Unit)? = null

    var onMessage:
        ((TransportMessage) -> Unit)? = null

    var onLocalDescription:
        ((SignalingDescription) -> Unit)? = null

    var onLocalIceCandidate:
        ((SignalingIceCandidate) -> Unit)? = null

    init {

        initializeWebRtc(context)


        factory =
            PeerConnectionFactory
                .builder()
                .createPeerConnectionFactory()

    }

    fun createOffer() {
        diagnostic("CONNECTING — creating local WebRTC offer")
        state = TransportState.CONNECTING
        notifyState()

        /*
         * Single-negotiation DataChannel setup.
         *
         * The DataChannel must exist before createOffer() so the
         * generated SDP contains m=application from the beginning.
         *
         * We no longer perform a second offer/answer renegotiation.
         */
        createPeerConnection(createDataChannel = true)

        val connection =
            requireNotNull(peerConnection)

        val channel =
            dataChannel
                ?: run {
                    fail("DataChannel was not created")
                    return
                }

        dataChannelCreated = true

        diagnostic(
            "DATACHANNEL CREATED BEFORE OFFER — state=${channel.state().name}"
        )

        connection.createOffer(
            object : SdpObserverAdapter() {

                override fun onCreateSuccess(
                    description: SessionDescription
                ) {
                    val hasApplication =
                        description.description.contains("m=application")

                    diagnostic(
                        "OFFER CREATED — SDP application=$hasApplication"
                    )

                    if (!hasApplication) {
                        fail(
                            "Initial SDP does not contain m=application"
                        )
                        return
                    }

                    diagnostic(
                        "LOCAL OFFER SDP SUMMARY — " +
                            "type=${description.type.canonicalForm()} " +
                            "length=${description.description.length} " +
                            "hasApplication=${description.description.contains("m=application")} " +
                            "hasIce=${description.description.contains("a=ice-ufrag:")} " +
                            "hasFingerprint=${description.description.contains("a=fingerprint:")} " +
                            "hasSetup=${description.description.contains("a=setup:")} " +
                            "hasCandidate=${description.description.contains("a=candidate:")}"
                    )

                    connection.setLocalDescription(
                        object : SdpObserverAdapter() {

                            override fun onSetSuccess() {
                                diagnostic(
                                    "LOCAL SDP SET — publishing single offer"
                                )

                                onLocalDescription?.invoke(
                                    SignalingDescription(
                                        type =
                                            description.type
                                                .canonicalForm(),
                                        sdp =
                                            description.description
                                    )
                                )
                            }

                            override fun onSetFailure(
                                error: String
                            ) {
                                fail(
                                    "setLocalDescription failed: $error"
                                )
                            }
                        },
                        description
                    )
                }

                override fun onCreateFailure(
                    error: String
                ) {
                    fail("createOffer failed: $error")
                }
            },
            org.webrtc.MediaConstraints()
        )
    }

    fun acceptOffer(
        description: SignalingDescription
    ) {
        if (description.type.lowercase() != "offer") {
            fail("Expected SDP offer")
            return
        }

        diagnostic("INCOMING OFFER — accepting remote SDP")

        state = TransportState.CONNECTING
        notifyState()

        /*
         * The same PeerConnection must handle renegotiation.
         * Only create one for the initial incoming offer.
         */
        if (peerConnection == null) {
            createPeerConnection(
                createDataChannel = false
            )
        }

        setRemoteDescriptionInternal(
            description
        )
    }

    fun acceptAnswer(
        description: SignalingDescription
    ) {
        if (description.type.lowercase() != "answer") {
            fail("Expected SDP answer")
            return
        }

        diagnostic("INCOMING ANSWER — accepting remote SDP")

        setRemoteDescriptionInternal(
            description
        )
    }

    private fun setRemoteDescriptionInternal(
        description: SignalingDescription
    ) {
        val connection =
            peerConnection
                ?: run {
                    fail("Peer connection does not exist")
                    return
                }

        val type =
            when (description.type.lowercase()) {
                "offer" ->
                    SessionDescription.Type.OFFER

                "answer" ->
                    SessionDescription.Type.ANSWER

                else -> {
                    fail("Unsupported SDP type: ${description.type}")
                    return
                }
            }

        connection.setRemoteDescription(
            object : SdpObserverAdapter() {

                override fun onSetSuccess() {
                    diagnostic(
                        "REMOTE SDP SET — type=${type.canonicalForm()}"
                    )

                    remoteDescriptionSet = true

                    if (
                        type ==
                        SessionDescription.Type.OFFER
                    ) {
                        createAnswer()
                    } else if (
                        type ==
                        SessionDescription.Type.ANSWER
                    ) {
                        diagnostic(
                            "INITIAL ANSWER ACCEPTED — negotiation complete"
                        )

                        drainPendingRemoteIce()
                    }
                }

                override fun onSetFailure(
                    error: String
                ) {
                    fail(error)
                }
            },
            SessionDescription(
                type,
                description.sdp
            )
        )
    }

    private fun createAnswer() {

        val connection =
            peerConnection
                ?: run {
                    fail("Peer connection does not exist")
                    return
                }

        state =
            TransportState.CONNECTING

        notifyState()

        connection.createAnswer(
            object : SdpObserverAdapter() {

                override fun onCreateSuccess(
                    description: SessionDescription
                ) {
                    Log.e(
                        TAG,
                        "ANSWER HAS DATA SECTION = ${
                            description.description.contains("m=application")
                        } " +
                        "signalingState=${connection.signalingState().name}"
                    )

                    diagnostic(
                        "LOCAL ANSWER SDP SUMMARY — " +
                            "type=${description.type.canonicalForm()} " +
                            "length=${description.description.length} " +
                            "hasApplication=${description.description.contains("m=application")} " +
                            "hasIce=${description.description.contains("a=ice-ufrag:")} " +
                            "hasFingerprint=${description.description.contains("a=fingerprint:")} " +
                            "hasSetup=${description.description.contains("a=setup:")} " +
                            "hasCandidate=${description.description.contains("a=candidate:")}"
                    )

                    connection.setLocalDescription(
                        object : SdpObserverAdapter() {

                            override fun onSetSuccess() {
                                diagnostic(
                                    "LOCAL ANSWER SET — publishing answer"
                                )

                                onLocalDescription?.invoke(
                                    SignalingDescription(
                                        type =
                                            description.type
                                                .canonicalForm(),
                                        sdp =
                                            description.description
                                    )
                                )

                                drainPendingRemoteIce()
                            }

                            override fun onSetFailure(
                                error: String
                            ) {
                                fail(error)
                            }
                        },
                        description
                    )
                }

                override fun onCreateFailure(
                    error: String
                ) {
                    fail(error)
                }
            },
            org.webrtc.MediaConstraints()
        )
    }

    private fun drainPendingRemoteIce() {
        val pending =
            pendingRemoteIceCandidates.toList()

        pendingRemoteIceCandidates.clear()

        diagnostic(
            "DRAINING REMOTE ICE — count=${pending.size}"
        )

        for (candidate in pending) {
            addRemoteIceCandidateNow(candidate)
        }
    }

    fun addRemoteIceCandidate(
        candidate: SignalingIceCandidate
    ) {
        diagnostic("REMOTE ICE CANDIDATE RECEIVED")

        if (!remoteDescriptionSet) {
            diagnostic(
                "REMOTE ICE QUEUED — remote SDP not set"
            )

            pendingRemoteIceCandidates.add(candidate)
            return
        }

        addRemoteIceCandidateNow(candidate)
    }

    private fun addRemoteIceCandidateNow(
        candidate: SignalingIceCandidate
    ) {
        val connection =
            peerConnection
                ?: run {
                    diagnostic(
                        "REMOTE ICE DROPPED — PeerConnection does not exist"
                    )
                    return
                }

        diagnostic(
            "ADDING REMOTE ICE — mid=${candidate.sdpMid} index=${candidate.sdpMLineIndex}"
        )

        val accepted =
            connection.addIceCandidate(
                org.webrtc.IceCandidate(
                    candidate.sdpMid,
                    candidate.sdpMLineIndex,
                    candidate.candidate
                )
            )

        diagnostic(
            "REMOTE ICE ADD RESULT — $accepted"
        )
    }

    fun close() {

        dataChannel?.close()
        dataChannel = null

        peerConnection?.close()
        peerConnection = null

        state =
            TransportState.DISCONNECTED

        notifyState()
    }

    private fun renegotiateDataChannel() {

        if (!dataChannelCreated) {
            diagnostic(
                "RENEGOTIATION SKIPPED — DataChannel not created"
            )
            return
        }

        if (renegotiationInProgress) {
            diagnostic(
                "RENEGOTIATION SKIPPED — already in progress"
            )
            return
        }

        val connection =
            peerConnection
                ?: run {
                    diagnostic(
                        "RENEGOTIATION FAILED — PeerConnection missing"
                    )
                    return
                }

        val signalingState =
            connection.signalingState()

        diagnostic(
            "RENEGOTIATION CHECK — signaling state=${signalingState.name}"
        )

        if (
            signalingState !=
            PeerConnection.SignalingState.STABLE
        ) {
            diagnostic(
                "RENEGOTIATION WAITING — signaling state=${signalingState.name}"
            )
            return
        }

        renegotiationInProgress = true

        diagnostic(
            "CREATING DATA CHANNEL OFFER"
        )

        connection.createOffer(
            object : SdpObserverAdapter() {

                override fun onCreateSuccess(
                    description: SessionDescription
                ) {

                    val hasApplication =
                        description.description.contains(
                            "m=application"
                        )

                    diagnostic(
                        "DATA CHANNEL OFFER CREATED — SDP application=$hasApplication"
                    )

                    if (!hasApplication) {
                        renegotiationInProgress = false

                        fail(
                            "Renegotiated SDP does not contain m=application"
                        )

                        return
                    }

                    connection.setLocalDescription(
                        object : SdpObserverAdapter() {

                            override fun onSetSuccess() {

                                diagnostic(
                                    "RENEGOTIATED LOCAL SDP SET — publishing offer"
                                )

                                renegotiationInProgress = false

                                onLocalDescription?.invoke(
                                    SignalingDescription(
                                        type =
                                            description.type
                                                .canonicalForm(),
                                        sdp =
                                            description.description
                                    )
                                )
                            }

                            override fun onSetFailure(
                                error: String
                            ) {

                                renegotiationInProgress = false

                                fail(
                                    "Renegotiated setLocalDescription failed: $error"
                                )
                            }
                        },
                        description
                    )
                }

                override fun onCreateFailure(
                    error: String
                ) {

                    renegotiationInProgress = false

                    fail(
                        "Renegotiated createOffer failed: $error"
                    )
                }
            },
            org.webrtc.MediaConstraints()
        )
    }

    private fun createPeerConnection(
        createDataChannel: Boolean
    ) {

        peerConnection?.close()

        dataChannel = null
        dataChannelCreated = false
        renegotiationInProgress = false

        pendingRemoteIceCandidates.clear()
        remoteDescriptionSet = false

        /*
         * Deliberately empty ICE server list.
         *
         * This is the strict zero-server transport mode:
         * no STUN and no TURN.
         *
         * WebRTC can therefore use directly reachable
         * host candidates. NAT traversal limitations are
         * intentionally exposed rather than hidden behind
         * a relay.
         */
        /*
         * STUN is used only for ICE candidate discovery.
         *
         * It does NOT carry application messages.
         * Messages still travel through the WebRTC DataChannel.
         *
         * There is deliberately no TURN server here, so this
         * transport does not introduce a permanent application
         * relay for message traffic.
         */
        val iceServers =
            listOf(
                PeerConnection.IceServer
                    .builder(
                        "stun:stun.l.google.com:19302"
                    )
                    .createIceServer()
            )

        val configuration =
            PeerConnection.RTCConfiguration(
                iceServers
            )

        peerConnection =
            factory.createPeerConnection(
                configuration,
                object : PeerConnection.Observer {

                    override fun onIceCandidate(
                        candidate: org.webrtc.IceCandidate
                    ) {
                        diagnostic("LOCAL ICE CANDIDATE — ${candidate.sdp}")

                        onLocalIceCandidate?.invoke(
                            SignalingIceCandidate(
                                sdpMid = candidate.sdpMid,
                                sdpMLineIndex = candidate.sdpMLineIndex,
                                candidate = candidate.sdp
                            )
                        )
                    }

                    override fun onDataChannel(
                        channel: DataChannel
                    ) {
                        diagnostic("REMOTE DATACHANNEL RECEIVED")
                        attachDataChannel(channel)
                    }

                    override fun onConnectionChange(
                        newState:
                            PeerConnection.PeerConnectionState
                    ) {
                        diagnostic("PEER CONNECTION STATE — ${newState.name}")

                        when (newState) {
                            PeerConnection.PeerConnectionState.NEW ->
                                updateState(
                                    TransportState.CONNECTING
                                )

                            PeerConnection.PeerConnectionState.CONNECTING ->
                                updateState(
                                    TransportState.CONNECTING
                                )

                            PeerConnection.PeerConnectionState.CONNECTED ->
                                updateState(
                                    TransportState.CONNECTED
                                )

                            PeerConnection.PeerConnectionState.DISCONNECTED ->
                                updateState(
                                    TransportState.DISCONNECTED
                                )

                            PeerConnection.PeerConnectionState.FAILED ->
                                updateState(
                                    TransportState.FAILED
                                )

                            PeerConnection.PeerConnectionState.CLOSED ->
                                updateState(
                                    TransportState.DISCONNECTED
                                )
                        }
                    }

                    override fun onIceConnectionChange(
                        state:
                            PeerConnection.IceConnectionState
                    ) {
                        diagnostic("ICE CONNECTION STATE — ${state.name}")
                    }

                    override fun onSignalingChange(
                        state:
                            PeerConnection.SignalingState
                    ) {
                        diagnostic("SIGNALING STATE — ${state.name}")
                    }

                    override fun onIceGatheringChange(
                        state:
                            PeerConnection.IceGatheringState
                    ) {
                        diagnostic("ICE GATHERING STATE — ${state.name}")
                    }

                    override fun onIceConnectionReceivingChange(
                        receiving: Boolean
                    ) = Unit

                    override fun onIceCandidatesRemoved(
                        candidates:
                            Array<out org.webrtc.IceCandidate>
                    ) = Unit

                    override fun onAddStream(
                        stream: org.webrtc.MediaStream
                    ) = Unit

                    override fun onRemoveStream(
                        stream: org.webrtc.MediaStream
                    ) = Unit

                    override fun onRenegotiationNeeded() {
                        /*
                         * DataChannel negotiation is performed explicitly
                         * by createOffer(). Do not start a second offer here.
                         */
                        diagnostic(
                            "RENEGOTIATION NEEDED — ignored (explicit offer in progress)"
                        )
                    }

                    override fun onAddTrack(
                        receiver:
                            org.webrtc.RtpReceiver,
                        mediaStreams:
                            Array<out org.webrtc.MediaStream>
                    ) = Unit

                    override fun onTrack(
                        transceiver:
                            org.webrtc.RtpTransceiver
                    ) = Unit
                }
            )

        if (
            createDataChannel &&
            peerConnection != null
        ) {
            val init =
                DataChannel.Init().apply {
                    ordered = true
                }

            dataChannel =
                peerConnection!!.createDataChannel(
                    "serverless-messages",
                    init
                )

            attachDataChannel(
                requireNotNull(dataChannel)
            )
        }
    }

    fun send(bytes: ByteArray): Boolean {
        val channel =
            dataChannel
                ?: run {
                    diagnostic("SEND FAILED — DataChannel does not exist")
                    return false
                }

        val channelState = channel.state()

        if (channelState != DataChannel.State.OPEN) {
            diagnostic(
                "SEND FAILED — DataChannel state=${channelState.name}"
            )
            return false
        }

        return try {
            val buffer =
                DataChannel.Buffer(
                    java.nio.ByteBuffer.wrap(bytes),
                    false
                )

            val sent = channel.send(buffer)

            diagnostic(
                if (sent) {
                    "SEND OK — ${bytes.size} bytes"
                } else {
                    "SEND FAILED — DataChannel.send returned false"
                }
            )

            sent
        } catch (e: Throwable) {
            diagnostic(
                "SEND ERROR — ${
                    e.message ?: e.javaClass.simpleName
                }"
            )
            false
        }
    }

    private fun attachDataChannel(channel: DataChannel) {

        diagnostic(
            "DATACHANNEL ATTACHED — state=${channel.state().name}"
        )

        dataChannel = channel

        channel.registerObserver(
            object : DataChannel.Observer {

                override fun onBufferedAmountChange(
                    previousAmount: Long
                ) = Unit

                override fun onStateChange() {

                    val channelState =
                        channel.state()

                    diagnostic(
                        "DATACHANNEL STATE — ${channelState.name}"
                    )

                    when (channelState) {

                        DataChannel.State.OPEN ->
                            updateState(
                                TransportState.CONNECTED
                            )

                        DataChannel.State.CLOSING,
                        DataChannel.State.CLOSED ->
                            updateState(
                                TransportState.DISCONNECTED
                            )

                        DataChannel.State.CONNECTING ->
                            updateState(
                                TransportState.CONNECTING
                            )
                    }
                }

                override fun onMessage(
                    buffer: DataChannel.Buffer
                ) {

                    diagnostic(
                        "DATACHANNEL MESSAGE RECEIVED"
                    )

                    val bytes =
                        ByteArray(
                            buffer.data.remaining()
                        )

                    buffer.data.get(bytes)

                    onMessage?.invoke(
                        TransportMessage(bytes)
                    )
                }
            }
        )
    }

    private fun updateState(
        newState: TransportState
    ) {
        state = newState
        notifyState()
    }

    private fun notifyState() {
        onStateChanged?.invoke(state)
    }

    private fun fail(
        error: String
    ) {
        diagnostic(
            "ERROR — $error"
        )

        updateState(
            TransportState.FAILED
        )
    }
}

private open class SdpObserverAdapter :
    org.webrtc.SdpObserver {

    override fun onCreateSuccess(
        description: SessionDescription
    ) = Unit

    override fun onSetSuccess() = Unit

    override fun onCreateFailure(
        error: String
    ) = Unit

    override fun onSetFailure(
        error: String
    ) = Unit
}
