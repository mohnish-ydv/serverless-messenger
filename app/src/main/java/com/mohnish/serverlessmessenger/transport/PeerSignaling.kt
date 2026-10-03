package com.mohnish.serverlessmessenger.transport

import com.mohnish.serverlessmessenger.security.EncryptedMessagePacket

/**
 * Signaling transports WebRTC negotiation metadata.
 */
interface PeerSignaling {

    fun publish(
        peerId: String,
        signal: PeerSignal
    )

    fun setListener(
        peerId: String,
        listener: (PeerSignal) -> Unit
    )

    fun removeListener(
        peerId: String
    )

    fun setIncomingListener(
        listener: (
            peerId: String,
            signingPublicKeyBase64: String,
            agreementPublicKeyBase64: String,
            signal: PeerSignal
        ) -> Unit
    )

    fun setDiagnosticListener(
        listener: (String) -> Unit
    )
}

/**
 * Encrypted application-message transport.
 *
 * The implementation is Nostr-backed in the current MVP.
 */
interface EncryptedMessageTransport {

    fun publishMessage(
        peerId: String,
        packet: EncryptedMessagePacket
    ): Boolean

    fun setMessageListener(
        listener: (
            peerId: String,
            signingPublicKeyBase64: String,
            packet: EncryptedMessagePacket
        ) -> Unit
    )

    fun setMessageConnectionListener(
        listener: (Boolean) -> Unit
    )
}

sealed class PeerSignal {

    data class Description(
        val description: SignalingDescription
    ) : PeerSignal()

    data class IceCandidate(
        val candidate: SignalingIceCandidate
    ) : PeerSignal()
}
