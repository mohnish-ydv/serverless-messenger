package com.mohnish.serverlessmessenger.transport

/**
 * Test-only signaling implementation.
 *
 * This exists so two PeerConnectionManager instances in the
 * same process can exercise offer/answer/ICE without a server.
 *
 * It must NOT be treated as the production discovery mechanism.
 */
class InMemoryPeerSignaling : PeerSignaling {

    private val listeners =
        mutableMapOf<String, (PeerSignal) -> Unit>()

    override fun publish(
        peerId: String,
        signal: PeerSignal
    ) {
        listeners[peerId]?.invoke(signal)
    }

    override fun setListener(
        peerId: String,
        listener: (PeerSignal) -> Unit
    ) {
        listeners[peerId] = listener
    }

    override fun setIncomingListener(
        listener: (
            peerId: String,
            signingPublicKeyBase64: String,
            agreementPublicKeyBase64: String,
            signal: PeerSignal
        ) -> Unit
    ) {
        // Test-only signaling does not need global discovery.
    }

    override fun setDiagnosticListener(
        listener: (String) -> Unit
    ) {
        // Test-only signaling does not need diagnostics.
    }

    override fun removeListener(
        peerId: String
    ) {
        listeners.remove(peerId)
    }
}
