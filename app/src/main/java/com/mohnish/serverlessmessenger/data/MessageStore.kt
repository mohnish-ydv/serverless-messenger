package com.mohnish.serverlessmessenger.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.mohnish.serverlessmessenger.security.EncryptedMessagePacket
import com.mohnish.serverlessmessenger.security.MessageCrypto
import com.mohnish.serverlessmessenger.security.MessageEnvelope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

private val Context.messageDataStore by preferencesDataStore(
    name = "serverless_messages"
)

object MessageDeliveryState {
    const val SENT = "sent"
    const val DELIVERED = "delivered"
    const val READ = "read"
}

data class LocalMessage(
    val id: String,
    val conversationId: String,
    val text: String,
    val mine: Boolean,
    val timestamp: Long,
    val read: Boolean,
    val deliveryState: String = MessageDeliveryState.SENT,
    val type: String = MessageEnvelope.TYPE_TEXT,
    val replyToMessageId: String? = null,
    val replyPreviewText: String? = null,
    val targetMessageId: String? = null,
    val reaction: String? = null,
    val edited: Boolean = false,
    val deleted: Boolean = false,
    val mediaId: String? = null,
    val mediaMimeType: String? = null,
    val mediaBase64: String? = null
)

data class ConversationSummary(
    val lastMessage: LocalMessage?,
    val unreadCount: Int
)

private data class StoredMessage(
    val packet: EncryptedMessagePacket,
    val mine: Boolean,
    val read: Boolean,
    val deliveryState: String = MessageDeliveryState.SENT,
    val localText: String? = null,
    val localEnvelope: MessageEnvelope? = null,
    val edited: Boolean = false,
    val deleted: Boolean = false
)

class MessageStore(
    private val context: Context
) {

    private fun messagesKey(
        conversationId: String
    ) =
        stringPreferencesKey(
            "messages_$conversationId"
        )

    fun messages(
        conversationId: String,
        peerSigningPublicKeyBase64: String
    ): Flow<List<LocalMessage>> {

        return context.messageDataStore.data.map { preferences ->

            val stored =
                decode(
                    json =
                        preferences[
                            messagesKey(
                                conversationId
                            )
                        ] ?: "[]"
                )

            stored.mapNotNull { message ->

                try {

                    if (
                        !message.mine &&
                        !MessageCrypto.verifyPacket(
                            packet = message.packet,
                            senderSigningPublicKeyBase64 =
                                peerSigningPublicKeyBase64
                        )
                    ) {
                        null
                    } else {

                        val decrypted =
                            if (message.mine && message.localText != null) {
                                null
                            } else {
                                MessageCrypto.decrypt(
                                    context = context,
                                    packet = message.packet
                                )
                            }

                        val envelope =
                            message.localEnvelope
                                ?: decrypted?.envelope
                                ?: MessageEnvelope.text(
                                    message.localText.orEmpty()
                                )

                        val displayText =
                            message.localText
                                ?: decrypted?.text
                                ?: envelope.text

                        LocalMessage(
                            id = message.packet.id,
                            conversationId =
                                conversationId,
                            text = displayText,
                            mine = message.mine,
                            timestamp =
                                message.packet.timestamp,
                            read = message.read,
                            deliveryState = message.deliveryState,
                            type = envelope.type,
                            replyToMessageId =
                                envelope.replyToMessageId,
                            replyPreviewText =
                                envelope.replyPreviewText,
                            targetMessageId =
                                envelope.targetMessageId,
                            reaction =
                                envelope.reaction,
                            
                            edited = message.edited,
                            deleted = message.deleted,
                            mediaId = envelope.mediaId,
                            mediaMimeType = envelope.mediaMimeType,
                            mediaBase64 = envelope.mediaBase64
                        )
                    }

                } catch (_: Exception) {
                    null
                }
            }
        }
    }

    fun summary(
        conversationId: String,
        peerSigningPublicKeyBase64: String
    ): Flow<ConversationSummary> {

        return messages(
            conversationId =
                conversationId,
            peerSigningPublicKeyBase64 =
                peerSigningPublicKeyBase64
        ).map { messages ->

            ConversationSummary(
                lastMessage =
                    messages.maxByOrNull {
                        it.timestamp
                    },
                unreadCount =
                    messages.count {
                        !it.mine && !it.read
                    }
            )
        }
    }

    suspend fun addEncryptedMessage(
        conversationId: String,
        packet: EncryptedMessagePacket,
        mine: Boolean,
        localText: String? = null,
        localEnvelope: MessageEnvelope? = null
    ) {

        context.messageDataStore.edit { preferences ->

            val key =
                messagesKey(
                    conversationId
                )

            val existing =
                decode(
                    preferences[key] ?: "[]"
                )

            if (
                existing.any {
                    it.packet.id == packet.id
                }
            ) {
                return@edit
            }

            val message =
                StoredMessage(
                    packet = packet,
                    mine = mine,
                    read = mine,
                    deliveryState =
                        if (mine) {
                            MessageDeliveryState.SENT
                        } else {
                            MessageDeliveryState.DELIVERED
                        },
                    localText = if (mine) localText else null,
                    localEnvelope =
                        localEnvelope
                            ?: localText?.let {
                                MessageEnvelope.text(it)
                            }
                )

            preferences[key] =
                encode(
                    existing + message
                )
        }
    }

    suspend fun markConversationRead(
        conversationId: String
    ): List<String> {

        var readIds = emptyList<String>()

        context.messageDataStore.edit { preferences ->

            val key =
                messagesKey(
                    conversationId
                )

            val existing =
                decode(
                    preferences[key] ?: "[]"
                )

            readIds =
                existing
                    .filter {
                        !it.mine &&
                            it.deliveryState !=
                                MessageDeliveryState.READ
                    }
                    .map {
                        it.packet.id
                    }

            val updated =
                existing.map { message ->

                    if (
                        !message.mine &&
                        message.deliveryState !=
                            MessageDeliveryState.READ
                    ) {
                        message.copy(
                            read = true,
                            deliveryState =
                                MessageDeliveryState.READ
                        )
                    } else {
                        message
                    }
                }

            preferences[key] =
                encode(updated)
        }

        return readIds
    }

    suspend fun markMessageDelivered(
        conversationId: String,
        messageId: String
    ) {
        updateDeliveryState(
            conversationId = conversationId,
            messageId = messageId,
            state = MessageDeliveryState.DELIVERED
        )
    }

    suspend fun markMessageRead(
        conversationId: String,
        messageId: String
    ) {
        updateDeliveryState(
            conversationId = conversationId,
            messageId = messageId,
            state = MessageDeliveryState.READ
        )
    }

    suspend fun editMessage(
        conversationId: String,
        messageId: String,
        newText: String
    ) {
        if (newText.isBlank()) {
            return
        }

        context.messageDataStore.edit { preferences ->
            val key = messagesKey(conversationId)
            val existing = decode(preferences[key] ?: "[]")

            val updated =
                existing.map { message ->
                    if (
                        message.packet.id == messageId &&
                        message.mine &&
                        !message.deleted
                    ) {
                        message.copy(
                            localText = newText,
                            edited = true
                        )
                    } else {
                        message
                    }
                }

            preferences[key] = encode(updated)
        }
    }

    suspend fun deleteMessage(
        conversationId: String,
        messageId: String
    ) {
        context.messageDataStore.edit { preferences ->
            val key = messagesKey(conversationId)
            val existing = decode(preferences[key] ?: "[]")

            val updated =
                existing.map { message ->
                    if (
                        message.packet.id == messageId &&
                        message.mine
                    ) {
                        message.copy(
                            localText = "This message was deleted",
                            deleted = true
                        )
                    } else {
                        message
                    }
                }

            preferences[key] = encode(updated)
        }
    }

    suspend fun setReaction(
        conversationId: String,
        messageId: String,
        reaction: String
    ) {
        if (reaction.isBlank()) return

        context.messageDataStore.edit { preferences ->
            val key = messagesKey(conversationId)
            val existing = decode(preferences[key] ?: "[]")

            val updated = existing.map { message ->
                if (message.packet.id == messageId) {
                    val envelope =
                        message.localEnvelope
                            ?: MessageEnvelope(
                                type = MessageEnvelope.TYPE_TEXT,
                                text = message.localText.orEmpty()
                            )

                    message.copy(
                        localEnvelope = envelope.copy(
                            reaction = reaction
                        )
                    )
                } else {
                    message
                }
            }

            preferences[key] = encode(updated)
        }
    }

    suspend fun applyRemoteReaction(
        conversationId: String,
        messageId: String,
        reaction: String
    ) {
        if (reaction.isBlank()) return

        context.messageDataStore.edit { preferences ->
            val key = messagesKey(conversationId)
            val existing = decode(preferences[key] ?: "[]")

            val updated = existing.map { message ->
                if (message.packet.id == messageId) {
                    val envelope =
                        message.localEnvelope
                            ?: MessageEnvelope(
                                type = MessageEnvelope.TYPE_TEXT,
                                text = message.localText.orEmpty()
                            )

                    message.copy(
                        localEnvelope = envelope.copy(
                            reaction = reaction
                        )
                    )
                } else {
                    message
                }
            }

            preferences[key] = encode(updated)
        }
    }

    suspend fun applyRemoteEdit(
        conversationId: String,
        messageId: String,
        newText: String
    ) {
        if (newText.isBlank()) {
            return
        }

        context.messageDataStore.edit { preferences ->
            val key = messagesKey(conversationId)
            val existing = decode(preferences[key] ?: "[]")

            val updated =
                existing.map { message ->
                    if (
                        message.packet.id == messageId &&
                        !message.deleted
                    ) {
                        message.copy(
                            localText = newText,
                            edited = true
                        )
                    } else {
                        message
                    }
                }

            preferences[key] = encode(updated)
        }
    }

    suspend fun applyRemoteDelete(
        conversationId: String,
        messageId: String
    ) {
        context.messageDataStore.edit { preferences ->
            val key = messagesKey(conversationId)
            val existing = decode(preferences[key] ?: "[]")

            val updated =
                existing.map { message ->
                    if (message.packet.id == messageId) {
                        message.copy(
                            localText = "This message was deleted",
                            deleted = true
                        )
                    } else {
                        message
                    }
                }

            preferences[key] = encode(updated)
        }
    }

    private suspend fun updateDeliveryState(
        conversationId: String,
        messageId: String,
        state: String
    ) {
        context.messageDataStore.edit { preferences ->

            val key =
                messagesKey(
                    conversationId
                )

            val existing =
                decode(
                    preferences[key] ?: "[]"
                )

            val updated =
                existing.map { message ->

                    if (message.packet.id == messageId) {
                        message.copy(
                            read =
                                state ==
                                    MessageDeliveryState.READ,
                            deliveryState = state
                        )
                    } else {
                        message
                    }
                }

            preferences[key] =
                encode(updated)
        }
    }


    private fun encode(
        messages: List<StoredMessage>
    ): String {

        val array =
            JSONArray()

        messages.forEach { message ->

            val packet =
                message.packet

            array.put(
                JSONObject().apply {

                    put(
                        "id",
                        packet.id
                    )

                    put(
                        "sender_identity_id",
                        packet.senderIdentityId
                    )

                    put(
                        "recipient_identity_id",
                        packet.recipientIdentityId
                    )

                    put(
                        "sender_agreement_public_key",
                        packet.senderAgreementPublicKey
                    )

                    put(
                        "recipient_agreement_public_key",
                        packet.recipientAgreementPublicKey
                    )

                    put(
                        "timestamp",
                        packet.timestamp
                    )

                    put(
                        "nonce",
                        packet.nonce
                    )

                    put(
                        "ciphertext",
                        packet.ciphertext
                    )

                    put(
                        "signature",
                        packet.signature
                    )

                    put(
                        "mine",
                        message.mine
                    )

                    message.localText?.let {
                        put(
                            "local_text",
                            it
                        )
                    }

                    put(
                        "read",
                        message.read
                    )

                    put(
                        "delivery_state",
                        message.deliveryState
                    )

                    put(
                        "edited",
                        message.edited
                    )

                    put(
                        "deleted",
                        message.deleted
                    )

                    message.localEnvelope?.let { envelope ->
                        put(
                            "local_type",
                            envelope.type
                        )

                        envelope.replyToMessageId?.let {
                            put(
                                "local_reply_to",
                                it
                            )
                        }

                          envelope.replyPreviewText?.let {
                              put(
                                  "local_reply_preview",
                                  it
                              )
                          }


                        envelope.targetMessageId?.let {
                            put(
                                "local_target",
                                it
                            )
                        }

                        envelope.reaction?.let {
                            put(
                                "local_reaction",
                                it
                            )
                        }

                        envelope.mediaId?.let {
                            put(
                                "local_media_id",
                                it
                            )
                        }

                        envelope.mediaMimeType?.let {
                            put(
                                "local_media_mime_type",
                                it
                            )
                        }

                        envelope.mediaBase64?.let {
                            put(
                                "local_media_base64",
                                it
                            )
                        }
                    }
                }
            )
        }

        return array.toString()
    }

    private fun decode(
        json: String
    ): List<StoredMessage> {

        return try {

            val array =
                JSONArray(json)

            buildList {

                for (
                    index in 0 until array.length()
                ) {

                    val item =
                        array.getJSONObject(index)

                    val packet =
                        EncryptedMessagePacket(

                            id =
                                item.getString(
                                    "id"
                                ),

                            senderIdentityId =
                                item.getString(
                                    "sender_identity_id"
                                ),

                            recipientIdentityId =
                                item.getString(
                                    "recipient_identity_id"
                                ),

                            senderAgreementPublicKey =
                                item.getString(
                                    "sender_agreement_public_key"
                                ),

                            recipientAgreementPublicKey =
                                item.getString(
                                    "recipient_agreement_public_key"
                                ),

                            timestamp =
                                item.getLong(
                                    "timestamp"
                                ),

                            nonce =
                                item.getString(
                                    "nonce"
                                ),

                            ciphertext =
                                item.getString(
                                    "ciphertext"
                                ),

                            signature =
                                item.getString(
                                    "signature"
                                )
                        )

                    val localText =
                        item.optString("local_text").takeIf { it != "null" }.takeIf {
                            !it.isNullOrBlank()
                        }

                    val localType =
                        item.optString("local_type").takeIf { it != "null" }.takeIf {
                            !it.isNullOrBlank()
                        }

                    val localEnvelope =
                        if (localType != null) {
                            MessageEnvelope(
                                version =
                                    MessageEnvelope.CURRENT_VERSION,
                                type = localType,
                                text =
                                    localText.orEmpty(),
                                replyToMessageId =
                                    item.optString("local_reply_to").takeIf { it != "null" }.takeIf {
                                        !it.isNullOrBlank()
                                    },
                                replyPreviewText =
                                    item.optString("local_reply_preview").takeIf { it != "null" }.takeIf {
                                        !it.isNullOrBlank()
                                    },
                                targetMessageId =
                                    item.optString("local_target").takeIf { it != "null" }.takeIf {
                                        !it.isNullOrBlank()
                                    },
                                reaction =
                                    item.optString("local_reaction").takeIf { it != "null" }.takeIf {
                                        !it.isNullOrBlank()
                                    },
                                mediaId =
                                    item.optString("local_media_id").takeIf { it != "null" }.takeIf {
                                        !it.isNullOrBlank()
                                    },
                                mediaMimeType =
                                    item.optString("local_media_mime_type").takeIf { it != "null" }.takeIf {
                                        !it.isNullOrBlank()
                                    },
                                mediaBase64 =
                                    item.optString("local_media_base64").takeIf { it != "null" }.takeIf {
                                        !it.isNullOrBlank()
                                    }
                            )
                        } else {
                            null
                        }

                    val mine =
                        item.optBoolean(
                            "mine",
                            false
                        )

                    val read =
                        item.optBoolean(
                            "read",
                            false
                        )

                    val deliveryState =
                        item.optString(
                            "delivery_state",
                            ""
                        ).takeIf {
                            it == MessageDeliveryState.SENT ||
                                it == MessageDeliveryState.DELIVERED ||
                                it == MessageDeliveryState.READ
                        } ?: when {
                            mine ->
                                MessageDeliveryState.SENT

                            read ->
                                MessageDeliveryState.READ

                            else ->
                                MessageDeliveryState.DELIVERED
                        }

                    val edited =
                        item.optBoolean(
                            "edited",
                            false
                        )

                    val deleted =
                        item.optBoolean(
                            "deleted",
                            false
                        )

                    add(
                        StoredMessage(
                            packet = packet,
                            mine = mine,
                            read =
                                read ||
                                    deliveryState ==
                                        MessageDeliveryState.READ,
                            deliveryState = deliveryState,
                            localText = localText,
                            localEnvelope = localEnvelope,
                            edited = edited,
                            deleted = deleted
                        )
                    )
                }
            }

        } catch (_: Exception) {
            emptyList()
        }
    }
}
