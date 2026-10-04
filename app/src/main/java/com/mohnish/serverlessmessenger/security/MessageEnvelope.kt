package com.mohnish.serverlessmessenger.security

import org.json.JSONObject

/**
 * Versioned payload carried inside the existing encrypted message packet.
 *
 * The outer EncryptedMessagePacket stays unchanged so existing
 * signatures, encryption, and Nostr transport remain compatible.
 */
data class MessageEnvelope(
    val version: Int = CURRENT_VERSION,
    val type: String = TYPE_TEXT,
    val text: String = "",
    val replyToMessageId: String? = null,
    val replyPreviewText: String? = null,
    val targetMessageId: String? = null,
    val reaction: String? = null
) {
    fun toJson(): String =
        JSONObject().apply {
            put("v", version)
            put("type", type)
            put("text", text)

            replyToMessageId?.let {
                put("replyTo", it)
            }

            replyPreviewText?.let {
                put("replyPreview", it)
            }

            targetMessageId?.let {
                put("target", it)
            }

            reaction?.let {
                put("reaction", it)
            }
        }.toString()

    companion object {
        const val CURRENT_VERSION = 1

        const val TYPE_TEXT = "text"
        const val TYPE_REPLY = "reply"
        const val TYPE_EDIT = "edit"
        const val TYPE_DELETE = "delete"
        const val TYPE_REACTION = "reaction"
        const val TYPE_DELIVERY_ACK = "delivery_ack"
        const val TYPE_READ_ACK = "read_ack"

        fun text(value: String): MessageEnvelope =
            MessageEnvelope(
                version = CURRENT_VERSION,
                type = TYPE_TEXT,
                text = value
            )

        fun fromJson(value: String): MessageEnvelope? {
            return try {
                val json = JSONObject(value)

                if (!json.has("v") || !json.has("type")) {
                    null
                } else {
                    MessageEnvelope(
                        version = json.optInt(
                            "v",
                            CURRENT_VERSION
                        ),
                        type = json.getString("type"),
                        text = json.optString(
                            "text",
                            ""
                        ),
                        replyToMessageId =
                            json.optString(
                                "replyTo",
                                null
                            ),
                          replyPreviewText =
                              json.optString(
                                  "replyPreview",
                                  null
                              ),
                        targetMessageId =
                            json.optString(
                                "target",
                                null
                            ),
                        reaction =
                            json.optString(
                                "reaction",
                                null
                            )
                    )
                }
            } catch (_: Exception) {
                null
            }
        }
    }
}
