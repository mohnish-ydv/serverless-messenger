package com.mohnish.serverlessmessenger.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import com.mohnish.serverlessmessenger.security.MessageEnvelope
import org.json.JSONArray
import org.json.JSONObject

private val Context.outboxDataStore by preferencesDataStore(
    name = "serverless_outbox"
)

data class PendingMessage(
    val id: String,
    val peerId: String,
    val text: String,
    val createdAt: Long,
    val envelope: MessageEnvelope = MessageEnvelope.text(text)
)

class MessageOutbox(
    private val context: Context
) {
    private val mutex = Mutex()

    private val key =
        stringPreferencesKey("pending")

    val messages: Flow<List<PendingMessage>> =
        context.outboxDataStore.data.map { preferences ->
            decode(
                preferences[key].orEmpty()
            )
        }

    suspend fun add(
        peerId: String,
        text: String,
        envelope: MessageEnvelope = MessageEnvelope.text(text)
    ): PendingMessage =
        mutex.withLock {
            val current =
                messages.first()

            val item =
                PendingMessage(
                    id = java.util.UUID.randomUUID().toString(),
                    peerId = peerId,
                    text = text,
                    createdAt = System.currentTimeMillis(),
                    envelope = envelope
                )

            save(
                current + item
            )

            item
        }

    suspend fun remove(
        id: String
    ) =
        mutex.withLock {
            val current =
                messages.first()

            save(
                current.filterNot {
                    it.id == id
                }
            )
        }

    suspend fun forPeer(
        peerId: String
    ): List<PendingMessage> =
        messages.first().filter {
            it.peerId == peerId
        }

    private suspend fun save(
        items: List<PendingMessage>
    ) {
        context.outboxDataStore.edit { preferences ->
            preferences[key] =
                encode(items)
        }
    }

    private fun encode(
        items: List<PendingMessage>
    ): String {
        val array = JSONArray()

        items.forEach { item ->
            array.put(
                JSONObject().apply {
                    put("id", item.id)
                    put("peerId", item.peerId)
                    put("text", item.text)
                    put("createdAt", item.createdAt)
                    put("envelope", item.envelope.toJson())
                }
            )
        }

        return array.toString()
    }

    private fun decode(
        raw: String
    ): List<PendingMessage> {
        if (raw.isBlank()) {
            return emptyList()
        }

        return runCatching {
            val array = JSONArray(raw)

            buildList {
                for (index in 0 until array.length()) {
                    val item =
                        array.getJSONObject(index)

                    val text = item.getString("text")
                    val envelope =
                        item.optString("envelope", null)?.let {
                            MessageEnvelope.fromJson(it)
                        } ?: MessageEnvelope.text(text)

                    add(
                        PendingMessage(
                            id = item.getString("id"),
                            peerId = item.getString("peerId"),
                            text = text,
                            createdAt = item.getLong("createdAt"),
                            envelope = envelope
                        )
                    )
                }
            }
        }.getOrDefault(emptyList())
    }
}
