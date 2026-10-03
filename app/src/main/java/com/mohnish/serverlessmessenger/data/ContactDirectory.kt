package com.mohnish.serverlessmessenger.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

class ContactDirectory(
    contactStore: ContactStore,
    scope: CoroutineScope
) {
    private val byIdentityId =
        ConcurrentHashMap<String, LocalContact>()

    private val byNostrPublicKey =
        ConcurrentHashMap<String, LocalContact>()

    init {
        scope.launch {
            contactStore.contacts.collectLatest { contacts ->
                byIdentityId.clear()
                byNostrPublicKey.clear()

                contacts.forEach { contact ->
                    if (
                        contact.nostrPublicKeyHex.isNotBlank()
                    ) {
                        byIdentityId[
                            contact.identityId
                        ] = contact

                        byNostrPublicKey[
                            contact.nostrPublicKeyHex
                                .trim()
                                .lowercase()
                        ] = contact
                    }
                }
            }
        }
    }

    fun get(
        identityId: String
    ): LocalContact? =
        byIdentityId[identityId]

    fun getByNostrPublicKey(
        publicKeyHex: String
    ): LocalContact? =
        byNostrPublicKey[
            publicKeyHex.trim().lowercase()
        ]
}
