package com.mohnish.serverlessmessenger.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.profileDataStore by preferencesDataStore(
    name = "serverless_profile"
)

class ProfileStore(
    private val context: Context
) {
    private val usernameKey = stringPreferencesKey("username")

    val username: Flow<String> =
        context.profileDataStore.data.map { preferences ->
            preferences[usernameKey].orEmpty()
        }

    suspend fun setUsername(username: String) {
        context.profileDataStore.edit { preferences ->
            preferences[usernameKey] = username.trim()
        }
    }
}
