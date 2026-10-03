package com.mohnish.serverlessmessenger.data

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.appSettingsDataStore by preferencesDataStore(
    name = "serverless_app_settings"
)

class AppSettingsStore(
    private val context: Context
) {
    private val developerModeKey =
        booleanPreferencesKey("developer_mode")

    val developerMode: Flow<Boolean> =
        context.appSettingsDataStore.data.map { preferences ->
            preferences[developerModeKey] ?: false
        }

    suspend fun setDeveloperMode(enabled: Boolean) {
        context.appSettingsDataStore.edit { preferences ->
            preferences[developerModeKey] = enabled
        }
    }
}
