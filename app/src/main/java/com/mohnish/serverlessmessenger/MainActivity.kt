package com.mohnish.serverlessmessenger

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.mohnish.serverlessmessenger.ui.MessengerApp
import com.mohnish.serverlessmessenger.ui.theme.ServerlessMessengerTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        enableEdgeToEdge()

        setContent {
            ServerlessMessengerTheme {
                MessengerApp()
            }
        }
    }
}
