package com.mohnish.serverlessmessenger.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val BrandBlue = Color(0xFF246BFD)
val AppWhite = Color(0xFFFFFFFF)
val Surface = Color(0xFFFAFAFA)
val PrimaryText = Color(0xFF212121)
val SecondaryText = Color(0xFF757575)
val Border = Color(0xFFEEEEEE)

private val AppColors = lightColorScheme(
    primary = BrandBlue,
    onPrimary = AppWhite,
    background = AppWhite,
    onBackground = PrimaryText,
    surface = AppWhite,
    onSurface = PrimaryText,
    secondary = SecondaryText,
    outline = Border
)

@Composable
fun ServerlessMessengerTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = AppColors,
        content = content
    )
}
