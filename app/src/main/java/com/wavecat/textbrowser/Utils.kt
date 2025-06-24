package com.wavecat.textbrowser

import androidx.core.net.toUri

fun extractBaseUrlFromHtml(html: String, fallbackUrl: String?): String? {
    return try {
        val baseTagRegex = Regex("<base\\s+href\\s*=\\s*[\"']([^\"']+)[\"']", RegexOption.IGNORE_CASE)
        val match = baseTagRegex.find(html)

        if (match != null) {
            val baseHref = match.groupValues[1]
            extractBaseUrl(baseHref)
        } else {
            fallbackUrl
        }
    } catch (e: Exception) {
        fallbackUrl
    }
}

fun extractBaseUrl(url: String): String {
    return try {
        val uri = url.toUri()
        "${uri.scheme}://${uri.host}/"
    } catch (e: Exception) {
        url
    }
}