package com.anon.dnsencrypt

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class DohResolver(private val url: String) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .writeTimeout(5, TimeUnit.SECONDS)
        .build()

    private val mediaType = "application/dns-message".toMediaType()

    /**
     * Send a raw DNS query over HTTPS (RFC 8484 POST).
     * Returns the raw DNS answer, or null on any failure.
     */
    fun resolve(query: ByteArray): ByteArray? {
        return try {
            val request = Request.Builder()
                .url(url)
                .post(query.toRequestBody(mediaType))
                .header("Accept", "application/dns-message")
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                response.body?.bytes()
            }
        } catch (e: Exception) {
            null
        }
    }
}
