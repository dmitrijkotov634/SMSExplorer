package com.wavecat.textbrowser

import com.txtnet.brotli4droid.decoder.BrotliInputStream
import com.txtnet.brotli4droid.encoder.BrotliOutputStream
import java.io.ByteArrayOutputStream

fun compressAndEncode(text: String): String {
    val bos = ByteArrayOutputStream()
    BrotliOutputStream(bos).bufferedWriter(Charsets.UTF_8).use { it.write(text) }
    val compressed = bos.toByteArray()
    return Base114.encode(compressed)
}

fun decodeAndDecompress(base114Brotli: String): String {
    val decodedBytes = Base114.decode(base114Brotli)
    return BrotliInputStream(decodedBytes.inputStream()).bufferedReader().use { it.readText() }
}