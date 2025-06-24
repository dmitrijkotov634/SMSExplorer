package com.wavecat.textbrowser

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

class SmsViewModel : ViewModel() {

    private val _decodedHtml = MutableStateFlow<String?>(null)
    val decodedHtml = _decodedHtml.asStateFlow()

    private val _progressValue = MutableStateFlow(0)
    val progressValue = _progressValue.asStateFlow()

    private val _progressMax = MutableStateFlow(0)
    val progressMax = _progressMax.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading = _isLoading.asStateFlow()

    private val smsParts = mutableMapOf<Int, String>()
    private var expectedParts: Int? = null

    private val _baseUrl = MutableStateFlow("")
    val baseUrl = _baseUrl.asStateFlow()

    private val smsTimestamps = mutableListOf<Long>()
    private val _estimatedTimeRemaining = MutableStateFlow<String?>(null)
    val estimatedTimeRemaining = _estimatedTimeRemaining.asStateFlow()

    fun setBaseUrl(url: String) {
        _baseUrl.value = url
    }

    fun processSms(sms: String) {
        val regex = Regex("""^(\d+)/(\d+)#([\s\S]*)${'$'}""")
        val match = regex.matchEntire(sms) ?: return

        val (indexStr, totalStr, body) = match.destructured
        val index = indexStr.toIntOrNull() ?: return
        val total = totalStr.toIntOrNull() ?: return

        if (expectedParts == null) {
            expectedParts = total
            _progressMax.value = total
            _isLoading.value = true
        } else if (expectedParts != total) {
            reset()
            return
        }

        smsParts[index] = body
        _progressValue.value = smsParts.size

        val currentTime = System.currentTimeMillis()
        smsTimestamps.add(currentTime)

        if (smsParts.size > 1) {
            val intervals = smsTimestamps.zipWithNext { a, b -> b - a }
            val averageIntervalMillis = intervals.average().toLong()

            val remainingParts = total - smsParts.size
            val estimatedRemainingMillis = averageIntervalMillis * remainingParts

            val minutes = estimatedRemainingMillis / 1000 / 60
            val seconds = (estimatedRemainingMillis / 1000) % 60

            _estimatedTimeRemaining.value = when {
                minutes > 0 -> "${minutes}m ${seconds}s"
                else -> "${seconds}s"
            }
        }

        if (smsParts.size == total) {
            val fullMessage = (1..total).joinToString("") { smsParts[it].orEmpty() }

            smsParts.clear()
            expectedParts = null
            _isLoading.value = false

            try {
                val decoded = decodeAndDecompress(fullMessage)
                _decodedHtml.value = decoded
            } catch (e: Exception) {
                _decodedHtml.value = e.message
            }
        }
    }

    fun reset() {
        smsTimestamps.clear()
        smsParts.clear()
        expectedParts = null
        _progressValue.value = 0
        _progressMax.value = 0
        _isLoading.value = false
        _estimatedTimeRemaining.value = null
    }

    fun processSending() {
        reset()
        _isLoading.value = true
    }
}