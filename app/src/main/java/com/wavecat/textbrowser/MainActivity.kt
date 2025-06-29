package com.wavecat.textbrowser

import android.Manifest
import android.annotation.SuppressLint
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.provider.Telephony
import android.telephony.SmsManager
import android.view.View
import android.view.inputmethod.EditorInfo
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.PopupMenu
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.content.getSystemService
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.transition.TransitionManager
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import com.google.android.material.color.DynamicColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.txtnet.brotli4droid.Brotli4jLoader
import com.wavecat.textbrowser.databinding.ActivityMainBinding
import com.wavecat.textbrowser.databinding.DialogSetupBinding
import kotlinx.coroutines.launch
import java.io.ByteArrayInputStream

class MainActivity : AppCompatActivity() {
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }

    private val preferences by lazy { getSharedPreferences("settings", MODE_PRIVATE) }

    private lateinit var smsViewModel: SmsViewModel
    private lateinit var smsReceiver: SmsBroadcastReceiver

    private val smsManager by lazy { getSystemService<SmsManager>() }

    init {
        Brotli4jLoader.ensureAvailability()
    }

    private val requiredPermissions = arrayOf(
        Manifest.permission.SEND_SMS,
        Manifest.permission.RECEIVE_SMS,
        Manifest.permission.READ_SMS
    )

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        if (allGranted) {
            initializeSmsFeatures()
        } else {
            Toast.makeText(this, "SMS permissions are required for this app to work", Toast.LENGTH_LONG)
                .show()
        }
    }

    private fun hasAllPermissions(): Boolean {
        return requiredPermissions.all { permission ->
            ContextCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED
        }
    }

    private fun requestPermissions() {
        permissionLauncher.launch(requiredPermissions)
    }

    private fun initializeSmsFeatures() {
        smsReceiver = SmsBroadcastReceiver { sms ->
            smsViewModel.processSms(sms)
        }

        registerReceiver(smsReceiver, IntentFilter(Telephony.Sms.Intents.SMS_RECEIVED_ACTION))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        DynamicColors.applyToActivityIfAvailable(this)

        super.onCreate(savedInstanceState)

        enableEdgeToEdge()
        setContentView(binding.root)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        smsViewModel = ViewModelProvider(this)[SmsViewModel::class.java]

        if (hasAllPermissions()) {
            initializeSmsFeatures()
        } else {
            requestPermissions()
        }

        setupWebView()
        setupUI()
    }

    private fun setupUI() = binding.run {
        url.editText?.setOnEditorActionListener { v, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_SEARCH) {
                val input = v.text.toString()
                val baseUrl = extractBaseUrl(input)
                smsViewModel.setBaseUrl(baseUrl)
                sendURL(input)
                true
            } else {
                false
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                with(smsViewModel) {
                    launch { progressMax.collect { progressBar.max = it } }
                    launch { progressValue.collect { progressBar.progress = it } }

                    launch {
                        isLoading.collect {
                            TransitionManager.beginDelayedTransition(root)
                            progressOverlay.visibility = if (it) View.VISIBLE else View.GONE
                            goBack.isEnabled = !it
                            menu.isEnabled = !it
                        }
                    }

                    launch {
                        estimatedTimeRemaining.collect { time ->
                            estimatedInfo.text = time?.let {
                                getString(
                                    R.string.estimated_time_remaining,
                                    time
                                )
                            } ?: ""
                        }
                    }

                    launch {
                        decodedHtml.collect { html ->
                            html?.let {
                                val currentBaseUrl = baseUrl.value
                                val newBaseUrl = extractBaseUrlFromHtml(it, currentBaseUrl)

                                if (newBaseUrl != null && newBaseUrl != currentBaseUrl) {
                                    smsViewModel.setBaseUrl(newBaseUrl)
                                    binding.url.editText?.setText(newBaseUrl)
                                }

                                webView.loadDataWithBaseURL(
                                    newBaseUrl ?: currentBaseUrl,
                                    it,
                                    "text/html",
                                    "UTF-8",
                                    null
                                )
                            }
                        }
                    }
                }
            }
        }

        goBack.setOnClickListener { webView.goBack() }

        menu.setOnClickListener {
            val popupMenu = PopupMenu(this@MainActivity, binding.menu)

            popupMenu.apply {
                menuInflater.inflate(R.menu.popup_menu, menu)

                setOnMenuItemClickListener {
                    when (it.itemId) {
                        R.id.forward -> webView.goForward()
                        R.id.settings -> openSettingsDialog()
                    }

                    true
                }
            }

            popupMenu.show()
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        binding.webView.apply {
            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)

                    view?.evaluateJavascript(
                        """
                       |document.addEventListener('submit', function(e) {
                       |    e.preventDefault();
                       |    var form = e.target;
                       |    var formData = new FormData(form);
                       |    var params = [];
                       |    
                       |    for (var pair of formData.entries()) {
                       |        params.push(pair[0] + '=' + encodeURIComponent(pair[1]));
                       |    }
                       |    
                       |    var url = form.action || window.location.href;
                       |    var method = form.method.toUpperCase() || 'GET';
                       |    var body = '';
                       |    
                       |    if (method === 'GET' && params.length > 0) {
                       |        var separator = url.includes('?') ? '&' : '?';
                       |        url = url + separator + params.join('&');
                       |    } else if (method === 'POST') {
                       |        body = params.join('&');
                       |    }
                       |    
                       |    window.SE.handleFormSubmit(url, method, body);
                       |});
                       """.trimMargin(), null
                    )
                }

                override fun shouldInterceptRequest(
                    view: WebView?,
                    request: WebResourceRequest?,
                ): WebResourceResponse? {
                    request?.let { req ->
                        val url = req.url.toString()

                        if (req.method == "POST" &&
                            req.requestHeaders["Content-Type"]?.contains("application/x-www-form-urlencoded") == true
                        ) {
                            val fullUrl = if (url.startsWith("http")) {
                                url
                            } else {
                                "${smsViewModel.baseUrl.value}$url"
                            }

                            val baseUrl = extractBaseUrl(fullUrl)
                            smsViewModel.setBaseUrl(baseUrl)

                            binding.url.editText?.setText(fullUrl)
                            sendURL(fullUrl, req.method)

                            return WebResourceResponse(
                                "text/html",
                                "UTF-8",
                                ByteArrayInputStream("".toByteArray())
                            )
                        }
                    }

                    return super.shouldInterceptRequest(view, request)
                }

                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    request?.url?.toString()?.let { url ->
                        val fullUrl = if (url.startsWith("http")) {
                            url
                        } else {
                            "${smsViewModel.baseUrl.value}$url"
                        }

                        val baseUrl = extractBaseUrl(fullUrl)
                        smsViewModel.setBaseUrl(baseUrl)

                        binding.url.editText?.setText(fullUrl)
                        sendURL(fullUrl, request.method)
                    }

                    return true
                }
            }

            settings.javaScriptEnabled = true

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                settings.safeBrowsingEnabled = false
            }

            addJavascriptInterface(WebAppInterface(), "SE")
            setBackgroundColor(Color.TRANSPARENT)

            if (WebViewFeature.isFeatureSupported(WebViewFeature.ALGORITHMIC_DARKENING))
                WebSettingsCompat.setAlgorithmicDarkeningAllowed(settings, true)

            if (WebViewFeature.isFeatureSupported(WebViewFeature.FORCE_DARK)) {
                when (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) {
                    Configuration.UI_MODE_NIGHT_YES -> {
                        @Suppress("DEPRECATION")
                        WebSettingsCompat.setForceDark(settings, WebSettingsCompat.FORCE_DARK_ON)
                    }

                    Configuration.UI_MODE_NIGHT_NO, Configuration.UI_MODE_NIGHT_UNDEFINED -> {
                        @Suppress("DEPRECATION")
                        WebSettingsCompat.setForceDark(settings, WebSettingsCompat.FORCE_DARK_OFF)
                    }
                }
            }

            loadUrl("file:///android_asset/homepage.html")
        }
    }

    private inner class WebAppInterface {
        @JavascriptInterface
        fun openSettings() {
            runOnUiThread { openSettingsDialog() }
        }

        @JavascriptInterface
        fun handleFormSubmit(url: String, method: String, body: String) {
            runOnUiThread {
                val fullUrl = if (url.startsWith("http")) {
                    url
                } else {
                    "${smsViewModel.baseUrl.value}$url"
                }

                val baseUrl = extractBaseUrl(fullUrl)
                smsViewModel.setBaseUrl(baseUrl)
                binding.url.editText?.setText(fullUrl)

                sendURL(fullUrl, method, body)
            }
        }
    }

    private fun openSettingsDialog() {
        val setupDialogBinding = DialogSetupBinding.inflate(layoutInflater)

        setupDialogBinding.apply {
            text.setText(preferences.getString(PHONE, null))
            imageQuality.setText(preferences.getInt(IMAGE_QUALITY, 1).toString())
            imagesCheckbox.isChecked = preferences.getBoolean(IMAGES_ENABLED, false)
            rawCheckbox.isChecked = preferences.getBoolean(RAW_ENABLED, false)
            pngCheckbox.isChecked = preferences.getBoolean(PNG_ENABLED, false)
            nolimitCheckbox.isChecked = preferences.getBoolean(NOLIMIT_ENABLED, false)
        }

        MaterialAlertDialogBuilder(this)
            .setTitle("Setup")
            .setView(setupDialogBinding.root)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                preferences.edit {
                    putString(PHONE, setupDialogBinding.text.text.toString())
                    putInt(IMAGE_QUALITY, setupDialogBinding.imageQuality.text.toString().toIntOrNull() ?: 1)
                    putBoolean(IMAGES_ENABLED, setupDialogBinding.imagesCheckbox.isChecked)
                    putBoolean(RAW_ENABLED, setupDialogBinding.rawCheckbox.isChecked)
                    putBoolean(PNG_ENABLED, setupDialogBinding.pngCheckbox.isChecked)
                    putBoolean(NOLIMIT_ENABLED, setupDialogBinding.nolimitCheckbox.isChecked)
                }

                smsReceiver.targetSender = setupDialogBinding.text.text.toString()
            }
            .show()
    }

    override fun onDestroy() {
        if (::smsReceiver.isInitialized)
            unregisterReceiver(smsReceiver)

        super.onDestroy()
    }

    private fun sendURL(message: String, method: String = "GET", body: String? = null) {
        if (!hasAllPermissions()) {
            Toast.makeText(this, "SMS permissions required", Toast.LENGTH_SHORT).show()
            requestPermissions()
            return
        }

        val phoneNumber = preferences.getString(PHONE, null) ?: return openSettingsDialog()
        val flags = mutableListOf<String>()

        val imagesEnabled = preferences.getBoolean(IMAGES_ENABLED, false)

        if (method != "GET")
            flags.add(method)

        if (imagesEnabled)
            flags.add("IMG")

        if (preferences.getBoolean(RAW_ENABLED, false) && imagesEnabled) {
            flags.add("RAW")
            flags.remove("IMG")
        }

        if (preferences.getBoolean(PNG_ENABLED, false) && imagesEnabled) {
            flags.add("PNG")
            flags.remove("IMG")
        }

        if (preferences.getBoolean(NOLIMIT_ENABLED, false)) {
            flags.add("NOLIMIT")
        }

        if (imagesEnabled) {
            val imageQuality = preferences.getInt(IMAGE_QUALITY, 1)

            if (imageQuality != 1) {
                flags.add("IMGQ$imageQuality")
                flags.remove("IMG")
            }
        }

        val finalMessage = buildString {
            if (flags.isNotEmpty()) {
                append(flags.joinToString(" "))
                append(" ")
            }
            append(message)
            if (!body.isNullOrEmpty()) {
                append("\n")
                append(body)
            }
        }

        val encoded = compressAndEncode(finalMessage)

        smsViewModel.processSending()
        if (encoded.length > 160) {
            val parts = smsManager?.divideMessage(encoded)
            smsManager?.sendMultipartTextMessage(phoneNumber, null, parts, null, null)
        } else {
            smsManager?.sendTextMessage(phoneNumber, null, encoded, null, null)
        }
    }

    companion object {
        const val PHONE = "phone"

        private const val IMAGE_QUALITY = "image_quality"
        private const val IMAGES_ENABLED = "images_enabled"
        private const val RAW_ENABLED = "raw_enabled"
        private const val PNG_ENABLED = "png_enabled"
        private const val NOLIMIT_ENABLED = "nolimit_enabled"
    }
}