package com.wavecat.textbrowser

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony

class SmsBroadcastReceiver(
    var targetSender: String? = null,
    private val onSmsReceived: (String) -> Unit,
) : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
            for (smsMessage in Telephony.Sms.Intents.getMessagesFromIntent(intent)) {
                val smsSender = smsMessage.displayOriginatingAddress
                val smsBody = smsMessage.messageBody

                if (targetSender == null || targetSender == smsSender)
                    onSmsReceived(smsBody)
            }
        }
    }
}