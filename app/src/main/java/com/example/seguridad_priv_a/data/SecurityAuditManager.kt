package com.example.seguridad_priv_a.data

import android.content.Context
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.*
import kotlin.collections.HashMap

class SecurityAuditManager(private val context: Context) {

    private val prefs = context.getSharedPreferences("audit_logs", Context.MODE_PRIVATE)
    private val attemptTracker = HashMap<String, MutableList<Long>>()  // key: acción, value: timestamps
    private val RATE_LIMIT_MS = 3000L // Tiempo mínimo entre acciones sensibles (3 seg)
    private val ALERT_THRESHOLD = 5 // Más de 5 acciones en 10 segundos

    // Registrar operación sensible
    fun registerSensitiveAction(action: String): Boolean {
        val now = SystemClock.elapsedRealtime()

        val timestamps = attemptTracker.getOrPut(action) { mutableListOf() }
        timestamps.add(now)

        // Limpiar timestamps viejos (> 10s)
        timestamps.removeIf { now - it > 10000 }

        if (timestamps.size > ALERT_THRESHOLD) {
            generateAlert("Sospecha de abuso en acción: $action")
        }

        if (timestamps.size >= 2 && now - timestamps[timestamps.size - 2] < RATE_LIMIT_MS) {
            logEvent(action, "RATE_LIMITED")
            return false // Rate limit aplicado
        }

        logEvent(action, "SUCCESS")
        return true
    }

    // Registrar intento general
    private fun logEvent(action: String, status: String) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())

        val logEntry = JSONObject().apply {
            put("timestamp", timestamp)
            put("action", action)
            put("status", status)
        }

        val existingLogs = prefs.getString("logs", "[]")
        val jsonArray = JSONArray(existingLogs)
        jsonArray.put(logEntry)

        prefs.edit().putString("logs", jsonArray.toString()).apply()
    }

    // Alerta interna (puedes vincular a notificaciones o reporte remoto)
    private fun generateAlert(message: String) {
        val alert = JSONObject().apply {
            put("timestamp", System.currentTimeMillis())
            put("type", "ALERT")
            put("message", message)
        }

        val existing = prefs.getString("alerts", "[]")
        val array = JSONArray(existing)
        array.put(alert)

        prefs.edit().putString("alerts", array.toString()).apply()
        Log.w("SecurityAudit", "⚠️ ALERTA: $message")
    }

    // Exportar logs firmados digitalmente
    fun exportSignedLogs(): String {
        val logs = prefs.getString("logs", "[]") ?: "[]"
        val privateKey = getOrCreatePrivateKey()

        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(logs.toByteArray())

        val signedData = signature.sign()
        val encodedSignature = Base64.encodeToString(signedData, Base64.NO_WRAP)

        val exportObject = JSONObject().apply {
            put("logs", JSONArray(logs))
            put("signature", encodedSignature)
        }

        return exportObject.toString(4) // JSON indentado
    }

    // Crear clave RSA privada persistente (solo para firmar localmente)
    private fun getOrCreatePrivateKey(): PrivateKey {
        val keyPrefs = context.getSharedPreferences("key_store", Context.MODE_PRIVATE)
        val stored = keyPrefs.getString("private_key", null)

        return if (stored != null) {
            val decoded = Base64.decode(stored, Base64.NO_WRAP)
            val keySpec = PKCS8EncodedKeySpec(decoded)
            val kf = KeyFactory.getInstance("RSA")
            kf.generatePrivate(keySpec)
        } else {
            val keyPairGen = KeyPairGenerator.getInstance("RSA")
            keyPairGen.initialize(2048)
            val keyPair = keyPairGen.generateKeyPair()
            val privateKeyBytes = keyPair.private.encoded
            val encoded = Base64.encodeToString(privateKeyBytes, Base64.NO_WRAP)
            keyPrefs.edit().putString("private_key", encoded).apply()
            keyPair.private
        }
    }

    fun clearAuditLogs() {
        prefs.edit().clear().apply()
    }

    fun getAlerts(): List<String> {
        val alertJson = prefs.getString("alerts", "[]") ?: "[]"
        val array = JSONArray(alertJson)
        val alerts = mutableListOf<String>()
        for (i in 0 until array.length()) {
            alerts.add(array.getJSONObject(i).getString("message"))
        }
        return alerts
    }
}
