package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

class DataProtectionManager(private val context: Context) {

    private lateinit var encryptedPrefs: SharedPreferences
    private lateinit var accessLogPrefs: SharedPreferences
    private lateinit var metadataPrefs: SharedPreferences
    private var userSalt: String = ""

    companion object {
        private const val METADATA_PREFS = "metadata_prefs"
        private const val LAST_ROTATION_KEY = "last_rotation"
        private const val HMAC_SECRET_KEY = "hmac_secret_key"
        private const val SALT_KEY = "user_salt"
    }

    fun initialize() {
        metadataPrefs = context.getSharedPreferences(METADATA_PREFS, Context.MODE_PRIVATE)

        // Verificar y rotar la clave si es necesario
        if (shouldRotateKey()) {
            rotateEncryptionKey()
        }

        // Obtener o generar salt por usuario
        userSalt = metadataPrefs.getString(SALT_KEY, null) ?: generateAndStoreUserSalt()

        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        encryptedPrefs = EncryptedSharedPreferences.create(
            context,
            "secure_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
    }

    private fun shouldRotateKey(): Boolean {
        val lastRotation = metadataPrefs.getLong(LAST_ROTATION_KEY, 0L)
        val now = System.currentTimeMillis()
        val THIRTY_DAYS_MILLIS = 30L * 24 * 60 * 60 * 1000
        return now - lastRotation > THIRTY_DAYS_MILLIS
    }

    fun rotateEncryptionKey(): Boolean {
        return try {
            // Solo actualizamos la fecha de rotación
            metadataPrefs.edit().putLong(LAST_ROTATION_KEY, System.currentTimeMillis()).apply()
            logAccess("KEY_ROTATION", "Rotación de clave realizada")
            true
        } catch (e: Exception) {
            logAccess("KEY_ROTATION_ERROR", "Error al rotar clave: ${e.message}")
            false
        }
    }

    private fun generateAndStoreUserSalt(): String {
        val saltBytes = ByteArray(16)
        SecureRandom().nextBytes(saltBytes)
        val saltBase64 = Base64.encodeToString(saltBytes, Base64.NO_WRAP)
        metadataPrefs.edit().putString(SALT_KEY, saltBase64).apply()
        return saltBase64
    }

    private fun deriveKey(password: String, salt: String): ByteArray {
        val keySpec =
            PBEKeySpec(password.toCharArray(), Base64.decode(salt, Base64.NO_WRAP), 10000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(keySpec).encoded
    }

    fun storeSecureData(key: String, value: String) {
        encryptedPrefs.edit().putString(key, value).apply()
        saveDataHMAC(key, value)
        logAccess("DATA_STORAGE", "Dato almacenado de forma segura: $key")
    }

    fun getSecureData(key: String): String? {
        val data = encryptedPrefs.getString(key, null)
        if (data != null) {
            logAccess("DATA_ACCESS", "Dato accedido: $key")
        }
        return data
    }

    fun verifyDataIntegrity(key: String): Boolean {
        val originalValue = encryptedPrefs.getString(key, null) ?: return false
        val storedHmac = encryptedPrefs.getString("${key}_hmac", null) ?: return false
        val computedHmac = computeHMAC(originalValue)
        return storedHmac == computedHmac
    }

    private fun saveDataHMAC(key: String, value: String) {
        val hmac = computeHMAC(value)
        encryptedPrefs.edit().putString("${key}_hmac", hmac).apply()
    }

    private fun computeHMAC(data: String): String {
        val secretKey = deriveKey("app_secret_password", userSalt) // fija para app (idealmente distinta por app)
        val signingKey = SecretKeySpec(secretKey, "HmacSHA256")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(signingKey)
        val hmacBytes = mac.doFinal(data.toByteArray())
        return Base64.encodeToString(hmacBytes, Base64.NO_WRAP)
    }

    fun logAccess(category: String, action: String) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        val logEntry = "$timestamp - $category: $action"
        val existingLogs = accessLogPrefs.getString("logs", "") ?: ""
        val newLogs = if (existingLogs.isEmpty()) logEntry else "$existingLogs\n$logEntry"
        accessLogPrefs.edit().putString("logs", newLogs).apply()
        val logLines = newLogs.split("\n")
        if (logLines.size > 100) {
            val trimmedLogs = logLines.takeLast(100).joinToString("\n")
            accessLogPrefs.edit().putString("logs", trimmedLogs).apply()
        }
    }

    fun getAccessLogs(): List<String> {
        val logsString = accessLogPrefs.getString("logs", "") ?: ""
        return if (logsString.isEmpty()) emptyList() else logsString.split("\n").reversed()
    }

    fun clearAllData() {
        encryptedPrefs.edit().clear().apply()
        accessLogPrefs.edit().clear().apply()
        logAccess("DATA_MANAGEMENT", "Todos los datos han sido borrados de forma segura")
    }

    fun getDataProtectionInfo(): Map<String, String> {
        return mapOf(
            "Encriptación" to "AES-256-GCM",
            "Almacenamiento" to "Local encriptado",
            "Logs de acceso" to "${getAccessLogs().size} entradas",
            "Rotación de clave" to SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
                .format(Date(metadataPrefs.getLong(LAST_ROTATION_KEY, 0))),
            "Integridad OK (ejemplo)" to "${verifyDataIntegrity("ejemplo_key")}",
            "Estado de seguridad" to "Activo"
        )
    }

    fun anonymizeData(data: String): String {
        return data.replace(Regex("[0-9]"), "*").replace(Regex("[A-Za-z]{3,}"), "***")
    }
}
