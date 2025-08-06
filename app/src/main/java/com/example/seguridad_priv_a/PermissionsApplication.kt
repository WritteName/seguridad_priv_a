package com.example.seguridad_priv_a

import android.app.Application
import com.example.seguridad_priv_a.data.DataProtectionManager
import com.example.seguridad_priv_a.data.SecurityAuditManager

class PermissionsApplication : Application() {
    
    val dataProtectionManager by lazy {
        DataProtectionManager(this)
    }
    val securityAuditManager by lazy {
        SecurityAuditManager(this)
    }

    override fun onCreate() {
        super.onCreate()
        
        // Inicializar el sistema de protección de datos
        dataProtectionManager.initialize()
        
        // Log de inicio de aplicación
        dataProtectionManager.logAccess("APPLICATION", "App iniciada")

        // Registrar auditoría del inicio
        securityAuditManager.registerSensitiveAction("APPLICATION_STARTED")
    }
}