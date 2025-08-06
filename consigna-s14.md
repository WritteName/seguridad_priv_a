# Evaluación Técnica: Análisis y Mejora de Seguridad en Aplicación Android

## Introducción
Esta evaluación técnica se basa en una aplicación Android que implementa un sistema de demostración de permisos y protección de datos. La aplicación utiliza tecnologías modernas como Kotlin, Android Security Crypto, SQLCipher y patrones de arquitectura MVVM.

## Parte 1: Análisis de Seguridad Básico (0-7 puntos)

### 1.1 Identificación de Vulnerabilidades (2 puntos)
Analiza el archivo `DataProtectionManager.kt` y responde:
- ¿Qué método de encriptación se utiliza para proteger datos sensibles?  
El sistema utiliza encriptación AES-256, en modos SIV y GCM, que son resistentes a ataques como manipulación de texto cifrado o repetición.
- Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging  
⦁	Almacenamiento de logs sin cifrado, guardandolos en texto plano en accessLogPrefs. Esto podría filtrar información sensible si alguien accede al almacenamiento local de la app.
⦁	Riesgo de crecimiento descontrolado o mal manejo del tamaño del log; es decir, por cada llamada a logAccess, hay dos escrituras seguidas: una para guardar todos los logs incluyendo el nuevo, y otra si excede los 100. Esto degrada el rendimiento y puede crear condiciones de carrera o corrupción si hay múltiples accesos simultáneos.
- ¿Qué sucede si falla la inicialización del sistema de encriptación?  
Se entra en el bloque catch y se usa un SharedPreferences no cifrado como "fallback", llamado "fallback_prefs" para almacenar datos sensibles. Esto reduce el nivel de seguridad de manera significativa, ya que ahora los datos sensibles quedan expuestos en texto claro.

### 1.2 Permisos y Manifiesto (2 puntos)
Examina `AndroidManifest.xml` y `MainActivity.kt`:
- Lista todos los permisos peligrosos declarados en el manifiesto  
⦁	android.permission.CAMERA: Acceso a la cámara.
⦁	android.permission.READ_EXTERNAL_STORAGE: Leer archivos en almacenamiento externo.
⦁	android.permission.READ_MEDIA_IMAGES: Leer imágenes del almacenamiento.
⦁	android.permission.RECORD_AUDIO: Grabar audio con el micrófono.
⦁	android.permission.READ_CONTACTS: Leer contactos del usuario.personales.
⦁	android.permission.CALL_PHONE: Realizar llamadas telefónicas directamente.
⦁	android.permission.SEND_SMS: Enviar mensajes SMS sin intervención del usuario	
⦁	android.permission.ACCESS_COARSE_LOCATION: Obtener ubicación aproximada
- ¿Qué patrón se utiliza para solicitar permisos en runtime?  
El código usa el patrón recomendado de ActivityResultContracts.RequestPermission(), evitando el uso obsoleto de onRequestPermissionsResult(), además de incluir: Revisión del estado del permiso, Razonamiento con shouldShowRequestPermissionRationale(), Razonamiento con shouldShowRequestPermissionRationale() y Registro de acceso con logAccess.

	private val requestPermissionLauncher = registerForActivityResult(
		ActivityResultContracts.RequestPermission()
	) { isGranted -> ... }
- Identifica qué configuración de seguridad previene backups automáticos  
    android:allowBackup="false"
Esta configuración impide que los datos sean respaldados por el sistema operativo cuando el usuario cambia de dispositivo o reinstala la app.

### 1.3 Gestión de Archivos (3 puntos)
Revisa `CameraActivity.kt` y `file_paths.xml`:
- ¿Cómo se implementa la compartición segura de archivos de imágenes?  
La compartición segura se implementa mediante el componente FileProvider, permite a la app compartir archivos con otras aplicaciones sin exponer directamente las rutas del sistema de archivos.
	currentPhotoUri = FileProvider.getUriForFile(
	    this,
	    "com.example.seguridad_priv_a.fileprovider", // autoridad
	    photoFile
	)
- ¿Qué autoridad se utiliza para el FileProvider?  
    com.example.seguridad_priv_a.fileprovider
Esta autoridad debe ser única por aplicación y coincidir exactamente en el manifiesto y en el código. Se recomienda que use el paquete de la app como prefijo para evitar conflictos.
- Explica por qué no se debe usar `file://` URIs directamente

## Parte 2: Implementación y Mejoras Intermedias (8-14 puntos)

### 2.1 Fortalecimiento de la Encriptación (3 puntos)
Modifica `DataProtectionManager.kt` para implementar:
- Rotación automática de claves maestras cada 30 días
- Verificación de integridad de datos encriptados usando HMAC
- Implementación de key derivation con salt único por usuario

```kotlin
// Ejemplo de estructura esperada
fun rotateEncryptionKey(): Boolean {
    // Tu implementación aquí
}

fun verifyDataIntegrity(key: String): Boolean {
    // Tu implementación aquí
}
```

### 2.2 Sistema de Auditoría Avanzado (3 puntos)
Crea una nueva clase `SecurityAuditManager` que:
- Detecte intentos de acceso sospechosos (múltiples solicitudes en corto tiempo)
- Implemente rate limiting para operaciones sensibles
- Genere alertas cuando se detecten patrones anómalos
- Exporte logs en formato JSON firmado digitalmente

### 2.3 Biometría y Autenticación (3 puntos)
Implementa autenticación biométrica en `DataProtectionActivity.kt`:
- Integra BiometricPrompt API para proteger el acceso a logs
- Implementa fallback a PIN/Pattern si biometría no está disponible
- Añade timeout de sesión tras inactividad de 5 minutos

## Parte 3: Arquitectura de Seguridad Avanzada (15-20 puntos)

### 3.1 Implementación de Zero-Trust Architecture (3 puntos)
Diseña e implementa un sistema que:
- Valide cada operación sensible independientemente
- Implemente principio de menor privilegio por contexto
- Mantenga sesiones de seguridad con tokens temporales
- Incluya attestation de integridad de la aplicación

### 3.2 Protección Contra Ingeniería Inversa (3 puntos)
Implementa medidas anti-tampering:
- Detección de debugging activo y emuladores
- Obfuscación de strings sensibles y constantes criptográficas
- Verificación de firma digital de la aplicación en runtime
- Implementación de certificate pinning para comunicaciones futuras

### 3.3 Framework de Anonimización Avanzado (2 puntos)
Mejora el método `anonymizeData()` actual implementando:
- Algoritmos de k-anonimity y l-diversity
- Differential privacy para datos numéricos
- Técnicas de data masking específicas por tipo de dato
- Sistema de políticas de retención configurables

```kotlin
class AdvancedAnonymizer {
    fun anonymizeWithKAnonymity(data: List<PersonalData>, k: Int): List<AnonymizedData>
    fun applyDifferentialPrivacy(data: NumericData, epsilon: Double): NumericData
    fun maskByDataType(data: Any, maskingPolicy: MaskingPolicy): Any
}
```

### 3.4 Análisis Forense y Compliance (2 puntos)
Desarrolla un sistema de análisis forense que:
- Mantenga chain of custody para evidencias digitales
- Implemente logs tamper-evident usando blockchain local
- Genere reportes de compliance GDPR/CCPA automáticos
- Incluya herramientas de investigación de incidentes

## Criterios de Evaluación

### Puntuación Base (0-7 puntos):
- Correcta identificación de vulnerabilidades y patrones de seguridad
- Comprensión de conceptos básicos de Android Security
- Documentación clara de hallazgos

### Puntuación Intermedia (8-14 puntos):
- Implementación funcional de mejoras de seguridad
- Código limpio siguiendo principios SOLID
- Manejo adecuado de excepciones y edge cases
- Pruebas unitarias para componentes críticos

### Puntuación Avanzada (15-20 puntos):
- Arquitectura robusta y escalable
- Implementación de patrones de seguridad industry-standard
- Consideración de amenazas emergentes y mitigaciones
- Documentación técnica completa con diagramas de arquitectura
- Análisis de rendimiento y optimización de operaciones criptográficas

## Entregables Requeridos

1. **Código fuente** de todas las implementaciones solicitadas
2. **Informe técnico** detallando vulnerabilidades encontradas y soluciones aplicadas
3. **Diagramas de arquitectura** para componentes de seguridad nuevos
4. **Suite de pruebas** automatizadas para validar medidas de seguridad
5. **Manual de deployment** con consideraciones de seguridad para producción

## Tiempo Estimado
- Parte 1: 2-3 horas
- Parte 2: 4-6 horas  
- Parte 3: 8-12 horas

## Recursos Permitidos
- Documentación oficial de Android
- OWASP Mobile Security Guidelines
- Libraries de seguridad open source
- Stack Overflow y comunidades técnicas

---

**Nota**: Esta evaluación requiere conocimientos sólidos en seguridad móvil, criptografía aplicada y arquitecturas Android modernas. Se valorará especialmente la capacidad de aplicar principios de security-by-design y el pensamiento crítico en la identificación de vectores de ataque.
