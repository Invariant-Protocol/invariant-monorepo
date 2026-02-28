// invariant_sdk/android/src/main/kotlin/tech/invariant/invariant_sdk/InvariantSdkPlugin.kt
package tech.invariant.invariant_sdk

import androidx.annotation.NonNull
import android.content.Context
import android.app.KeyguardManager
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyInfo
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyFactory

class InvariantSdkPlugin: FlutterPlugin, MethodCallHandler {
    private lateinit var channel : MethodChannel
    private lateinit var context: Context 
    private val KEY_ALIAS = "invariant_hardware_anchor"
    private val TAG = "InvariantHardware"

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "com.invariant.protocol/keystore")
        channel.setMethodCallHandler(this)
        context = flutterPluginBinding.applicationContext
    }

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        try {
            when (call.method) {
                "generateIdentity" -> {
                    if (!isDeviceSecure()) {
                        result.error("DEVICE_INSECURE", "Hardware keygen requires an active lock screen.", null)
                        return
                    }

                    val nonceHex = call.argument<String>("nonce")
                        ?: throw IllegalArgumentException("Nonce is required for attestation")
                    
                    val keyStore = KeyStore.getInstance("AndroidKeyStore")
                    keyStore.load(null)
                    if (keyStore.containsAlias(KEY_ALIAS)) {
                        keyStore.deleteEntry(KEY_ALIAS)
                    }
                    
                    val keyMap = executeHardwareAttestation(nonceHex)
                    result.success(keyMap)
                }
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Hardware attestation failed: ${e.message}")
            result.error("HARDWARE_ATTESTATION_FAILED", e.message, null)
        }
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    private fun isDeviceSecure(): Boolean {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return keyguardManager.isDeviceSecure
    }

    private fun executeHardwareAttestation(nonceHex: String): Map<String, Any> {
        val challengeBytes = hexStringToByteArray(nonceHex)
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        
        // 1. Titanium (StrongBox)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && 
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            try {
                Log.i(TAG, "Attempting TITANIUM Attestation")
                return generateKeyPair(kpg, challengeBytes, useStrongBox = true, includeProps = true)
            } catch (e: Exception) {
                Log.w(TAG, "TITANIUM failed. Degrading to STEEL.")
            }
        }

        // 2. Steel (TEE) with Hardware IDs
        try {
            Log.i(TAG, "Attempting STEEL Attestation (with HW IDs)")
            return generateKeyPair(kpg, challengeBytes, useStrongBox = false, includeProps = true)
        } catch (e: Exception) {
            Log.w(TAG, "TEE rejected HW ID request. Degrading to Base TEE.")
        }

        // 3. Steel (TEE) without Hardware IDs (Software ID Fallback)
        Log.i(TAG, "Attempting Base STEEL Attestation (Software ID Fallback)")
        return generateKeyPair(kpg, challengeBytes, useStrongBox = false, includeProps = false)
    }

    private fun generateKeyPair(
        kpg: KeyPairGenerator, 
        challenge: ByteArray, 
        useStrongBox: Boolean, 
        includeProps: Boolean
    ): Map<String, Any> {
        val builder = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .setUserAuthenticationRequired(true) // 🛡️ Fixes the "No Auth" rejection

        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        if (includeProps && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setDevicePropertiesAttestationIncluded(true)
        }

        kpg.initialize(builder.build())
        val keyPair = kpg.generateKeyPair()

        val factory = KeyStore.getInstance("AndroidKeyStore")
        factory.load(null)
        val entry = factory.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        
        val keyFactory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
        val keyInfo = keyFactory.getKeySpec(entry.privateKey, KeyInfo::class.java)

        if (!keyInfo.isInsideSecureHardware) {
            throw IllegalStateException("Key generated in software. Hardware-rooted identity required.")
        }

        val certs = factory.getCertificateChain(KEY_ALIAS)
        val chainList = certs.map { cert -> cert.encoded.map { it.toInt() and 0xFF }.toList() }
        val publicKeyBytes = keyPair.public.encoded.map { it.toInt() and 0xFF }.toList()

        return mapOf(
            "publicKey" to publicKeyBytes, 
            "attestationChain" to chainList,
            "softwareBrand" to Build.BRAND,       
            "softwareModel" to Build.MODEL,       
            "softwareProduct" to Build.PRODUCT,   
            "tier" to if (useStrongBox) "TITANIUM" else "STEEL"
        )
    }

    private fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}