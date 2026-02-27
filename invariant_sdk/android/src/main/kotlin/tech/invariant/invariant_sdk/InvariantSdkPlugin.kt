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
import java.security.InvalidAlgorithmParameterException

/**
 * InvariantSdkPlugin
 *
 * Bridges the Flutter SDK to the Android Keystore API to perform hardware-backed
 * key generation and remote attestation. Ensures that cryptographic material is
 * bound to physical silicon (TEE or StrongBox).
 */
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

    /**
     * Verifies that the Android device has a secure lock screen enabled (PIN, pattern, or password).
     * This is a prerequisite for generating high-assurance keys in the Keystore.
     */
    private fun isDeviceSecure(): Boolean {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return keyguardManager.isDeviceSecure
    }

    /**
     * Orchestrates the hardware attestation flow.
     * * Attempts to generate a StrongBox-backed key first to attain the highest trust tier.
     * If the hardware does not support StrongBox, it falls back to a standard TEE-backed key.
     */
    private fun executeHardwareAttestation(nonceHex: String): Map<String, Any> {
        val challengeBytes = hexStringToByteArray(nonceHex)
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && 
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            try {
                Log.i(TAG, "Initiating TITANIUM (StrongBox) Attestation")
                return generateKeyPair(kpg, challengeBytes, useStrongBox = true, includeProps = true)
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox generation failed. Falling back to STEEL tier.")
            }
        }

        Log.i(TAG, "Initiating STEEL (TEE) Attestation")
        return generateKeyPair(kpg, challengeBytes, useStrongBox = false, includeProps = false)
    }

    /**
     * Configures the KeyGenParameterSpec and generates the ECDSA key pair.
     * Extracts the public key and the X.509 attestation certificate chain.
     */
    private fun generateKeyPair(
        kpg: KeyPairGenerator, 
        challenge: ByteArray, 
        useStrongBox: Boolean, 
        includeProps: Boolean
    ): Map<String, Any> {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)

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
            "softwareBrand" to Build.MANUFACTURER,
            "softwareModel" to Build.MODEL,
            "tier" to if (useStrongBox) "TITANIUM" else "STEEL"
        )
    }

    /**
     * Converts a hexadecimal string to a byte array for cryptographic operations.
     */
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