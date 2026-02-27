// invariant_sdk/lib/invariant_sdk.dart
library invariant_sdk;

import 'package:flutter/services.dart';
import 'src/api_client.dart';
import 'src/verification_service.dart';
import 'src/models.dart';

export 'src/models.dart';

/// The primary interface for the Invariant Protocol SDK.
///
/// Exposes initialization and hardware verification methods to the integrating application.
class Invariant {
  static ApiClient? _client;
  static VerificationService? _verificationService;
  
  static const MethodChannel _channel = MethodChannel('com.invariant.protocol/keystore');

  /// Configures the SDK with the integrating partner's credentials.
  /// Must be called prior to invoking [verifyDevice].
  static void initialize({
    required String apiKey,
    required String hmacSecret,
    InvariantMode mode = InvariantMode.shadow,
    String? baseUrl,
  }) {
    _client = ApiClient(
      apiKey: apiKey,
      hmacSecret: hmacSecret,
      baseUrl: baseUrl,
    );
    
    _verificationService = VerificationService(_client!, mode);
  }

  /// Initiates the hardware attestation flow.
  ///
  /// Requests a nonce from the server, commands the Android Keystore to generate
  /// an attested keypair, and submits the resulting certificate chain for verification.
  static Future<InvariantResult> verifyDevice() async {
    if (_client == null || _verificationService == null) {
      return InvariantResult.deny("SDK not initialized. Call Invariant.initialize() first.");
    }

    final nonce = await _client!.getChallenge();
    
    if (nonce == null) {
      return await _verificationService!.executeVerification({}, networkDown: true);
    }

    Map<dynamic, dynamic> hardwareResult;
    try {
      hardwareResult = await _channel.invokeMethod('generateIdentity', {'nonce': nonce});
    } on PlatformException catch (e) {
      return InvariantResult.deny("Hardware Failure: ${e.message}");
    }

    final payload = {
      "public_key": hardwareResult['publicKey'],         
      "attestation_chain": hardwareResult['attestationChain'], 
      "nonce": _client!.hexToBytes(nonce),
    };

    return await _verificationService!.executeVerification(payload);
  }
}