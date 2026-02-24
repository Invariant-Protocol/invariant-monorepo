// invariant_sdk/lib/invariant_sdk.dart
library invariant_sdk;

import 'package:flutter/services.dart';
import 'src/api_client.dart';
import 'src/verification_service.dart';
import 'src/models.dart';

export 'src/models.dart';

class Invariant {
  static ApiClient? _client;
  static VerificationService? _verificationService;
  
  static const MethodChannel _channel = MethodChannel('com.invariant.protocol/keystore');

  static void initialize({
    required String apiKey,
    required String hmacSecret,
    required String clientCertPem,
    required String clientPrivateKeyPem,
    InvariantMode mode = InvariantMode.shadow,
    String? baseUrl,
  }) {
    _client = ApiClient(
      apiKey: apiKey,
      hmacSecret: hmacSecret,
      clientCertPem: clientCertPem,
      clientPrivateKeyPem: clientPrivateKeyPem,
      baseUrl: baseUrl,
    );
    
    _verificationService = VerificationService(_client!, mode);
  }

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