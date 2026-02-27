// invariant_sdk/lib/src/api_client.dart
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:developer' as developer;
import 'package:http/io_client.dart';
import 'package:crypto/crypto.dart';
import 'internal_certificates.dart'; 

/// Handles secure HTTP communication with the Invariant Node.
///
/// Ensures request authenticity through a dual-layer security model:
/// 1. Transport Layer: Enforces mTLS using the compiled-in SDK certificate to prove SDK authenticity.
/// 2. Application Layer: Signs request payloads using HMAC-SHA256 bound to the Partner's API Key to authorize the integration.
class ApiClient {
  /// The partner's public API identifier.
  final String apiKey;
  
  /// The partner's secret key used for HMAC request signing.
  final String hmacSecret;
  
  /// The base URL of the Invariant Node.
  final String baseUrl;
  
  late final IOClient _client;
  late final String _certFingerprint;
  
  static const Duration kNetworkTimeout = Duration(seconds: 15);

  /// Initializes the API Client and configures the mTLS SecurityContext.
  ApiClient({
    required this.apiKey,
    required this.hmacSecret,
    String? baseUrl,
  }) : baseUrl = baseUrl ?? "https://16.171.151.222:8443" {
    
    final context = SecurityContext(withTrustedRoots: true);
    
    try {
      context.useCertificateChainBytes(utf8.encode(SdkIdentity.clientCrt));
      context.usePrivateKeyBytes(utf8.encode(SdkIdentity.clientKey));
      developer.log("SDK Identity loaded into SecurityContext", name: "tech.invariant.sdk");
    } catch (e, stackTrace) {
      developer.log("FAILED_TO_LOAD_SDK_IDENTITY", name: "tech.invariant.sdk", error: e, stackTrace: stackTrace);
    }
    
    _certFingerprint = sha256.convert(utf8.encode(SdkIdentity.clientCrt)).toString();
    
    // 🛡️ Restored to a silent developer log for production
    developer.log("SDK Fingerprint initialized: $_certFingerprint", name: "tech.invariant.sdk");

    final httpClient = HttpClient(context: context)
      ..connectionTimeout = kNetworkTimeout
      ..badCertificateCallback = (X509Certificate cert, String host, int port) {
        if (host == '16.171.151.222') {
            return true; 
        }
        return false;
      };

    _client = IOClient(httpClient);
  }

  /// Requests a cryptographic challenge (nonce) from the server.
  ///
  /// This nonce is required by the hardware enclave to prevent replay attacks
  /// during the generation of the attestation signature.
  Future<String?> getChallenge() async {
    developer.log("Attempting GET $baseUrl/heartbeat/challenge", name: "tech.invariant.sdk");
    try {
      final response = await _client.get(
        Uri.parse('$baseUrl/heartbeat/challenge'),
        headers: {
          'X-Client-Cert-Fingerprint': _certFingerprint,
          'X-Invariant-ApiKey': apiKey,
        }
      ).timeout(kNetworkTimeout);

      if (response.statusCode == 200) {
        return jsonDecode(response.body)['nonce'];
      }
      
      developer.log("Challenge request rejected: ${response.statusCode}", name: "tech.invariant.sdk");
      return null;
    } catch (e, stackTrace) {
      developer.log("Network Error on getChallenge", name: "tech.invariant.sdk", error: e, stackTrace: stackTrace);
      return null;
    }
  }

  /// Constructs the required HTTP headers for the Invariant protocol.
  ///
  /// Computes the HMAC-SHA256 signature over a canonical request string
  /// comprising the HTTP method, URI path, host, body hash, timestamp, and nonce.
  Map<String, String> _buildSecureHeaders(String method, String path, String bodyString) {
    final timestamp = (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
    final nonce = _generateNonce();
    
    final bodyBytes = utf8.encode(bodyString);
    final bodyHash = sha256.convert(bodyBytes).toString();
    
    final host = Uri.parse(baseUrl).host;
    final canonicalString = "$method\n$path\n\nhost:$host\n$bodyHash\n$timestamp\n$nonce";
    
    final hmacKey = utf8.encode(hmacSecret);
    final hmacBytes = utf8.encode(canonicalString);
    final hmac = Hmac(sha256, hmacKey);
    final signature = hmac.convert(hmacBytes).toString();

    return {
      'Content-Type': 'application/json',
      'X-Invariant-ApiKey': apiKey,
      'X-Invariant-Timestamp': timestamp,
      'X-Invariant-Nonce': nonce,
      'X-Invariant-Signature': signature,
      'X-Client-Cert-Fingerprint': _certFingerprint,
    };
  }

  /// Transmits the hardware attestation payload to the Invariant backend for verification.
  ///
  /// Automatically appends offline reconciliation headers if [isOfflineFallback] is true.
  Future<Map<String, dynamic>?> verify(Map<String, dynamic> payload, {bool isOfflineFallback = false}) async {
    developer.log("Attempting POST $baseUrl/verify", name: "tech.invariant.sdk");
    try {
      const path = '/verify';
      final bodyStr = jsonEncode(payload);
      final headers = _buildSecureHeaders('POST', path, bodyStr);

      if (isOfflineFallback) {
        headers['X-Invariant-Offline'] = 'true';
        headers['X-Invariant-Offline-Snapshot'] = payload['offline_snapshot'] ?? '{}';
      }

      final response = await _client.post(
        Uri.parse('$baseUrl$path'), 
        headers: headers,
        body: bodyStr,
      ).timeout(kNetworkTimeout);

      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      } else if (response.statusCode == 429) {
        developer.log("Rate Limit Exceeded", name: "tech.invariant.sdk");
        throw Exception("Rate Limit Exceeded");
      } else {
        developer.log("Server rejected payload: ${response.statusCode} - ${response.body}", name: "tech.invariant.sdk");
        return null;
      }
    } catch (e, stackTrace) {
      developer.log("Network Error on verify", name: "tech.invariant.sdk", error: e, stackTrace: stackTrace);
      return null;
    }
  }

  /// Generates a local 16-byte cryptographically secure random nonce.
  String _generateNonce() {
    final random = Random.secure();
    final values = List<int>.generate(16, (i) => random.nextInt(256));
    return values.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Converts a hexadecimal string representation into a list of bytes.
  List<int> hexToBytes(String hexStr) {
    List<int> bytes = [];
    for (int i = 0; i < hexStr.length; i += 2) {
      bytes.add(int.parse(hexStr.substring(i, i + 2), radix: 16));
    }
    return bytes;
  }
}