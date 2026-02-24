// invariant_sdk/lib/src/api_client.dart
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:developer' as developer; // 🛡️ Import for silent logging
import 'package:http/io_client.dart';
import 'package:crypto/crypto.dart';
import 'internal_certificates.dart'; 

class ApiClient {
  final String apiKey;
  final String hmacSecret;
  final String baseUrl;
  late final IOClient _client;
  
  static const Duration kNetworkTimeout = Duration(seconds: 4);

  ApiClient({
    required this.apiKey,
    required this.hmacSecret,
    String? baseUrl,
  }) : baseUrl = baseUrl ?? "https://16.171.151.222:8443" {
    
    final context = SecurityContext(withTrustedRoots: true);
    
    try {
      context.useCertificateChainBytes(utf8.encode(SdkIdentity.clientCrt));
      context.usePrivateKeyBytes(utf8.encode(SdkIdentity.clientKey));
    } catch (e, stackTrace) {
      // 🛡️ Fixed: Replaced 'print' with developer.log for production safety.
      // This is visible in DevTools but silent in the user's terminal.
      developer.log(
        "FAILED_TO_LOAD_SDK_IDENTITY",
        name: "tech.invariant.sdk",
        error: e,
        stackTrace: stackTrace,
      );
    }
    
    final httpClient = HttpClient(context: context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => false;

    _client = IOClient(httpClient);
  }

  Future<String?> getChallenge() async {
    try {
      final response = await _client.get(
        Uri.parse('$baseUrl/heartbeat/challenge')
      ).timeout(kNetworkTimeout);

      if (response.statusCode == 200) {
        return jsonDecode(response.body)['nonce'];
      }
      return null;
    } catch (_) {
      return null;
    }
  }

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
    };
  }

  Future<Map<String, dynamic>?> verify(Map<String, dynamic> payload, {bool isOfflineFallback = false}) async {
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
        throw Exception("Rate Limit Exceeded");
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  String _generateNonce() {
    final random = Random.secure();
    final values = List<int>.generate(16, (i) => random.nextInt(256));
    return values.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  List<int> hexToBytes(String hexStr) {
    List<int> bytes = [];
    for (int i = 0; i < hexStr.length; i += 2) {
      bytes.add(int.parse(hexStr.substring(i, i + 2), radix: 16));
    }
    return bytes;
  }
}