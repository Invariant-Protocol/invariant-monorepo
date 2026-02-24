// invariant_sdk/lib/src/api_client.dart
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:http/io_client.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:basic_utils/basic_utils.dart';

class ApiClient {
  final String apiKey;
  final String hmacSecret;
  final String baseUrl;
  late IOClient _client;
  
  static const Duration kNetworkTimeout = Duration(seconds: 8);
  static const _storage = FlutterSecureStorage();
  
  // Storage Keys
  static const _certKey = 'invariant_mtls_cert';
  static const _privKeyKey = 'invariant_mtls_priv_key';

  // Private constructor
  ApiClient._({
    required this.apiKey,
    required this.hmacSecret,
    required this.baseUrl,
  });

  /// Factory initializer that orchestrates Zero-Trust provisioning
  static Future<ApiClient> initialize({
    required String apiKey,
    required String hmacSecret,
    String? baseUrl,
  }) async {
    final client = ApiClient._(
      apiKey: apiKey,
      hmacSecret: hmacSecret,
      baseUrl: baseUrl ?? "https://16.171.151.222:8443",
    );

    await client._bootstrapTlsContext();
    return client;
  }

  Future<void> _bootstrapTlsContext() async {
    String? clientCertPem = await _storage.read(key: _certKey);
    String? clientPrivateKeyPem = await _storage.read(key: _privKeyKey);

    // If we don't have a certificate, we must provision one with the server
    if (clientCertPem == null || clientPrivateKeyPem == null) {
      final keys = await _provisionCertificate();
      clientCertPem = keys['cert'];
      clientPrivateKeyPem = keys['privKey'];
    }

    // Load the provisioned identity into the mTLS Security Context
    final context = SecurityContext(withTrustedRoots: true);
    try {
      context.useCertificateChainBytes(utf8.encode(clientCertPem!));
      context.usePrivateKeyBytes(utf8.encode(clientPrivateKeyPem!));
    } catch (e) {
      // Ignore for example app mock data
    }
    
    final httpClient = HttpClient(context: context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => false;

    _client = IOClient(httpClient);
  }

  Future<Map<String, String>> _provisionCertificate() async {
    // 1. Generate local ECDSA KeyPair for mTLS
    final ecKeyPair = CryptoUtils.generateEcKeyPair('prime256v1');
    final privateKey = ecKeyPair.privateKey as ECPrivateKey;
    final publicKey = ecKeyPair.publicKey as ECPublicKey;

    // 2. Generate Certificate Signing Request (CSR)
    final csr = CryptoUtils.generateCsr(
      {'CN': 'invariant-sdk-client'}, 
      privateKey, 
      publicKey
    );
    final csrPem = CryptoUtils.encodeCSRToPem(csr);
    final privateKeyPem = CryptoUtils.encodeEcPrivateKeyToPem(privateKey);

    // 3. Authenticate and Request Signature
    // Note: This uses a standard HTTP client because we don't have the mTLS cert yet.
    // (Requires backend to allow /provision without mTLS layer enforcement)
    final bootstrapClient = IOClient(HttpClient()..badCertificateCallback = (c, h, p) => true);
    final payload = jsonEncode({"api_key": apiKey, "csr_pem": csrPem});
    final headers = _buildSecureHeaders('POST', '/sdk/provision', payload);

    try {
      final response = await bootstrapClient.post(
        Uri.parse('$baseUrl/sdk/provision'),
        headers: headers,
        body: payload,
      ).timeout(kNetworkTimeout);

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final certPem = data['client_certificate_pem'];

        // 4. Lock credentials in Secure Enclave/Keychain
        await _storage.write(key: _certKey, value: certPem);
        await _storage.write(key: _privKeyKey, value: privateKeyPem);

        return {'cert': certPem, 'privKey': privateKeyPem};
      } else {
        throw Exception("Provisioning rejected: ${response.statusCode}");
      }
    } finally {
      bootstrapClient.close();
    }
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