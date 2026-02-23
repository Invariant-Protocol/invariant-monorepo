// invariant_sdk/lib/src/verification_service.dart

import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter/services.dart';
import 'api_client.dart';
import 'models.dart';

class VerificationService {
  final ApiClient client;
  final InvariantMode mode; // 🛡️ Added: Respect the developer's requested mode
  
  static const MethodChannel _channel = MethodChannel('com.invariant.protocol/keystore');

  VerificationService(this.client, this.mode);
  
  Future<InvariantResult> executeVerification(Map<String, dynamic> hardwarePayload, {bool networkDown = false}) async {
    final prefs = await SharedPreferences.getInstance();
    
    if (!networkDown) {
      try {
        final serverResponse = await client.verify(hardwarePayload);
        
        if (serverResponse != null) {
          // 🛡️ Fixed: Use the dynamic mode instead of hardcoded InvariantMode.shadow
          final result = InvariantResult.fromServer(serverResponse, mode);
          
          if (result.isVerified) {
            await prefs.setString('last_verified_at', DateTime.now().toIso8601String());
          }
          return result;
        }
      } catch (e) {
        // Fall through to offline check
      }
    }

    return await _executeOfflineFallback(prefs, hardwarePayload);
  }

  Future<InvariantResult> _executeOfflineFallback(SharedPreferences prefs, Map<String, dynamic> hardwarePayload) async {
    final policyRaw = prefs.getString('offline_policy');
    if (policyRaw == null) return InvariantResult.deny("Network Error & No Offline Policy");

    final policy = jsonDecode(policyRaw);
    if (policy['enabled'] != true) return InvariantResult.deny("Offline Policy Disabled");

    final lastVerifiedStr = prefs.getString('last_verified_at');
    if (lastVerifiedStr == null) return InvariantResult.deny("Never successfully verified online");
    
    final lastVerified = DateTime.parse(lastVerifiedStr);
    final secondsSinceVerify = DateTime.now().difference(lastVerified).inSeconds;
    
    if (secondsSinceVerify > policy['grace_seconds']) {
      return InvariantResult.deny("Offline Grace Period Expired (${policy['grace_seconds']}s limit)");
    }

    String snapshotSignature = "";
    try {
      final snapshot = await _channel.invokeMethod('signOfflineSnapshot', {
          'timestamp': DateTime.now().toIso8601String()
      });
      snapshotSignature = snapshot['signature'];
    } catch (e) {
      return InvariantResult.deny("Hardware offline signing failed: $e");
    }

    hardwarePayload['offline_snapshot'] = snapshotSignature;
    client.verify(hardwarePayload, isOfflineFallback: true).ignore(); 

    return const InvariantResult(
      decision: InvariantDecision.allowShadow,
      tier: "OFFLINE_CACHE",
      score: 50.0,
      reason: "Network down. Using cached hardware state within grace period.",
      offlineSnapshot: "pending_reconciliation",
    );
  }
}