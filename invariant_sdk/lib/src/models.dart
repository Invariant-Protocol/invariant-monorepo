// invariant_sdk/lib/src/models.dart

enum InvariantMode { enforce, shadow }
enum InvariantDecision { allow, allowShadow, deny }

class InvariantResult {
  final InvariantDecision decision;
  final String tier;
  final double score;
  final String? brand;
  final String? deviceModel;
  final String? product;
  final bool bootLocked;
  final String? reason;
  final String? offlineSnapshot;

  const InvariantResult({
    required this.decision,
    required this.tier,
    required this.score,
    this.brand,
    this.deviceModel,
    this.product,
    this.bootLocked = false,
    this.reason,
    this.offlineSnapshot,
  });

  bool get isVerified => decision == InvariantDecision.allow;

  factory InvariantResult.fromServer(
    Map<String, dynamic> json, 
    InvariantMode mode,
    {String? fallbackBrand, String? fallbackModel, String? fallbackProduct}
  ) {
    final bool isVerified = json['verified'] ?? false;
    final String tier = json['tier'] ?? 'UNKNOWN';
    final double score = (json['risk_score'] as num?)?.toDouble() ?? 100.0;
    
    final String? brand = json['brand'] ?? fallbackBrand;
    final String? deviceModel = json['device_model'] ?? fallbackModel; 
    final String? product = json['product'] ?? fallbackProduct;
    
    final bool bootLocked = json['boot_locked'] ?? false;
    final String? error = json['error'];

    InvariantDecision decision;
    if (isVerified) {
      decision = InvariantDecision.allow;
    } else {
      decision = (mode == InvariantMode.shadow) 
          ? InvariantDecision.allowShadow 
          : InvariantDecision.deny;
    }

    return InvariantResult(
      decision: decision,
      tier: tier,
      score: score,
      brand: brand,
      deviceModel: deviceModel,
      product: product,
      bootLocked: bootLocked,
      reason: error,
    );
  }

  factory InvariantResult.failOpen(String reason) {
    return InvariantResult(
      decision: InvariantDecision.allow,
      tier: "UNVERIFIED_TRANSIENT",
      score: 0.0, 
      reason: reason,
    );
  }

  factory InvariantResult.deny(String reason) {
    return InvariantResult(
      decision: InvariantDecision.deny,
      tier: "REJECTED",
      score: 100.0,
      reason: reason,
    );
  }
}