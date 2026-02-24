// invariant_sdk/example/lib/main.dart

import 'package:flutter/material.dart';
import 'package:invariant_sdk/invariant_sdk.dart';
import 'dart:async';
import 'dart:math';

void main() {
  runApp(const OperationalDashboardApp());
}

class OperationalDashboardApp extends StatelessWidget {
  const OperationalDashboardApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF050505),
        primaryColor: const Color(0xFF00FFC2),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00FFC2),
          secondary: Colors.white,
          surface: Color(0xFF0A0A0A),
        ),
      ),
      home: const TerminalScreen(),
    );
  }
}

// --- 1. SERVICES & LOGIC LAYER ---

enum SimulationMode {
  realNetwork,
  forceAllow,
  forceShadow,
  forceDeny,
}

class VerificationService {
  SimulationMode mode = SimulationMode.realNetwork;

  Future<InvariantResult> verify() async {
    if (mode == SimulationMode.realNetwork) {
      return await Invariant.verifyDevice();
    } else {
      return await _getSimulatedResult(mode);
    }
  }

  Future<InvariantResult> _getSimulatedResult(SimulationMode mode) async {
    await Future.delayed(Duration(milliseconds: 300 + Random().nextInt(400)));

    switch (mode) {
      case SimulationMode.forceAllow:
        return const InvariantResult(
          decision: InvariantDecision.allow,
          tier: "TITANIUM (StrongBox)",
          score: 0.0,
          brand: "Google",
          deviceModel: "Pixel 8 Pro",
          product: "husky",
          bootLocked: true,
        );
      case SimulationMode.forceShadow:
        return const InvariantResult(
          decision: InvariantDecision.allowShadow,
          tier: "SOFTWARE_ONLY",
          score: 75.0,
          brand: "Samsung",
          deviceModel: "Galaxy S23",
          product: "kalama",
          bootLocked: true,
          reason: "Environment Mismatch (Shadow Mode)",
        );
      case SimulationMode.forceDeny:
        return const InvariantResult(
          decision: InvariantDecision.deny,
          tier: "EMULATOR",
          score: 100.0,
          brand: "Generic",
          deviceModel: "Android SDK built for x86",
          product: "sdk_gphone_x86",
          bootLocked: false,
          reason: "Virtualization Detected",
        );
      default:
        return InvariantResult.failOpen("Simulation Error");
    }
  }
}

class TelemetryManager {
  final List<String> _logs = [];
  final List<int> _latencies = [];
  static const int _maxLogs = 100;

  List<String> get logs => List.unmodifiable(_logs);
  
  double get avgLatency => _latencies.isEmpty 
      ? 0.0 
      : _latencies.reduce((a, b) => a + b) / _latencies.length;

  void addLog(String tag, String message) {
    final timestamp = DateTime.now().toIso8601String().substring(11, 19);
    _logs.insert(0, "[$timestamp] $tag: $message"); 
    
    if (_logs.length > _maxLogs) {
      _logs.removeRange(_maxLogs, _logs.length);
    }
  }

  void addLatency(int ms) {
    _latencies.add(ms);
  }

  void clear() {
    _logs.clear();
  }
}

// --- 2. UI LAYER ---

class TerminalScreen extends StatefulWidget {
  const TerminalScreen({super.key});

  @override
  State<TerminalScreen> createState() => _TerminalScreenState();
}

class _TerminalScreenState extends State<TerminalScreen> with SingleTickerProviderStateMixin {
  final VerificationService _verifier = VerificationService();
  final TelemetryManager _telemetry = TelemetryManager();
  
  String _statusDisplay = 'WAITING_FOR_SIGNAL';
  InvariantResult? _lastResult;
  bool _isLoading = false;
  late AnimationController _pulseController;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);

    _telemetry.addLog("SYSTEM", "Initializing Invariant SDK...");
    
    // 🛡️ Clean Partner Integration: Only the authorization identity is provided.
    // The mTLS certificate is securely loaded internally.
    Invariant.initialize(
      apiKey: "pk_live_pilot_evaluation",
      hmacSecret: "mock_hmac_secret_for_ui_testing",
      mode: InvariantMode.shadow,
    );
    
    _telemetry.addLog("SDK", "Ready. Mode: SHADOW.");
  }

  @override
  void dispose() {
    _pulseController.dispose();
    super.dispose();
  }

  Future<void> _runAttestation() async {
    setState(() {
      _isLoading = true;
      _statusDisplay = "ANALYZING...";
      _lastResult = null;
    });

    if (_verifier.mode == SimulationMode.realNetwork) {
       _telemetry.addLog("NET", "Requesting Nonce...");
    } else {
       _telemetry.addLog("SIM", "Simulating ${_verifier.mode.name}...");
    }

    try {
      final startTime = DateTime.now();
      final result = await _verifier.verify();
      final duration = DateTime.now().difference(startTime).inMilliseconds;
      
      _telemetry.addLatency(duration);

      if (!mounted) return;

      switch (result.decision) {
        case InvariantDecision.allow:
           _telemetry.addLog("SUCCESS", "Verified (${duration}ms)");
           break;
        case InvariantDecision.allowShadow:
           _telemetry.addLog("SHADOW", "Allowed w/ Risk (${duration}ms)");
           break;
        case InvariantDecision.deny:
           _telemetry.addLog("REJECTED", "Blocked: ${result.tier}");
           break;
      }

      setState(() {
        _lastResult = result;
        _statusDisplay = result.tier;
        _isLoading = false;
      });

    } catch (e) {
      _telemetry.addLog("CRITICAL", e.toString());
      setState(() {
        _statusDisplay = "FAULT";
        _isLoading = false;
      });
    }
  }

  Color _getStatusColor() {
    if (_isLoading) return Colors.white;
    if (_lastResult == null) return Colors.white24;
    
    switch (_lastResult!.decision) {
      case InvariantDecision.allow: return const Color(0xFF00FFC2);
      case InvariantDecision.allowShadow: return Colors.amberAccent;
      case InvariantDecision.deny: return const Color(0xFFFF2A6D);
    }
  }

  void _showManifest() {
    if (_lastResult == null) return;
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF111111),
      isScrollControlled: true,
      builder: (context) => ManifestSheet(result: _lastResult!),
    );
  }

  @override
  Widget build(BuildContext context) {
    final color = _getStatusColor();

    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              HeaderControlPanel(
                currentMode: _verifier.mode,
                statusColor: color,
                result: _lastResult,
                onModeChanged: (mode) => setState(() => _verifier.mode = mode!),
              ),
              
              const SizedBox(height: 40),

              Center(
                child: StatusDisplay(
                  isLoading: _isLoading,
                  color: color,
                  text: _statusDisplay,
                  result: _lastResult,
                  pulseValue: _pulseController.value,
                ),
              ),

              const SizedBox(height: 40),

              TelemetryHud(
                riskScore: _lastResult?.score ?? 0.0,
                avgLatency: _telemetry.avgLatency,
                onViewManifest: _lastResult != null ? _showManifest : null,
              ),

              const Spacer(),

              LogConsole(logs: _telemetry.logs),

              const SizedBox(height: 16),

              SizedBox(
                width: double.infinity,
                height: 50,
                child: ElevatedButton(
                  onPressed: _isLoading ? null : _runAttestation,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF222222),
                    foregroundColor: Colors.white,
                    side: BorderSide(color: _isLoading ? Colors.white10 : color),
                    shape: const RoundedRectangleBorder(borderRadius: BorderRadius.zero),
                    elevation: 0,
                  ),
                  child: _isLoading 
                    ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                    : Text(
                        "EXECUTE ATTESTATION",
                        style: TextStyle(
                          fontFamily: 'monospace',
                          fontWeight: FontWeight.bold,
                          letterSpacing: 1.5,
                          color: color,
                        ),
                      ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// --- 3. WIDGET COMPONENTS ---

class HeaderControlPanel extends StatelessWidget {
  final SimulationMode currentMode;
  final Color statusColor;
  final InvariantResult? result;
  final ValueChanged<SimulationMode?> onModeChanged;

  const HeaderControlPanel({
    super.key,
    required this.currentMode,
    required this.statusColor,
    required this.result,
    required this.onModeChanged,
  });

  @override
  Widget build(BuildContext context) {
    final isSim = currentMode != SimulationMode.realNetwork;
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Row(
          children: [
            const Text(
              "INVARIANT // OPS",
              style: TextStyle(fontFamily: 'monospace', fontSize: 12, letterSpacing: 2.0, color: Colors.white54),
            ),
            if (isSim)
              Container(
                margin: const EdgeInsets.only(left: 8),
                padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.cyanAccent.withValues(alpha: 0.5)),
                  borderRadius: BorderRadius.circular(2),
                  color: Colors.cyanAccent.withValues(alpha: 0.1)
                ),
                child: const Text("SIMULATION", style: TextStyle(fontSize: 8, color: Colors.cyanAccent, fontWeight: FontWeight.bold)),
              )
          ],
        ),
        Container(
          height: 32,
          padding: const EdgeInsets.symmetric(horizontal: 8),
          decoration: BoxDecoration(
            color: Colors.white10,
            borderRadius: BorderRadius.circular(4),
            border: Border.all(color: isSim ? Colors.cyanAccent.withValues(alpha: 0.3) : Colors.white24)
          ),
          child: DropdownButtonHideUnderline(
            child: DropdownButton<SimulationMode>(
              value: currentMode,
              dropdownColor: const Color(0xFF222222),
              icon: const Icon(Icons.tune, color: Colors.white54, size: 16),
              style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: Colors.white),
              onChanged: onModeChanged,
              items: const [
                DropdownMenuItem(value: SimulationMode.realNetwork, child: Text("REAL (NET)")),
                DropdownMenuItem(value: SimulationMode.forceAllow, child: Text("SIM: ALLOW")),
                DropdownMenuItem(value: SimulationMode.forceShadow, child: Text("SIM: SHADOW")),
                DropdownMenuItem(value: SimulationMode.forceDeny, child: Text("SIM: DENY")),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class StatusDisplay extends StatelessWidget {
  final bool isLoading;
  final Color color;
  final String text;
  final InvariantResult? result;
  final double pulseValue;

  const StatusDisplay({
    super.key,
    required this.isLoading,
    required this.color,
    required this.text,
    required this.result,
    required this.pulseValue,
  });

  @override
  Widget build(BuildContext context) {
    IconData icon = Icons.security;
    if (result?.decision == InvariantDecision.deny) icon = Icons.gpp_bad_rounded;
    if (result?.decision == InvariantDecision.allowShadow) icon = Icons.warning_amber_rounded;

    return Column(
      children: [
        Container(
          width: 120, height: 120,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            border: Border.all(
              color: color.withValues(alpha: isLoading ? pulseValue : 0.3),
              width: 2
            ),
            boxShadow: [
              BoxShadow(
                color: color.withValues(alpha: isLoading ? 0.2 : 0.05),
                blurRadius: 20,
                spreadRadius: 5
              )
            ]
          ),
          child: Center(
            child: Icon(icon, size: 48, color: color),
          ),
        ),
        const SizedBox(height: 24),
        Text(
          text,
          style: TextStyle(
            fontFamily: 'monospace',
            fontSize: 20,
            fontWeight: FontWeight.bold,
            color: color,
            letterSpacing: 1.5,
          ),
        ),
      ],
    );
  }
}

class TelemetryHud extends StatelessWidget {
  final double riskScore;
  final double avgLatency;
  final VoidCallback? onViewManifest;

  const TelemetryHud({
    super.key,
    required this.riskScore,
    required this.avgLatency,
    required this.onViewManifest,
  });

  @override
  Widget build(BuildContext context) {
    Color riskColor = const Color(0xFF00FFC2);
    if (riskScore > 20) riskColor = Colors.amber;
    if (riskScore > 60) riskColor = const Color(0xFFFF2A6D);

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.03),
        border: Border.all(color: Colors.white10),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
               const Text("RISK INDEX", style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: Colors.white54)),
               Text("${riskScore.toStringAsFixed(1)}%", style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: Colors.white)),
            ],
          ),
          const SizedBox(height: 8),
          ClipRRect(
            borderRadius: BorderRadius.circular(2),
            child: LinearProgressIndicator(
              value: riskScore / 100,
              backgroundColor: Colors.white10,
              valueColor: AlwaysStoppedAnimation<Color>(riskColor),
              minHeight: 4,
            ),
          ),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                   const Text("AVG LATENCY", style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: Colors.white54)),
                   const SizedBox(height: 4),
                   Text("${avgLatency.toStringAsFixed(0)} ms", style: const TextStyle(fontFamily: 'monospace', fontSize: 14, color: Colors.white)),
                ],
              ),
              if (onViewManifest != null)
              TextButton(
                onPressed: onViewManifest,
                style: TextButton.styleFrom(
                  padding: EdgeInsets.zero,
                  minimumSize: const Size(50, 30),
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
                child: const Text("VIEW MANIFEST >", style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: Colors.white30)),
              )
            ],
          ),
        ],
      ),
    );
  }
}

class LogConsole extends StatelessWidget {
  final List<String> logs;

  const LogConsole({super.key, required this.logs});

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 120,
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF0A0A0A),
        border: Border.all(color: Colors.white10),
      ),
      child: ListView.separated(
        itemCount: logs.length,
        separatorBuilder: (context, index) => const SizedBox(height: 4),
        itemBuilder: (context, index) {
          final log = logs[index];
          Color logColor = Colors.white38;
          if (log.contains("SUCCESS")) logColor = const Color(0xFF00FFC2);
          if (log.contains("SHADOW") || log.contains("WARN")) logColor = Colors.amber;
          if (log.contains("REJECTED") || log.contains("CRITICAL")) logColor = const Color(0xFFFF2A6D);
          if (log.contains("SIM")) logColor = Colors.cyanAccent;
          
          return Text(
            log,
            style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: logColor),
          );
        },
      ),
    );
  }
}

class ManifestSheet extends StatelessWidget {
  final InvariantResult result;

  const ManifestSheet({super.key, required this.result});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(24),
      height: MediaQuery.of(context).size.height * 0.5,
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text("HARDWARE MANIFEST", style: TextStyle(
              fontFamily: 'monospace', color: Colors.white54, letterSpacing: 2
            )),
            const Divider(color: Colors.white10),
            const SizedBox(height: 10),
            _row("Decision", result.decision.name.toUpperCase()),
            _row("Risk Score", "${result.score.toStringAsFixed(1)} / 100.0"),
            _row("Trust Tier", result.tier),
            _row("Brand", result.brand ?? "N/A"),
            _row("Model", result.deviceModel ?? "N/A"),
            _row("Product", result.product ?? "N/A"),
            _row("Boot Locked", result.bootLocked.toString().toUpperCase()),
            const Divider(color: Colors.white10),
            Text(
              "RAW REASON: ${result.reason ?? "None"}",
               style: const TextStyle(color: Colors.white38, fontFamily: 'monospace', fontSize: 10)
            ),
          ],
        ),
      ),
    );
  }

  Widget _row(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6.0),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(color: Colors.white70, fontFamily: 'monospace')),
          Text(value, style: const TextStyle(color: Colors.white, fontFamily: 'monospace', fontWeight: FontWeight.bold)),
        ],
      ),
    );
  }
}