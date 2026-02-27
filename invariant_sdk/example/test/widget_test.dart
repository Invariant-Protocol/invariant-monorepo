// invariant_sdk/example/test/widget_test.dart

import 'package:flutter_test/flutter_test.dart';
import 'package:invariant_app/main.dart'; // Ensure this matches your package name in pubspec.yaml

void main() {
  testWidgets('Verify Operational Dashboard loads', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    // 🚀 FIXED: Updated class name from ShadowTestApp to OperationalDashboardApp
    await tester.pumpWidget(const OperationalDashboardApp());

    // Verify that the dashboard header exists
    expect(find.text('INVARIANT // OPS DASHBOARD'), findsOneWidget);
    
    // Verify the execute button exists
    expect(find.text('EXECUTE ATTESTATION'), findsOneWidget);
  });
}