import 'dart:convert';

import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'package:nv_engine/ai_service.dart';

void main() {
  test('runMalwarePrediction returns 0 or 1', () async {
    final mockClient = MockClient((request) async {
      return http.Response(jsonEncode({'prediction': 1}), 200);
    });

    final result = await runMalwarePrediction(
      [7.9, 1.0, 3.0, 7.2],
      client: mockClient,
    );

    expect(result, anyOf(0, 1));
  });
}
