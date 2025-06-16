import 'dart:convert';
import 'package:http/http.dart' as http;

Future<int> runMalwarePrediction(
  List<double> inputValues, {
  http.Client? client,
}) async {
  final httpClient = client ?? http.Client();
  final shouldClose = client == null;
  final uri = Uri.parse(
    "http://127.0.0.1:5000/predict",
  ); // or use your IP if on real device

  final response = await httpClient.post(
    uri,
    headers: {"Content-Type": "application/json"},
    body: jsonEncode({"input": inputValues}),
  );

  if (response.statusCode == 200) {
    final result = jsonDecode(response.body);
    if (shouldClose) {
      httpClient.close();
    }
    return result["prediction"];
  } else {
    if (shouldClose) {
      httpClient.close();
    }
    throw Exception("Prediction failed: ${response.body}");
  }
}
