// lib/pages/home_page.dart

import 'package:flutter/material.dart';
import 'package:nv_engine/models/scan_result.dart';
import 'package:provider/provider.dart';
import 'package:nv_engine/theme/theme_provider.dart';
import 'package:nv_engine/widgets/navigation_panel.dart';
import 'package:nv_engine/utils.dart';
import 'package:nv_engine/models/mock_file.dart';

import 'package:nv_engine/history_database.dart';
import 'package:nv_engine/ai_service.dart';

class AntivirusHomePage extends StatefulWidget {
  const AntivirusHomePage({super.key});

  @override
  _AntivirusHomePageState createState() => _AntivirusHomePageState();
}

class _AntivirusHomePageState extends State<AntivirusHomePage> {
  bool _realTimeProtectionEnabled = true;
  bool _notificationsEnabled = true;
  int _selectedIndex = 0;
  String _status = "Ready to scan!";
  bool _isScanning = false;
  List<ScanResult> _scanHistory = [];
  static bool _darkModeEnabled = false;

  final Color primaryBlue = const Color(0xFF1F2A44);
  final Color accentGreen = const Color(0xFF42A67F);
  final Color softGray = const Color(0xFFBFC0C0);

  HistoryDatabase history = HistoryDatabase();

  Future<void> _startScan() async {
    List<MockFile> filesToScan = [
      MockFile(filename: "System32.dll", features: [8.2, 1.0, 4.0, 7.8]),
      MockFile(filename: "Secret_Trojan.exe", features: [7.6, 1.0, 3.0, 6.9]),
      MockFile(filename: "Resume.pdf", features: [4.2, 0.0, 0.0, 3.5]),
      MockFile(filename: "Downloader.mal", features: [7.9, 1.0, 2.0, 7.1]),
      MockFile(filename: "vacation.jpg", features: [5.1, 0.0, 1.0, 4.4]),
    ];

    int threats = 0;

    for (var file in filesToScan) {
      setState(() {
        _status = "Scanning ${file.filename}...";
      });

      await Future.delayed(Duration(milliseconds: 600));

      final prediction = await runMalwarePrediction(file.features);
      file.prediction = prediction;

      if (prediction == 1) {
        threats++;
      }
    }

    final infectedFiles = filesToScan.where((f) => f.prediction == 1).toList();

    print("🛑 Infected Files:");
    if (infectedFiles.isEmpty) {
      print("✅ No infected files found.");
    } else {
      for (var file in infectedFiles) {
        print("- ${file.filename}");
      }
    }

    final result =
        threats == 0
            ? "No threats detected."
            : "$threats threat${threats > 1 ? 's' : ''} detected.";

    final newResult = ScanResult(amount: threats);

    final now = DateTime.now();
    int nowm = now.month;
    int nowd = now.day;
    int nowh = now.hour;
    int nowmin = now.minute;
    
    await history.insertHistory(threats, nowm, nowd, nowh, nowmin);

    _scanHistory.add(newResult);

    setState(() {
      _isScanning = false;
      _status = "Scan Complete! $result";
    });
  }

  Widget _buildOverviewPage() {
    return LayoutBuilder(
      builder: (context, constraints) {
        double iconSize = constraints.maxHeight * 0.2;

        return Padding(
          padding: const EdgeInsets.all(40.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.shield,
                size: iconSize.clamp(120.0, 300.0),
                color: accentGreen,
              ),
              const SizedBox(height: 20),
              Text(
                _status,
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.bold,
                  color:
                      _status.contains("No threats")
                          ? accentGreen
                          : (_status.contains("Ready")
                              ? Theme.of(context).textTheme.headlineLarge?.color
                              : Colors.orange),
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 10),
              FutureBuilder(
              future: history.getHistory(),
              builder: (BuildContext context, AsyncSnapshot snapshot) {
                if (snapshot.connectionState == ConnectionState.waiting) {
                  return Center(child: CircularProgressIndicator());
                } else if (snapshot.hasError) {
                  return Text('Error: ${snapshot.error}');
                } else if (snapshot.data == null || snapshot.data.isEmpty) {
                  return Center(child: Text('No scan history'));
                } else {
                  return Text('Last scan on: ${snapshot.data?[snapshot.data!.length - 1]['month']}/${snapshot.data?[snapshot.data!.length - 1]['day']} ${snapshot.data?[snapshot.data!.length - 1]['hour']}:${snapshot.data?[snapshot.data!.length - 1]['minute'] < 10 ? '0${snapshot.data?[snapshot.data!.length - 1]['minute']}':'${snapshot.data?[snapshot.data!.length - 1]['minute']}'}');
                }
              },
            ),
              const SizedBox(height: 30),
              ElevatedButton(
                onPressed: _isScanning ? null : _startScan,
                style: ElevatedButton.styleFrom(
                  backgroundColor: accentGreen,
                  padding: const EdgeInsets.symmetric(
                    horizontal: 40,
                    vertical: 16,
                  ),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                child: Text(
                  _isScanning ? "Scanning..." : "Start Scan",
                  style: const TextStyle(fontSize: 18, color: Colors.white),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildProtectionPage() {
    return LayoutBuilder(
      builder: (context, constraints) {
        return SingleChildScrollView(
          padding: const EdgeInsets.all(40.0),
          child: ConstrainedBox(
            constraints: BoxConstraints(minHeight: constraints.maxHeight),
            child: IntrinsicHeight(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    "Protection Settings",
                    style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 30),

                  if (!_realTimeProtectionEnabled)
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(16),
                      margin: const EdgeInsets.only(bottom: 20),
                      decoration: BoxDecoration(
                        color: Colors.red.shade100,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Row(
                        children: [
                          const Icon(Icons.warning, color: Colors.red),
                          const SizedBox(width: 10),
                          const Expanded(
                            child: Text(
                              "Warning: Real-Time Protection is disabled. Your system might be at risk.",
                              style: TextStyle(
                                color: Colors.red,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),

                  SwitchListTile(
                    value: _realTimeProtectionEnabled,
                    onChanged: (val) {
                      setState(() {
                        _realTimeProtectionEnabled = val;
                      });
                    },
                    title: const Text("Enable Real-Time Protection"),
                  ),

                  ListTile(
                    leading: Icon(Icons.shield, color: accentGreen),
                    title: const Text("Firewall: Active"),
                    subtitle: const Text(
                      "Your system is protected from network threats.",
                    ),
                  ),

                  ExpansionTile(
                    leading: const Icon(Icons.warning_amber, color: Colors.red),
                    title: const Text("Threats Blocked: 5"),
                    subtitle: const Text("Last 30 days"),
                    children: [
                      ListTile(
                        title: const Text("Malware.ABC"),
                        subtitle: const Text("Blocked on Apr 1"),
                        trailing: ElevatedButton(
                          onPressed: () {},
                          child: const Text("Details"),
                        ),
                      ),
                      ListTile(
                        title: const Text("Trojan.XYZ"),
                        subtitle: const Text("Blocked on Mar 30"),
                        trailing: ElevatedButton(
                          onPressed: () {},
                          child: const Text("Details"),
                        ),
                      ),
                      ListTile(
                        title: const Text("Spyware.123"),
                        subtitle: const Text("Blocked on Mar 27"),
                        trailing: ElevatedButton(
                          onPressed: () {},
                          child: const Text("Details"),
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 20),
                  ElevatedButton.icon(
                    onPressed: _isScanning ? null : _startScan,
                    icon: const Icon(Icons.search, color: Colors.white),
                    label: const Text(
                      "Run Quick Scan",
                      style: TextStyle(fontSize: 18, color: Colors.white),
                    ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: accentGreen,
                      padding: const EdgeInsets.symmetric(
                        horizontal: 40,
                        vertical: 16,
                      ),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildReportPage() {
    return Padding(
      padding: const EdgeInsets.all(40.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                "Scan Report",
                style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
              ),
              FutureBuilder<bool>(
                future: history.historyHasData(),
                builder: (context, snapshot) {
                  switch (snapshot.connectionState) {
                    case ConnectionState.waiting:
                      return Center(child: CircularProgressIndicator());
                    default:
                      if (snapshot.hasError) {
                        return Text('Error: ${snapshot.error}');
                      } else {
                        if (snapshot.data!) {
                          return ElevatedButton.icon(
                            onPressed: () {
                              setState(() {
                                _scanHistory.clear();
                              });
                              history.clearhistory();
                            },
                            icon: const Icon(Icons.delete, color: Colors.white),
                            label: const Text(
                              "Clear",
                              style: TextStyle(color: Colors.white),
                            ),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.redAccent,
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 10,
                              ),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(10),
                              ),
                            ),
                          );
                        } else {
                          return ElevatedButton.icon(
                            onPressed: null,
                            icon: const Icon(Icons.delete, color: Colors.white),
                            label: const Text(
                              "Clear",
                              style: TextStyle(color: Colors.white),
                            ),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.redAccent,
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 10,
                              ),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(10),
                              ),
                            ),
                          );
                        }
                      }
                  }
                },
              ),
            ],
          ),
          const SizedBox(height: 20),
          Expanded(
            child: FutureBuilder(
              future: history.getHistory(),
              builder: (BuildContext context, AsyncSnapshot snapshot) {
                if (snapshot.connectionState == ConnectionState.waiting) {
                  return Center(child: CircularProgressIndicator());
                } else if (snapshot.hasError) {
                  return Text('Error: ${snapshot.error}');
                } else if (snapshot.data == null || snapshot.data.isEmpty) {
                  return Center(child: Text('History is empty'));
                } else {
                  return ListView.builder(
                    itemCount: snapshot.data.length,
                    itemBuilder: (context, index) {
                      return ListTile(
                        leading: Icon(
                          snapshot.data?[index]['amount'] > 0
                              ? Icons.error
                              : Icons.check_circle,
                          color:
                              snapshot.data?[index]['amount'] > 0
                                  ? Colors.red
                                  : Colors.green,
                        ),
                        title: Text(
                          'Threat${snapshot.data?[index]['amount'] > 1 ? 's':''} detected: ${snapshot.data?[index]['amount']}',
                        ),
                        subtitle: Text('Scanned on: ${snapshot.data?[index]['month']}/${snapshot.data?[index]['day']} ${snapshot.data?[index]['hour']}:${snapshot.data?[index]['minute'] < 10 ? '0${snapshot.data?[index]['minute']}':'${snapshot.data?[index]['minute']}'}'),
                      );
                    },
                  );
                }
              },
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSettingsPage() {
    return Padding(
      padding: const EdgeInsets.all(40.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            "Settings",
            style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 20),
          SwitchListTile(
            value: _notificationsEnabled,
            onChanged: (val) {
              setState(() {
                _notificationsEnabled = val;
              });
            },
            title: const Text("Enable Notifications"),
          ),
          SwitchListTile(
            value: _darkModeEnabled,
            onChanged: (bool value) {
              Provider.of<ThemeProvider>(context, listen: false).toggleTheme();
              setState(() {
                _darkModeEnabled = value;
              });
            },
            title: const Text("Dark Mode"),
          ),
        ],
      ),
    );
  }

  Widget _buildPage() {
    switch (_selectedIndex) {
      case 0:
        return _buildOverviewPage();
      case 1:
        return _buildProtectionPage();
      case 2:
        return _buildReportPage();
      case 3:
        return _buildSettingsPage();
      default:
        return _buildOverviewPage();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          NavigationPanel(
            backgroundColor: primaryBlue,
            onItemSelected: (index) {
              setState(() {
                _selectedIndex = index;
              });
            },
            selectedIndex: _selectedIndex,
          ),
          Expanded(child: _buildPage()),
        ],
      ),
    );
  }
}
