import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SecretBay VPN',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      home: const VPNConfigPage(),
    );
  }
}

class VPNConfigPage extends StatefulWidget {
  const VPNConfigPage({super.key});

  @override
  State<VPNConfigPage> createState() => _VPNConfigPageState();
}

class _VPNConfigPageState extends State<VPNConfigPage> {
  final _formKey = GlobalKey<FormState>();
  bool _isLoading = false;
  String? _errorMessage;
  
  final _serverIPController = TextEditingController();
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();
  String _selectedVPNType = 'openvpn';

  Future<void> _configureVPN() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final response = await http.post(
        Uri.parse('/api/vpn/configure'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'server_ip': _serverIPController.text,
          'username': _usernameController.text,
          'auth_method': 'password',
          'auth_credential': _passwordController.text,
          'vpn_type': _selectedVPNType,
        }),
      );

      if (response.statusCode == 200) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('VPN configured successfully!')),
        );
      } else {
        throw Exception('Failed to configure VPN: ${response.body}');
      }
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('SecretBay VPN Configuration'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Server Configuration',
                        style: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 16),
                      TextFormField(
                        controller: _serverIPController,
                        decoration: const InputDecoration(
                          labelText: 'Server IP',
                          border: OutlineInputBorder(),
                        ),
                        validator: (value) {
                          if (value == null || value.isEmpty) {
                            return 'Please enter the server IP';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 16),
                      TextFormField(
                        controller: _usernameController,
                        decoration: const InputDecoration(
                          labelText: 'Username',
                          border: OutlineInputBorder(),
                        ),
                        validator: (value) {
                          if (value == null || value.isEmpty) {
                            return 'Please enter the username';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 16),
                      TextFormField(
                        controller: _passwordController,
                        decoration: const InputDecoration(
                          labelText: 'Password',
                          border: OutlineInputBorder(),
                        ),
                        obscureText: true,
                        validator: (value) {
                          if (value == null || value.isEmpty) {
                            return 'Please enter the password';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 16),
                      DropdownButtonFormField<String>(
                        value: _selectedVPNType,
                        decoration: const InputDecoration(
                          labelText: 'VPN Type',
                          border: OutlineInputBorder(),
                        ),
                        items: const [
                          DropdownMenuItem(
                            value: 'openvpn',
                            child: Text('OpenVPN'),
                          ),
                          DropdownMenuItem(
                            value: 'ikev2',
                            child: Text('IKEv2 (iOS)'),
                          ),
                        ],
                        onChanged: (value) {
                          setState(() {
                            _selectedVPNType = value!;
                          });
                        },
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              if (_errorMessage != null)
                Card(
                  color: Colors.red[100],
                  child: Padding(
                    padding: const EdgeInsets.all(16.0),
                    child: Text(
                      _errorMessage!,
                      style: TextStyle(color: Colors.red[900]),
                    ),
                  ),
                ),
              const SizedBox(height: 16),
              ElevatedButton(
                onPressed: _isLoading ? null : _configureVPN,
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.all(16),
                ),
                child: _isLoading
                    ? const CircularProgressIndicator()
                    : const Text('Configure VPN'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _serverIPController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    super.dispose();
  }
} 