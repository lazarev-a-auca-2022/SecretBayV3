document.addEventListener('DOMContentLoaded', function() {
    // Get form elements
    const vpnForm = document.getElementById('vpn-form');
    const authMethod = document.getElementById('auth-method');
    const passwordField = document.getElementById('password-field');
    const keyField = document.getElementById('key-field');
    const serverIp = document.getElementById('server-ip');
    const username = document.getElementById('username');
    const password = document.getElementById('password');
    const sshKey = document.getElementById('ssh-key');
    const vpnType = document.getElementById('vpn-type');
    const loading = document.getElementById('loading');
    const resultArea = document.getElementById('result-area');
    const errorMessage = document.getElementById('error-message');
    const downloadConfig = document.getElementById('download-config');
    const newPassword = document.getElementById('new-password');

    // Toggle between password and key authentication
    authMethod.addEventListener('change', function() {
        if (this.value === 'password') {
            passwordField.style.display = 'block';
            keyField.style.display = 'none';
        } else {
            passwordField.style.display = 'none';
            keyField.style.display = 'block';
        }
    });

    // Handle form submission
    vpnForm.addEventListener('submit', function(e) {
        e.preventDefault();

        // Validate form
        if (!serverIp.value || !username.value) {
            showError('Please fill in all required fields.');
            return;
        }

        if (authMethod.value === 'password' && !password.value) {
            showError('Password is required for password authentication.');
            return;
        }

        if (authMethod.value === 'key' && !sshKey.value) {
            showError('SSH key is required for key authentication.');
            return;
        }

        // Show loading indicator
        loading.style.display = 'block';
        errorMessage.style.display = 'none';
        resultArea.style.display = 'none';

        // Prepare request data
        const requestData = {
            server_ip: serverIp.value,
            username: username.value,
            auth_method: authMethod.value,
            auth_credential: authMethod.value === 'password' ? password.value : sshKey.value,
            vpn_type: vpnType.value
        };

        // Send API request
        fetch('/api/vpn/configure', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => {
                    throw new Error(text || 'Failed to configure VPN. Please try again.');
                });
            }
            return response.json();
        })
        .then(data => {
            // Hide loading indicator
            loading.style.display = 'none';

            // Store configuration data
            if (data.config_file && data.new_password) {
                // Set download link
                downloadConfig.setAttribute('href', 'data:application/octet-stream;base64,' + data.config_file);
                downloadConfig.setAttribute('download', vpnType.value === 'openvpn' ? 'secretbay.ovpn' : 'secretbay.mobileconfig');

                // Show new password
                newPassword.textContent = data.new_password;

                // Show result area
                resultArea.style.display = 'block';
            } else {
                showError('Invalid response from server. Please try again.');
            }
        })
        .catch(error => {
            // Hide loading indicator
            loading.style.display = 'none';

            // Show error message
            showError(error.message || 'Failed to configure VPN. Please try again.');
        });
    });

    // Helper function to show error message
    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
    }
}); 