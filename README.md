# USB Security Scanner

A comprehensive security tool for scanning USB drives and monitoring network activity, built with Python and wxPython.

## Features

### 1. USB Drive Scanning
- 🔍 Real-time USB device detection
- 📁 Automatic drive recognition
- 🛡️ File threat analysis using VirusTotal API
- ⚡ Fast scanning with progress tracking
- 🚫 Detection of suspicious file types

### 2. IP Monitoring
- 🌐 Real-time IP connection tracking
- ⚠️ Suspicious IP detection
- 📊 Connection statistics
- 🕒 First and last seen timestamps
- 🔄 Auto-refresh every 3 seconds

### 3. Threat Detection
- 🎯 Multiple threat levels (HIGH, MODERATE, LOW)
- 🎨 Color-coded threat indicators
- 📝 Detailed threat descriptions
- ⚡ Real-time threat updates
- 🔒 Quarantine functionality

### 4. System Monitoring
- 💻 CPU usage monitoring
- 💾 RAM usage tracking
- 📈 Real-time performance graphs
- 🔄 Automatic updates

### 5. Activity Logging
- 📝 Comprehensive activity logs
- 🎨 Color-coded log entries
- 💾 Log file export
- 🔍 Clear log viewing
- 📊 Auto-scroll functionality

## Requirements

```bash
pip install -r requirements.txt
```

Required packages:
- wxPython
- psutil
- requests
- pywin32 (for Windows)
- scapy (optional, for enhanced network monitoring)

## Configuration

1. Create a `config.ini` file in the application directory
2. Add your VirusTotal API key:
```ini
[VirusTotal]
api_key = YOUR_API_KEY_HERE
max_file_size_mb = 32
rate_limit_delay = 15
```

## Usage

1. Run the application:
```bash
python usb_scanner.py
```

2. Main Features:
   - **USB Scanning**: Insert a USB drive and click "Scan"
   - **IP Monitoring**: View real-time network connections
   - **Threat Management**: Use quarantine/remove buttons for detected threats
   - **Activity Log**: Monitor all activities and export logs

3. Controls:
   - 🔍 Scan: Start USB drive scanning
   - 🔄 Refresh: Update drive list
   - ⚠️ Quarantine: Move suspicious files to quarantine
   - 🗑️ Remove: Delete suspicious files
   - 💾 Save Log: Export activity log

## Security Features

### Threat Detection
- File signature analysis
- Suspicious extension detection
- VirusTotal integration
- Behavioral analysis
- Real-time monitoring

### Network Security
- Suspicious IP detection
- Connection monitoring
- Traffic analysis
- IP reputation checking

### File Protection
- Quarantine system
- Safe file removal
- Threat isolation
- Recovery options

## Troubleshooting

1. **USB Not Detected**
   - Ensure proper USB connection
   - Click refresh button
   - Check device manager

2. **Scanning Issues**
   - Verify VirusTotal API key
   - Check internet connection
   - Ensure sufficient permissions

3. **Network Monitoring**
   - Check network adapter status
   - Verify firewall settings
   - Ensure admin privileges

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- VirusTotal API for threat detection
- wxPython for the GUI framework
- psutil for system monitoring
- Python community for various libraries

## Support

For support, please:
1. Check the troubleshooting guide
2. Review existing issues
3. Create a new issue with detailed information

---

Made with ❤️ for USB security 