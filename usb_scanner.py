import os
import sys
import time
import json
import shutil
import requests
import wx
import wx.adv
import wx.grid
from pathlib import Path
import win32file
import win32con
import threading
from network_monitor import NetworkMonitor
from datetime import datetime, timedelta
import configparser
import hashlib
import psutil
import socket
from ipaddress import ip_address, IPv4Address

# Make scapy optional
SCAPY_AVAILABLE = False
try:
    import scapy.all as scapy
    from scapy.layers import http
    SCAPY_AVAILABLE = True
except ImportError:
    pass

try:
    from system_monitor import SystemMonitorPanel
    SYSTEM_MONITOR_AVAILABLE = True
except ImportError:
    SYSTEM_MONITOR_AVAILABLE = False

class NetworkAnalyzer:
    def __init__(self, config):
        try:
            self.config = config
            self.suspicious_ips = set()
            self.known_macs = {}
            self.ip_connections = {}
            self.running = False
            self.thread = None
            
            # Load API keys
            self.abuseipdb_key = self.config.get('AbuseIPDB', 'api_key', fallback='')
            self.virustotal_key = self.config.get('VirusTotal', 'api_key', fallback='')
            
            # Initialize interfaces
            self.interfaces = {}
            self.get_network_interfaces()
        except Exception as e:
            print(f"Error initializing NetworkAnalyzer: {e}")
            self.running = False
    
    def get_network_interfaces(self):
        """Get all available network interfaces"""
        try:
            for iface in psutil.net_if_addrs().keys():
                try:
                    addrs = psutil.net_if_addrs()[iface]
                    if any(addr.family == socket.AF_INET for addr in addrs):  # Has IPv4
                        ip = next((addr.address for addr in addrs if addr.family == socket.AF_INET), None)
                        mac = next((addr.address for addr in addrs if addr.family == psutil.AF_LINK), None)
                        if ip:
                            self.interfaces[iface] = {'ip': ip, 'mac': mac}
                except Exception:
                    continue
            return self.interfaces
        except Exception as e:
            print(f"Error getting network interfaces: {e}")
            return {}
    
    def start_monitoring(self):
        """Start network monitoring"""
        if not SCAPY_AVAILABLE:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self.capture_packets)
        self.thread.daemon = True
        self.thread.start()
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
    
    def capture_packets(self):
        """Capture and analyze network packets"""
        if not SCAPY_AVAILABLE:
            return
            
        try:
            scapy.sniff(prn=self.analyze_packet, store=False, 
                       stop_filter=lambda _: not self.running)
        except Exception as e:
            print(f"Error capturing packets: {e}")
    
    def analyze_packet(self, packet):
        """Analyze a network packet"""
        if not SCAPY_AVAILABLE:
            return
            
        try:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                # Skip local and private IPs
                if (self.is_private_ip(src_ip) and self.is_private_ip(dst_ip)):
                    return
                
                # Update IP list with new connections
                wx.CallAfter(self.update_ip_list, src_ip)
                wx.CallAfter(self.update_ip_list, dst_ip)
                
                # Get MAC addresses if available
                src_mac = packet.src if hasattr(packet, 'src') else None
                dst_mac = packet.dst if hasattr(packet, 'dst') else None
                
                # Update IP connections
                self.update_ip_connection(src_ip, dst_ip, src_mac, dst_mac)
                
                # Check for suspicious activity
                self.check_ip_reputation(src_ip)
                self.check_ip_reputation(dst_ip)
        
        except Exception as e:
            print(f"Error analyzing packet: {e}")
    
    def is_private_ip(self, ip):
        """Check if an IP is private"""
        try:
            return ip_address(ip).is_private
        except:
            return True
    
    def update_ip_connection(self, src_ip, dst_ip, src_mac, dst_mac):
        """Update IP connection tracking"""
        timestamp = datetime.now()
        
        for ip, mac in [(src_ip, src_mac), (dst_ip, dst_mac)]:
            if not self.is_private_ip(ip):
                if ip not in self.ip_connections:
                    self.ip_connections[ip] = {
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'mac_addresses': set(),
                        'connection_count': 0
                    }
                
                conn = self.ip_connections[ip]
                conn['last_seen'] = timestamp
                conn['connection_count'] += 1
                if mac:
                    conn['mac_addresses'].add(mac)
    
    def check_ip_reputation(self, ip):
        """Check IP reputation using AbuseIPDB and VirusTotal"""
        if ip in self.suspicious_ips or self.is_private_ip(ip):
            return
        
        # Check AbuseIPDB
        if self.abuseipdb_key:
            try:
                url = 'https://api.abuseipdb.com/api/v2/check'
                headers = {
                    'Accept': 'application/json',
                    'Key': self.abuseipdb_key
                }
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90
                }
                
                response = requests.get(url, headers=headers, params=params)
                if response.status_code == 200:
                    data = response.json()
                    if data['data']['abuseConfidenceScore'] > 50:
                        self.suspicious_ips.add(ip)
                        return True
            
            except Exception as e:
                print(f"Error checking AbuseIPDB: {e}")
        
        # Check VirusTotal
        if self.virustotal_key:
            try:
                url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
                params = {
                    'apikey': self.virustotal_key,
                    'ip': ip
                }
                
                response = requests.get(url, params=params)
                if response.status_code == 200:
                    result = response.json()
                    if result.get('detected_urls', []) or result.get('detected_downloaded_samples', []):
                        self.suspicious_ips.add(ip)
                        return True
            
            except Exception as e:
                print(f"Error checking VirusTotal: {e}")
        
        return False
    
    def get_network_status(self):
        """Get current network status"""
        status = {
            'interfaces': self.interfaces,
            'suspicious_ips': list(self.suspicious_ips),
            'connections': self.ip_connections
        }
        return status

class USBScannerFrame(wx.Frame):
    # Theme colors
    colors = {
        'light': {
            'bg': '#ffffff',
            'text': '#000000',
            'accent': '#0078d7',
            'panel': '#f5f5f5',
            'button': '#e0e0e0',
            'button_hover': '#d0d0d0',
            'threat_high': '#FF4D4D',
            'threat_high_bg': '#FFE6E6',
            'threat_moderate': '#FFA64D',
            'threat_moderate_bg': '#FFF2E6',
            'threat_low': '#FFD700',
            'threat_low_bg': '#FFFAE6'
        },
        'dark': {
            'bg': '#1e1e1e',
            'text': '#ffffff',
            'accent': '#0078d7',
            'panel': '#2d2d2d',
            'button': '#3d3d3d',
            'button_hover': '#4d4d4d',
            'threat_high': '#FF6B6B',
            'threat_high_bg': '#4D1F1F',
            'threat_moderate': '#FFB86C',
            'threat_moderate_bg': '#4D3319',
            'threat_low': '#FFE66D',
            'threat_low_bg': '#4D4419'
        }
    }

    def __init__(self):
        try:
            super().__init__(parent=None, title="USB Security Scanner", size=(1200, 800))
            
            # Initialize theme mode
            self.is_dark_mode = False
            
            # Initialize basic properties
            self.config = self.load_config()
            self.api_calls = {}
            self.max_file_size = 32 * 1024 * 1024
            self.rate_limit_delay = 15
            self.available_drives = []
            
            # Create quarantine directory
            self.quarantine_dir = Path("quarantine")
            self.quarantine_dir.mkdir(exist_ok=True)
            
            # Initialize suspicious extensions
            self.suspicious_extensions = {
                '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
                '.jar', '.py', '.scr', '.msi', '.com', '.pif', '.hta'
            }
            
            # Create main panel
            self.main_panel = wx.Panel(self)
            self.main_sizer = wx.BoxSizer(wx.VERTICAL)
            
            # Create top panel for system monitoring
            if SYSTEM_MONITOR_AVAILABLE:
                try:
                    self.system_monitor = SystemMonitorPanel(self.main_panel)
                    self.main_sizer.Add(self.system_monitor, 0, wx.EXPAND | wx.ALL, 5)
                except Exception as e:
                    print(f"Failed to initialize system monitor: {e}")
                    self.system_monitor = None
            
            # Setup UI components
            self.setup_ui()
            
            # Initialize network analyzer
            self.network_analyzer = NetworkAnalyzer(self.config)
            
            # Initialize network monitor
            self.network_monitor = NetworkMonitor(self.quarantine_dir)
            self.network_monitor.start_monitoring()
            
            # Start USB monitoring
            self.start_usb_monitor()
            
            # Set up window close handler
            self.Bind(wx.EVT_CLOSE, self.on_close)
            
            # Center the window
            self.Center()
            
            # Initial refresh of drives
            self.refresh_drives()
            
            # Start IP list refresh timer
            self.ip_timer = wx.Timer(self)
            self.Bind(wx.EVT_TIMER, self.refresh_ip_list, self.ip_timer)
            self.ip_timer.Start(3000)  # Update every 3 seconds
            
            # Initialize action panels dictionary
            self.action_panels = {}
            
        except Exception as e:
            print(f"Error initializing main frame: {e}")
            wx.MessageBox(f"Error initializing application: {str(e)}", "Initialization Error", wx.ICON_ERROR)
            raise
    
    def setup_ui(self):
        """Setup the main UI components"""
        # Create main splitter
        self.main_splitter = wx.SplitterWindow(self.main_panel)
        
        # Create left and right panels
        left_panel = wx.Panel(self.main_splitter)
        right_panel = wx.Panel(self.main_splitter)
        
        left_sizer = wx.BoxSizer(wx.VERTICAL)
        right_sizer = wx.BoxSizer(wx.VERTICAL)
        
        # Add IP Monitoring Bar at the top
        ip_box = wx.StaticBox(self.main_panel, label="IP Monitoring")
        ip_sizer = wx.StaticBoxSizer(ip_box, wx.HORIZONTAL)
        
        # Create IP list control
        self.ip_list = wx.ListCtrl(
            self.main_panel, 
            style=wx.LC_REPORT | wx.LC_SINGLE_SEL | wx.BORDER_SUNKEN
        )
        
        # Add columns to IP list
        self.ip_list.InsertColumn(0, "IP Address", width=150)
        self.ip_list.InsertColumn(1, "Status", width=100)
        self.ip_list.InsertColumn(2, "First Seen", width=150)
        self.ip_list.InsertColumn(3, "Last Seen", width=150)
        self.ip_list.InsertColumn(4, "Connections", width=100)
        self.ip_list.InsertColumn(5, "Risk Level", width=100)
        
        # Create control panel for IP monitoring
        ip_control_panel = wx.Panel(self.main_panel)
        ip_control_sizer = wx.BoxSizer(wx.VERTICAL)
        
        # Add refresh button
        self.ip_refresh_btn = wx.Button(ip_control_panel, label="🔄 Refresh IPs")
        self.ip_refresh_btn.Bind(wx.EVT_BUTTON, self.refresh_ip_list)
        ip_control_sizer.Add(self.ip_refresh_btn, 0, wx.ALL, 5)
        
        # Add clear button
        self.ip_clear_btn = wx.Button(ip_control_panel, label="🗑️ Clear IPs")
        self.ip_clear_btn.Bind(wx.EVT_BUTTON, self.clear_ip_list)
        ip_control_sizer.Add(self.ip_clear_btn, 0, wx.ALL, 5)
        
        ip_control_panel.SetSizer(ip_control_sizer)
        
        # Add components to IP sizer
        ip_sizer.Add(self.ip_list, 1, wx.EXPAND | wx.ALL, 5)
        ip_sizer.Add(ip_control_panel, 0, wx.ALL, 5)
        
        # Add IP monitoring bar to main sizer before the splitter
        self.main_sizer.Add(ip_sizer, 0, wx.EXPAND | wx.ALL, 5)
        
        # Status section (left panel)
        status_box = wx.StaticBox(left_panel, label="Status")
        status_sizer = wx.StaticBoxSizer(status_box, wx.VERTICAL)
        self.status_text = wx.StaticText(left_panel, label="Waiting for USB device...")
        status_sizer.Add(self.status_text, 0, wx.ALL, 5)
        left_sizer.Add(status_sizer, 0, wx.EXPAND | wx.ALL, 5)
        
        # Drive control section (left panel)
        drive_box = wx.StaticBox(left_panel, label="USB Drive Control")
        drive_sizer = wx.StaticBoxSizer(drive_box, wx.HORIZONTAL)
        
        self.drive_combo = wx.Choice(left_panel, choices=[])
        drive_sizer.Add(self.drive_combo, 1, wx.EXPAND | wx.ALL, 5)
        
        self.scan_btn = wx.Button(left_panel, label="🔍 Scan")
        self.scan_btn.Bind(wx.EVT_BUTTON, self.on_scan)
        drive_sizer.Add(self.scan_btn, 0, wx.ALL, 5)
        
        refresh_btn = wx.Button(left_panel, label="🔄 Refresh")
        refresh_btn.Bind(wx.EVT_BUTTON, lambda evt: self.refresh_drives())
        drive_sizer.Add(refresh_btn, 0, wx.ALL, 5)
        
        left_sizer.Add(drive_sizer, 0, wx.EXPAND | wx.ALL, 5)
        
        # Progress section (left panel)
        progress_box = wx.StaticBox(left_panel, label="Scan Progress")
        progress_sizer = wx.StaticBoxSizer(progress_box, wx.VERTICAL)
        self.progress_bar = wx.Gauge(left_panel, range=100)
        progress_sizer.Add(self.progress_bar, 0, wx.EXPAND | wx.ALL, 5)
        left_sizer.Add(progress_sizer, 0, wx.EXPAND | wx.ALL, 5)
        
        # Activity Log section
        activity_box = wx.StaticBox(left_panel, label="Activity Log")
        activity_sizer = wx.StaticBoxSizer(activity_box, wx.VERTICAL)
        
        # Create log control panel
        log_control_panel = wx.Panel(left_panel)
        log_control_sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        # Add clear log button
        self.clear_log_btn = wx.Button(log_control_panel, label="🗑️ Clear")
        self.clear_log_btn.Bind(wx.EVT_BUTTON, self.on_clear_log)
        log_control_sizer.Add(self.clear_log_btn, 0, wx.RIGHT, 5)
        
        # Add save log button
        self.save_log_btn = wx.Button(log_control_panel, label="💾 Save")
        self.save_log_btn.Bind(wx.EVT_BUTTON, self.on_save_log)
        log_control_sizer.Add(self.save_log_btn, 0, wx.RIGHT, 5)
        
        # Add auto-scroll checkbox
        self.auto_scroll = wx.CheckBox(log_control_panel, label="Auto-scroll")
        self.auto_scroll.SetValue(True)
        log_control_sizer.Add(self.auto_scroll, 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 10)
        
        log_control_panel.SetSizer(log_control_sizer)
        activity_sizer.Add(log_control_panel, 0, wx.EXPAND | wx.BOTTOM, 5)
        
        # Create log text control
        self.log_text = wx.TextCtrl(
            left_panel,
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2 | wx.HSCROLL,
            size=(-1, 300)
        )
        activity_sizer.Add(self.log_text, 1, wx.EXPAND | wx.ALL, 5)
        left_sizer.Add(activity_sizer, 1, wx.EXPAND | wx.ALL, 5)
        
        # Threat detection table (right panel)
        threat_box = wx.StaticBox(right_panel, label="Threat Detection")
        threat_sizer = wx.StaticBoxSizer(threat_box, wx.VERTICAL)
        
        # Create grid with custom colors and styling
        self.threat_grid = wx.grid.Grid(right_panel)
        self.threat_grid.CreateGrid(0, 6)
        
        # Configure columns
        columns = [
            ("File Name", 200),
            ("Threat Type", 180),
            ("Danger Level", 120),
            ("Action Required", 200),
            ("Description", 300),
            ("Actions", 100)
        ]
        
        # Set up grid appearance
        self.threat_grid.SetDefaultRowSize(35)
        self.threat_grid.SetDefaultCellAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTER)
        self.threat_grid.SetRowLabelSize(40)
        
        # Configure column headers
        header_font = wx.Font(9, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
        self.threat_grid.SetLabelFont(header_font)
        
        # Set up columns
        for idx, (name, width) in enumerate(columns):
            self.threat_grid.SetColLabelValue(idx, name)
            self.threat_grid.SetColSize(idx, width)
            
            # Set column-specific alignments
            align = wx.ALIGN_LEFT
            if name in ["Danger Level", "Actions"]:
                align = wx.ALIGN_CENTER
            self.threat_grid.SetColLabelAlignment(align, wx.ALIGN_CENTER)
            
            # Make column read-only
            attr = wx.grid.GridCellAttr()
            attr.SetReadOnly(True)
            self.threat_grid.SetColAttr(idx, attr)
        
        # Add grid to threat sizer
        threat_sizer.Add(self.threat_grid, 1, wx.EXPAND | wx.ALL, 5)
        right_sizer.Add(threat_sizer, 1, wx.EXPAND | wx.ALL, 5)
        
        # Set panel sizers
        left_panel.SetSizer(left_sizer)
        right_panel.SetSizer(right_sizer)
        
        # Split window
        self.main_splitter.SplitVertically(left_panel, right_panel)
        self.main_splitter.SetMinimumPaneSize(300)
        self.main_splitter.SetSashPosition(400)
        
        # Add splitter to main sizer
        self.main_sizer.Add(self.main_splitter, 1, wx.EXPAND)
        self.main_panel.SetSizer(self.main_sizer)
        
        # Initial UI state
        self.scan_btn.Disable()
    
    def on_scan(self, event):
        """Handle scan button click"""
        if self.drive_combo.GetSelection() == -1:
            wx.MessageBox("Please select a drive to scan", "Warning", wx.ICON_WARNING)
            return
        
        selected_drive = self.drive_combo.GetString(self.drive_combo.GetSelection())
        self.scan_btn.Disable()
        self.status_text.SetLabel(f"Scanning {selected_drive}...")
        self.progress_bar.SetValue(0)
        
        # Start scan in a separate thread
        thread = threading.Thread(target=self.scan_directory, args=(selected_drive,))
        thread.daemon = True
        thread.start()
    
    def on_close(self, event):
        """Handle window close"""
        # Stop system monitoring if available
        if SYSTEM_MONITOR_AVAILABLE and hasattr(self, 'system_monitor') and self.system_monitor:
            try:
                self.system_monitor.stop_monitoring()
            except:
                pass
        
        # Stop network monitoring
        if hasattr(self, 'network_monitor'):
            self.network_monitor.stop_monitoring()
        
        # Stop IP refresh timer
        if hasattr(self, 'ip_timer'):
            self.ip_timer.Stop()
        
        self.Destroy()

    def load_config(self):
        config = configparser.ConfigParser()
        config_file = Path('config.ini')
        
        if not config_file.exists():
            # Create default config
            config['VirusTotal'] = {
                'api_key': 'YOUR_API_KEY_HERE',
                'max_file_size_mb': '32',
                'rate_limit_delay': '15'
            }
            with open(config_file, 'w') as f:
                config.write(f)
            wx.MessageBox("Please edit config.ini and add your VirusTotal API key", "Configuration Required", wx.ICON_WARNING)
            sys.exit(1)
            
        config.read(config_file)
        return config
    
    def check_rate_limit(self):
        """Check if we're within rate limits for VirusTotal API"""
        now = datetime.now()
        if len(self.api_calls) > 0:
            oldest_call = min(self.api_calls.values())
            if (now - oldest_call).seconds < self.rate_limit_delay:
                return False
        return True
    
    def update_rate_limit(self, resource):
        """Update rate limit tracking"""
        now = datetime.now()
        self.api_calls[resource] = now
        # Clean up old entries
        for key in list(self.api_calls.keys()):
            if (now - self.api_calls[key]).seconds > self.rate_limit_delay:
                del self.api_calls[key]
    
    def on_closing(self):
        # Stop network monitoring before closing
        self.network_monitor.stop_monitoring()
        self.Destroy()
    
    def setup_styles(self):
        """Configure custom styles with modern design"""
        # Create custom fonts
        self.header_font = ('Helvetica', 12, 'bold')
        self.text_font = ('Helvetica', 9)
        
        # Get system settings
        style = wx.SystemSettings()
        
        # Configure label styles
        style_font = wx.Font(16, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
        
        # Configure colors and styles
        bg_color = self.colors['light']['bg']
        fg_color = self.colors['light']['fg']
        
        # Apply base colors
        self.SetBackgroundColour(bg_color)
        self.SetForegroundColour(fg_color)
        
        # Configure label styles
        style.SetFont(style_font)
        
        # Configure frame styles
        style.SetBackgroundColour(self.colors['light']['frame_bg'])
        
        # Configure button styles
        style.SetBackgroundColour(self.colors['light']['button_bg'])
        style.SetForegroundColour(self.colors['light']['button_fg'])
        
        # Configure Toggle button style
        style.SetBackgroundColour(self.colors['light']['toggle_bg'])
        style.SetForegroundColour(self.colors['light']['toggle_fg'])
        
        # Configure Treeview styles
        style.SetBackgroundColour(self.colors['light']['treeview_bg'])
        style.SetForegroundColour(self.colors['light']['treeview_fg'])
        
        # Configure Progressbar
        style.SetBackgroundColour(self.colors['light']['progress_bg'])
        style.SetForegroundColour(self.colors['light']['progress_fg'])
        
        # Configure Combobox with improved dropdown styling
        style.SetBackgroundColour(self.colors['light']['button_bg'])
        style.SetForegroundColour(self.colors['light']['button_fg'])
        
        # Update text widgets with improved text selection
        for widget in self.get_all_text_controls():
            style.SetBackgroundColour(self.colors['light']['text_bg'])
            style.SetForegroundColour(self.colors['light']['text_fg'])
        
        # Update status label with improved visibility
        style.SetBackgroundColour(self.colors['light']['label_bg'])
        style.SetForegroundColour(self.colors['light']['label_fg'])
        
        # Configure Scrollbar with improved grip
        style.SetBackgroundColour(self.colors['light']['scrollbar_bg'])
        style.SetForegroundColour(self.colors['light']['scrollbar_fg'])
        
        # Update threat level colors and styling
        self.threat_levels = {
            'HIGH': {
                'min_detections': 5,
                'color': self.colors['light']['threat_high'],
                'bg': self.colors['light']['threat_high_bg']
            },
            'MODERATE': {
                'min_detections': 2,
                'color': self.colors['light']['threat_moderate'],
                'bg': self.colors['light']['threat_moderate_bg']
            },
            'LOW': {
                'min_detections': 1,
                'color': self.colors['light']['threat_low'],
                'bg': self.colors['light']['threat_low_bg']
            }
        }
        
        # Update threat table tags with improved visibility
        for level, config in self.threat_levels.items():
            style.SetBackgroundColour(config['bg'])
            style.SetForegroundColour(config['color'])
        
        # Configure Action button style
        style.SetBackgroundColour(self.colors['light']['button_bg'])
        style.SetForegroundColour(self.colors['light']['button_fg'])
        
        # Update all frames with consistent styling
        for widget in [self.container] + self.container.GetChildren():
            if isinstance(widget, wx.Panel):
                style.SetBackgroundColour(self.colors['light']['frame_bg'])
            elif isinstance(widget, wx.StaticText):
                style.SetForegroundColour(self.colors['light']['fg'])

    def refresh_threat_levels(self):
        """Refresh and recalculate threat levels for all items"""
        # Store current items
        items = []
        for item in self.threat_grid.GetNumberRows():
            values = [self.threat_grid.GetCellValue(item, col) for col in range(self.threat_grid.GetNumberCols())]
            items.append(values)
        
        # Clear the table
        for item in self.threat_grid.GetNumberRows():
            self.threat_grid.DeleteRows(item)
        
        # Reinsert items with updated threat levels
        for values in items:
            if values:
                filename, threat_type = values[0], values[1]
                detections, total = map(int, values[3].split('/'))
                
                # Recalculate threat level
                level = self.determine_threat_level(detections, total)
                if level:
                    action = self.get_recommended_action(level)
                    
                    # Insert with updated level and action
                    self.threat_grid.AppendRows(1)
                    self.threat_grid.SetCellValue(self.threat_grid.GetNumberRows() - 1, 0, filename)
                    self.threat_grid.SetCellValue(self.threat_grid.GetNumberRows() - 1, 1, threat_type)
                    self.threat_grid.SetCellValue(self.threat_grid.GetNumberRows() - 1, 2, level)
                    self.threat_grid.SetCellValue(self.threat_grid.GetNumberRows() - 1, 3, f"{detections}/{total}")
                    self.threat_grid.SetCellValue(self.threat_grid.GetNumberRows() - 1, 4, action)
                    
                    # Log the update
                    self.log(f"Updated threat level for {filename}: {level}")
        
        # Update the threat description if an item is selected
        selection = self.threat_grid.GetSelectedRows()
        if selection:
            self.show_threat_details(None)
        
        # Show confirmation message
        self.status_text.SetLabel("Threat levels refreshed")

    def add_threat_to_grid(self, file_name, threat_type, threat_level, detections, total, major_detections=None):
        """Add a threat to the grid with enhanced visual feedback"""
        try:
            row = self.threat_grid.GetNumberRows()
            self.threat_grid.AppendRows(1)
            
            # Add threat information
            self.threat_grid.SetCellValue(row, 0, file_name)
            self.threat_grid.SetCellValue(row, 1, threat_type)
            self.threat_grid.SetCellValue(row, 2, threat_level)
            self.threat_grid.SetCellValue(row, 3, f"{detections}/{total}")
            
            # Set recommended action based on threat level
            actions = {
                'HIGH': "Immediate Quarantine Required",
                'MODERATE': "Investigation Recommended",
                'LOW': "Monitor and Scan Regularly"
            }
            self.threat_grid.SetCellValue(row, 4, actions.get(threat_level, "Unknown"))
            
            # Create detailed description
            description = f"Detection Rate: {detections}/{total}\n"
            if major_detections:
                description += "Major Detections:\n" + "\n".join(major_detections)
            
            # Add buttons column
            button_panel = wx.Panel(self.threat_grid)
            button_sizer = wx.BoxSizer(wx.HORIZONTAL)
            
            # Create quarantine button
            quarantine_btn = wx.Button(button_panel, label="⚠️ Quarantine", size=(90, 25))
            quarantine_btn.Bind(wx.EVT_BUTTON, lambda evt, fn=file_name: self.quarantine_file(fn))
            button_sizer.Add(quarantine_btn, 0, wx.RIGHT, 5)
            
            # Create remove button
            remove_btn = wx.Button(button_panel, label="🗑️ Remove", size=(80, 25))
            remove_btn.Bind(wx.EVT_BUTTON, lambda evt, fn=file_name: self.remove_file(fn))
            button_sizer.Add(remove_btn, 0)
            
            button_panel.SetSizer(button_sizer)
            
            # Set colors based on threat level
            colors = {
                'HIGH': (wx.Colour(255, 200, 200), wx.Colour(139, 0, 0)),    # Light red bg, Dark red text
                'MODERATE': (wx.Colour(255, 229, 204), wx.Colour(204, 85, 0)), # Light orange bg, Dark orange text
                'LOW': (wx.Colour(255, 255, 204), wx.Colour(184, 134, 11))    # Light yellow bg, Dark yellow text
            }
            
            bg_color, text_color = colors.get(threat_level, (wx.WHITE, wx.BLACK))
            
            # Apply colors to all cells in the row
            for col in range(self.threat_grid.GetNumberCols()):
                self.threat_grid.SetCellBackgroundColour(row, col, bg_color)
                self.threat_grid.SetCellTextColour(row, col, text_color)
            
            # Store the button panel reference
            self.threat_grid.SetCellValue(row, 5, "")  # Clear any existing value
            self.action_panels[row] = button_panel
            
            # Adjust row height to accommodate buttons
            self.threat_grid.SetRowSize(row, 35)
            
            # Force refresh of the grid
            self.threat_grid.ForceRefresh()
            
            # Log the threat detection
            self.log(f"\n⚠️ New {threat_level} Risk Threat Detected!")
            self.log(f"File: {file_name}")
            self.log(f"Type: {threat_type}")
            self.log(f"Detection Rate: {detections}/{total}")
            if major_detections:
                self.log("Major Detections:")
                for detection in major_detections:
                    self.log(f"- {detection}")
            
        except Exception as e:
            self.log(f"❌ Error adding threat to grid: {str(e)}", "Error")

    def determine_threat_level(self, detections, total, scan_results=None):
        """Determine threat level based on detection ratio and major vendor results"""
        try:
            # Calculate detection ratio
            ratio = detections / total if total > 0 else 0
            
            # Check major vendor detections if available
            major_vendor_detections = 0
            if scan_results:
                major_vendors = ['Microsoft', 'Kaspersky', 'Symantec', 'McAfee', 'Bitdefender', 'ESET-NOD32']
                for vendor in major_vendors:
                    if vendor in scan_results and scan_results[vendor].get('detected'):
                        major_vendor_detections += 1
            
            # Determine threat level
            if major_vendor_detections >= 2 or ratio >= 0.5:
                return 'HIGH'
            elif major_vendor_detections >= 1 or ratio >= 0.3:
                return 'MODERATE'
            elif detections > 0:
                return 'LOW'
            
            return None
            
        except Exception as e:
            self.log(f"❌ Error determining threat level: {str(e)}", "Error")
            return None

    def process_scan_results(self, file_name, result):
        """Process VirusTotal scan results with improved threat detection"""
        try:
            positives = result.get('positives', 0)
            total = result.get('total', 0)
            scans = result.get('scans', {})
            
            self.log(f"✅ Analysis complete: {positives}/{total} detections")
            
            if positives > 0:
                # Check major vendors
                major_vendors = ['Microsoft', 'Kaspersky', 'Symantec', 'McAfee', 'Bitdefender', 'ESET-NOD32']
                major_detections = []
                threat_types = set()
                
                for vendor in major_vendors:
                    if vendor in scans and scans[vendor].get('detected'):
                        result_text = scans[vendor].get('result', 'Unknown')
                        major_detections.append(f"{vendor}: {result_text}")
                        threat_types.add(result_text)
                
                # Determine threat level
                threat_level = self.determine_threat_level(positives, total, scans)
                if not threat_level:
                    return
                
                # Get most specific threat type
                threat_type = max(threat_types, key=len) if threat_types else "Unknown Threat"
                
                # Add to threat grid
                wx.CallAfter(self.add_threat_to_grid, file_name, threat_type, threat_level, 
                           positives, total, major_detections)
                
                self.log(f"⚠️ Added {threat_level} risk threat to table", "Warning")
            else:
                self.log("✅ No threats detected")
            
        except Exception as e:
            self.log(f"❌ Error processing scan results: {str(e)}", "Error")

    def refresh_drives(self):
        """Refresh the list of available USB drives with enhanced detection"""
        try:
            previous_selection = self.drive_combo.GetString(self.drive_combo.GetSelection()) if self.drive_combo.GetSelection() != -1 else None
            
            # Get all removable drives using win32file
            self.available_drives = [
                f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                if win32file.GetDriveType(f"{d}:\\") == win32con.DRIVE_REMOVABLE
            ]
            
            if self.available_drives:
                self.drive_combo.SetItems(self.available_drives)
                
                # Try to maintain previous selection if it still exists
                if previous_selection and previous_selection in self.available_drives:
                    self.drive_combo.SetStringSelection(previous_selection)
                else:
                    self.drive_combo.SetSelection(0)
                
                self.scan_btn.Enable()
                self.status_text.SetLabel("Select a drive and click Scan")
                
                # Log available drives
                self.log("\n📁 Available USB Drives:")
                for drive in self.available_drives:
                    try:
                        volume_info = win32file.GetVolumeInformation(drive)
                        volume_name = volume_info[0] if volume_info[0] else "Unnamed Device"
                        self.log(f"- {drive} ({volume_name})")
                    except:
                        self.log(f"- {drive} (Unable to read label)")
            else:
                self.drive_combo.SetItems([])
                self.scan_btn.Disable()
                self.status_text.SetLabel("No USB drives detected")
                self.log("\n❌ No USB drives currently connected")
            
        except Exception as e:
            self.log(f"❌ Error refreshing drives: {str(e)}")
            self.drive_combo.SetItems([])
            self.scan_btn.Disable()
            self.status_text.SetLabel("Error detecting USB drives")

    def start_usb_monitor(self):
        """Start monitoring for USB device changes"""
        self.previous_drives = set()
        
        def monitor_usb():
            while True:
                try:
                    current_drives = set(
                        f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        if win32file.GetDriveType(f"{d}:\\") == win32con.DRIVE_REMOVABLE
                    )
                    
                    # Check for new drives
                    new_drives = current_drives - self.previous_drives
                    for drive in new_drives:
                        wx.CallAfter(self.log, f"\n🔌 USB Device Connected: {drive}")
                        try:
                            volume_info = win32file.GetVolumeInformation(drive)
                            wx.CallAfter(self.log, f"Device Name: {volume_info[0] if volume_info[0] else 'Unnamed Device'}")
                            wx.CallAfter(self.log, f"Serial Number: {volume_info[1]:X}")
                        except Exception as e:
                            wx.CallAfter(self.log, f"Error getting device info: {str(e)}")
                    
                    # Check for removed drives
                    removed_drives = self.previous_drives - current_drives
                    for drive in removed_drives:
                        wx.CallAfter(self.log, f"\n❌ USB Device Disconnected: {drive}")
                    
                    self.previous_drives = current_drives
                    wx.CallAfter(self.refresh_drives)
                except Exception as e:
                    wx.CallAfter(self.log, f"Error monitoring USB devices: {str(e)}")
                time.sleep(2)
        
        thread = threading.Thread(target=monitor_usb, daemon=True)
        thread.start()
        self.log("USB monitoring started")

    def log(self, message, level="Info"):
        """Log a message with improved formatting and thread safety"""
        try:
            if not hasattr(self, 'log_text'):
                return
                
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            
            # Format based on message type and level
            if "❌" in message or level == "Error":
                color = wx.Colour(255, 0, 0)  # Red
                font = wx.Font(9, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
                prefix = "❌ ERROR: "
            elif "⚠️" in message or level == "Warning":
                color = wx.Colour(255, 140, 0)  # Orange
                font = wx.Font(9, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
                prefix = "⚠️ WARNING: "
            elif any(x in message for x in ["✅", "🔍", "📄"]):
                color = wx.Colour(0, 128, 0)  # Green
                font = wx.Font(9, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
                prefix = "✅ SUCCESS: "
            else:
                color = wx.Colour(0, 0, 0)  # Black for regular messages
                font = wx.Font(9, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
                prefix = "ℹ️ INFO: "
            
            # Format message
            if not message.startswith('\n'):
                formatted_message = f"[{timestamp}] {prefix}{message}\n"
            else:
                formatted_message = f"\n[{timestamp}] {prefix}{message.lstrip()}\n"
            
            def update_log():
                try:
                    # Create text attributes
                    attr = wx.TextAttr()
                    attr.SetTextColour(color)
                    attr.SetFont(font)
                    
                    # Store current position
                    start_pos = self.log_text.GetLastPosition()
                    
                    # Append text
                    self.log_text.AppendText(formatted_message)
                    
                    # Apply style to the appended text
                    end_pos = self.log_text.GetLastPosition()
                    self.log_text.SetStyle(start_pos, end_pos, attr)
                    
                    # Auto-scroll if enabled
                    if self.auto_scroll.GetValue():
                        self.log_text.ShowPosition(end_pos)
                    
                    # Limit log size (keep last 1000 lines)
                    if self.log_text.GetNumberOfLines() > 1000:
                        # Find position of 100th line from end
                        pos = 0
                        for i in range(100):
                            pos = self.log_text.GetLineLength(i) + 1 + pos
                        self.log_text.Remove(0, pos)
                    
                except Exception as e:
                    print(f"Error updating log: {str(e)}")
            
            # Ensure thread-safe update
            if wx.IsMainThread():
                update_log()
            else:
                wx.CallAfter(update_log)
            
        except Exception as e:
            print(f"Error logging message: {str(e)}")

    def on_clear_log(self, event):
        """Clear the activity log with confirmation"""
        if wx.MessageBox("Are you sure you want to clear the activity log?", 
                        "Confirm Clear", 
                        wx.YES_NO | wx.NO_DEFAULT | wx.ICON_QUESTION) == wx.YES:
            self.log_text.Clear()
            self.log("Activity log cleared", "Info")

    def on_save_log(self, event):
        """Save the activity log to a file"""
        with wx.FileDialog(self, "Save Log File", wildcard="Log files (*.log)|*.log",
                          style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return
            
            pathname = fileDialog.GetPath()
            try:
                with open(pathname, 'w', encoding='utf-8') as file:
                    file.write(self.log_text.GetValue())
                self.log(f"✅ Log saved to: {pathname}")
            except IOError as e:
                self.log(f"❌ Cannot save log to file '{pathname}': {str(e)}", "Error")
                wx.LogError(f"Cannot save log to file '{pathname}'")

    def scan_directory(self, directory):
        """Scan a directory for threats"""
        try:
            total_files = sum([len(files) for _, _, files in os.walk(directory)])
            scanned_files = 0
            
            self.log(f"\n🔍 Starting scan of {directory}")
            self.log(f"📁 Total files to scan: {total_files}")
            
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        relative_path = os.path.relpath(file_path, directory)
                        self.log(f"\n📄 Scanning: {relative_path}")
                        
                        # Get file size
                        file_size = os.path.getsize(file_path)
                        self.log(f"Size: {self.format_size(file_size)}")
                        
                        # Check if file is too large
                        if file_size > self.max_file_size:
                            self.log(f"⚠️ File too large to scan: {self.format_size(file_size)} > {self.format_size(self.max_file_size)}", "Warning")
                            continue
                        
                        # Scan the file
                        self.scan_file(file_path)
                        scanned_files += 1
                        
                        # Update progress
                        progress = (scanned_files / total_files) * 100 if total_files > 0 else 0
                        wx.CallAfter(self.progress_bar.SetValue, int(progress))
                        wx.CallAfter(self.status_text.SetLabel, f"Scanning: {scanned_files}/{total_files} files")
                        
                    except Exception as e:
                        self.log(f"❌ Error scanning {file_path}: {str(e)}", "Error")
            
            wx.CallAfter(self.status_text.SetLabel, f"✅ Scan completed. Scanned {scanned_files} files.")
            wx.CallAfter(self.scan_btn.Enable)
            self.log(f"\n✅ Scan completed")
            self.log(f"📊 Total files scanned: {scanned_files}")
            
        except Exception as e:
            wx.CallAfter(self.log, f"❌ Error scanning directory: {str(e)}", "Error")
            wx.CallAfter(self.status_text.SetLabel, "Scan failed")
            wx.CallAfter(self.scan_btn.Enable)

    def format_size(self, size):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def scan_file(self, file_path):
        """Scan a file using VirusTotal API"""
        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Calculate file hash
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            
            self.log(f"SHA256: {file_hash}")
            
            # Check VirusTotal API key
            api_key = self.config['VirusTotal']['api_key']
            if not api_key or api_key == 'YOUR_API_KEY_HERE':
                self.log("❌ VirusTotal API key not configured", "Error")
                return
            
            # Check rate limiting
            if not self.check_rate_limit():
                self.log(f"⚠️ Rate limit reached, waiting {self.rate_limit_delay} seconds...", "Warning")
                time.sleep(self.rate_limit_delay)
            
            # First, check if the file hash exists in VirusTotal
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {
                'apikey': api_key,
                'resource': file_hash
            }
            
            self.log("🔍 Checking VirusTotal database...")
            response = requests.get(url, params=params)
            
            if response.status_code == 200:
                result = response.json()
                
                if result['response_code'] == 1:
                    # File exists in database
                    self.update_rate_limit(file_hash)
                    self.process_scan_results(file_name, result)
                    return
                
            elif response.status_code == 204:
                self.log("⚠️ VirusTotal API rate limit exceeded", "Warning")
                time.sleep(self.rate_limit_delay)
                return
            
            # If file not found, upload it
            if file_size <= self.max_file_size:
                self.log("📤 File not found in database, uploading...")
                
                url = 'https://www.virustotal.com/vtapi/v2/file/scan'
                files = {'file': (file_name, open(file_path, 'rb'))}
                params = {'apikey': api_key}
                
                response = requests.post(url, files=files, params=params)
                
                if response.status_code == 200:
                    result = response.json()
                    if result['response_code'] == 1:
                        scan_id = result['scan_id']
                        self.update_rate_limit(scan_id)
                        
                        # Wait for analysis to complete
                        self.log("⏳ Waiting for analysis...")
                        time.sleep(self.rate_limit_delay)
                        
                        # Get the scan results
                        url = 'https://www.virustotal.com/vtapi/v2/file/report'
                        params = {
                            'apikey': api_key,
                            'resource': scan_id
                        }
                        
                        response = requests.get(url, params=params)
                        if response.status_code == 200:
                            result = response.json()
                            if result['response_code'] == 1:
                                self.process_scan_results(file_name, result)
                
                elif response.status_code == 204:
                    self.log("⚠️ VirusTotal API rate limit exceeded", "Warning")
                    time.sleep(self.rate_limit_delay)
            
        except Exception as e:
            self.log(f"❌ Error scanning file: {str(e)}", "Error")

    def update_network_info(self, event=None):
        """Update network information display"""
        try:
            network_info = []
            # Get network interfaces and their addresses using psutil
            for interface, addresses in psutil.net_if_addrs().items():
                for addr in addresses:
                    if addr.family == socket.AF_INET:  # IPv4 addresses
                        network_info.append(f"Interface: {interface}")
                        network_info.append(f"IP Address: {addr.address}")
                        network_info.append(f"Netmask: {addr.netmask}")
                        network_info.append("")
            
            # Get network connections
            connections = psutil.net_connections(kind='inet')
            suspicious_ips = []
            for conn in connections:
                if conn.raddr:  # If there's a remote address
                    ip = conn.raddr.ip
                    if any(ip.startswith(prefix) for prefix in ['192.168.', '10.', '172.']):
                        continue  # Skip local network IPs
                    suspicious_ips.append(f"⚠️ Suspicious connection: {ip}:{conn.raddr.port}")
            
            # Update the network info text
            info_text = "\n".join(network_info)
            if suspicious_ips:
                info_text += "\nSuspicious Connections:\n" + "\n".join(suspicious_ips)
            
            wx.CallAfter(self.network_text.SetValue, info_text)
            self.log_activity("Network information updated successfully", "success")
        except Exception as e:
            wx.CallAfter(self.network_text.SetValue, f"Error updating network information: {str(e)}")
            self.log_activity(f"Failed to update network information: {str(e)}", "error")

    def add_network_threat(self, threat_info):
        """Add network threat to the grid"""
        try:
            # Check if threat already exists
            for row in range(self.threat_grid.GetNumberRows()):
                if (self.threat_grid.GetCellValue(row, 0) == threat_info['name'] and
                    self.threat_grid.GetCellValue(row, 1) == threat_info['type']):
                    return
            
            row = self.threat_grid.GetNumberRows()
            self.threat_grid.AppendRows(1)
            
            self.threat_grid.SetCellValue(row, 0, threat_info['name'])
            self.threat_grid.SetCellValue(row, 1, threat_info['type'])
            self.threat_grid.SetCellValue(row, 2, threat_info['level'])
            self.threat_grid.SetCellValue(row, 3, "Block IP")
            self.threat_grid.SetCellValue(row, 4, threat_info['details'])
            
            # Set colors based on threat level
            colors = {
                'HIGH': (wx.Colour(255, 200, 200), wx.Colour(139, 0, 0)),
                'MODERATE': (wx.Colour(255, 229, 204), wx.Colour(204, 85, 0))
            }
            
            bg_color, text_color = colors.get(threat_info['level'], (wx.WHITE, wx.BLACK))
            
            for col in range(5):
                self.threat_grid.SetCellBackgroundColour(row, col, bg_color)
                self.threat_grid.SetCellTextColour(row, col, text_color)
            
            self.threat_grid.AutoSizeRow(row, setAsMin=True)
            self.threat_grid.ForceRefresh()
            
        except Exception as e:
            self.log(f"Error adding network threat: {str(e)}", "Error")

    def refresh_ip_list(self, event=None):
        """Refresh the IP monitoring list"""
        try:
            self.ip_list.DeleteAllItems()
            
            # Get current network connections
            connections = psutil.net_connections(kind='inet')
            ip_data = {}
            
            # Process connections
            for conn in connections:
                if conn.raddr:  # If there's a remote address
                    ip = conn.raddr.ip
                    if any(ip.startswith(prefix) for prefix in ['192.168.', '10.', '172.']):
                        continue  # Skip local network IPs
                    
                    if ip not in ip_data:
                        ip_data[ip] = {
                            'first_seen': datetime.now(),
                            'last_seen': datetime.now(),
                            'connections': 1,
                            'status': 'Active'
                        }
                    else:
                        ip_data[ip]['last_seen'] = datetime.now()
                        ip_data[ip]['connections'] += 1
            
            # Add IPs to list
            for ip, data in ip_data.items():
                index = self.ip_list.GetItemCount()
                self.ip_list.InsertItem(index, ip)
                self.ip_list.SetItem(index, 1, data['status'])
                self.ip_list.SetItem(index, 2, data['first_seen'].strftime('%Y-%m-%d %H:%M:%S'))
                self.ip_list.SetItem(index, 3, data['last_seen'].strftime('%Y-%m-%d %H:%M:%S'))
                self.ip_list.SetItem(index, 4, str(data['connections']))
                
                # Determine risk level based on connections
                risk_level = 'Low'
                if data['connections'] > 100:
                    risk_level = 'High'
                    self.ip_list.SetItemBackgroundColour(index, wx.Colour(255, 200, 200))
                elif data['connections'] > 50:
                    risk_level = 'Medium'
                    self.ip_list.SetItemBackgroundColour(index, wx.Colour(255, 229, 204))
                
                self.ip_list.SetItem(index, 5, risk_level)
            
            self.log("✅ IP list refreshed")
            
        except Exception as e:
            self.log(f"❌ Error refreshing IP list: {str(e)}", "Error")

    def clear_ip_list(self, event):
        """Clear the IP monitoring list"""
        if wx.MessageBox("Are you sure you want to clear the IP list?",
                        "Confirm Clear",
                        wx.YES_NO | wx.NO_DEFAULT | wx.ICON_QUESTION) == wx.YES:
            self.ip_list.DeleteAllItems()
            self.log("IP list cleared")

    def update_ip_list(self, ip, status="Active"):
        """Update or add an IP to the monitoring list"""
        try:
            # Search for existing IP
            for i in range(self.ip_list.GetItemCount()):
                if self.ip_list.GetItem(i, 0).GetText() == ip:
                    # Update existing entry
                    self.ip_list.SetItem(i, 1, status)
                    self.ip_list.SetItem(i, 3, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    connections = int(self.ip_list.GetItem(i, 4).GetText()) + 1
                    self.ip_list.SetItem(i, 4, str(connections))
                    
                    # Update risk level
                    risk_level = 'Low'
                    if connections > 100:
                        risk_level = 'High'
                        self.ip_list.SetItemBackgroundColour(i, wx.Colour(255, 200, 200))
                    elif connections > 50:
                        risk_level = 'Medium'
                        self.ip_list.SetItemBackgroundColour(i, wx.Colour(255, 229, 204))
                    
                    self.ip_list.SetItem(i, 5, risk_level)
                    return
            
            # Add new IP if not found
            index = self.ip_list.GetItemCount()
            self.ip_list.InsertItem(index, ip)
            self.ip_list.SetItem(index, 1, status)
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.ip_list.SetItem(index, 2, now)
            self.ip_list.SetItem(index, 3, now)
            self.ip_list.SetItem(index, 4, "1")
            self.ip_list.SetItem(index, 5, "Low")
            
        except Exception as e:
            self.log(f"❌ Error updating IP list: {str(e)}", "Error")

    def log_activity(self, message, level="info"):
        """Wrapper for logging activity with proper level"""
        level_map = {
            "error": "Error",
            "warning": "Warning",
            "success": "Info",
            "info": "Info"
        }
        self.log(message, level_map.get(level.lower(), "Info"))

class USBScannerApp(wx.App):
    def OnInit(self):
        frame = USBScannerFrame()
        frame.Show()
        return True

if __name__ == "__main__":
    try:
        app = USBScannerApp()
        app.MainLoop()
    except Exception as e:
        print(f"Application error: {str(e)}")
        wx.MessageBox(f"Application error: {str(e)}", "Error", wx.ICON_ERROR)
        sys.exit(1)
