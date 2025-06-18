import socket
import struct
import threading
import time
from datetime import datetime
import psutil
import logging
import os
import json
from collections import defaultdict

class NetworkMonitor:
    def __init__(self, quarantine_dir):
        self.quarantine_dir = quarantine_dir
        self.suspicious_ips = set()
        self.log_file = "network_monitor.log"
        self.setup_logging()
        self.running = False
        self.connection_counts = defaultdict(int)
        self.data_transfer = defaultdict(int)
        self.known_malicious_ports = {
            4444,  # Metasploit
            666,   # Common backdoor
            31337, # Elite speak
            1080,  # SOCKS proxy
            6666,  # IRC
            8080,  # Alternative HTTP
            9001   # Tor
        }
        
    def setup_logging(self):
        try:
            logging.basicConfig(
                filename=self.log_file,
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
        except Exception as e:
            print(f"Error setting up logging: {str(e)}")
            
    def check_connection(self, connection):
        """Check if a connection is suspicious"""
        try:
            if connection.status == 'ESTABLISHED':
                if connection.raddr and connection.raddr.port:
                    # Check for suspicious ports
                    if connection.raddr.port in self.known_malicious_ports:
                        return True
                    
                    # Check for unusual connection patterns
                    ip = connection.raddr.ip
                    self.connection_counts[ip] += 1
                    if self.connection_counts[ip] > 100:  # Threshold for suspicious activity
                        return True
                        
            return False
        except Exception as e:
            logging.error(f"Error checking connection: {str(e)}")
            return False
            
    def monitor_connections(self):
        """Monitor network connections"""
        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if self.check_connection(conn):
                        if conn.raddr:
                            self.suspicious_ips.add(conn.raddr.ip)
                            try:
                                process = psutil.Process(conn.pid)
                                logging.warning(
                                    f"Suspicious connection detected: "
                                    f"Process {process.name()} (PID: {conn.pid}) "
                                    f"connecting to {conn.raddr.ip}:{conn.raddr.port}"
                                )
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                
                # Monitor network interface statistics
                net_io = psutil.net_io_counters(pernic=True)
                for nic, stats in net_io.items():
                    if stats.bytes_sent > 1000000:  # Monitor large data transfers (1MB)
                        logging.warning(f"Large data transfer detected on interface {nic}")
                        
            except Exception as e:
                logging.error(f"Error monitoring connections: {str(e)}")
                
            time.sleep(1)  # Check every second
            
    def start_monitoring(self):
        """Start network monitoring"""
        try:
            self.running = True
            thread = threading.Thread(target=self.monitor_connections, daemon=True)
            thread.start()
            logging.info("Network monitoring started")
        except Exception as e:
            logging.error(f"Error starting network monitor: {str(e)}")
            
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        logging.info("Network monitoring stopped")
        
    def get_suspicious_ips(self):
        """Get list of suspicious IPs"""
        return list(self.suspicious_ips)
        
    def get_network_logs(self):
        """Get network monitoring logs"""
        try:
            with open(self.log_file, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return "No logs available yet"
        except Exception as e:
            logging.error(f"Error reading logs: {str(e)}")
            return f"Error reading logs: {str(e)}" 