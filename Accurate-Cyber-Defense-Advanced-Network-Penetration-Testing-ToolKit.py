#!/usr/bin/env python3
"""
Accurate Cyber Defense Cybersecurity Monitoring Tool with Telegram Integration
Green Theme - Multi-functional Security Platform
"""

import os
import sys
import time
import threading
import socket
import subprocess
import json
import requests
import ipaddress
import ping3
import scapy.all as scapy
import dns.resolver
import geoip2.database
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler
import sqlite3
import readline
import concurrent.futures
from typing import Dict, List, Tuple, Optional, Any
import argparse
import tempfile
import hashlib
import ssl
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
import signal
import psutil
import netifaces
import random
import string

# Third-party imports (install with pip)
try:
    import telegram
    from telegram import Update
    from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
    from telegram.error import TelegramError
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    print("python-telegram-bot not installed. Install with: pip install python-telegram-bot")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("python-whois not installed. Install with: pip install python-whois")

# Configuration
class Config:
    """Configuration management class"""
    def __init__(self):
        self.config_file = "cyber_tool_config.json"
        self.default_config = {
            "telegram": {
                "token": "",
                "chat_id": "",
                "enabled": False
            },
            "monitoring": {
                "interval": 60,
                "max_targets": 10,
                "alert_threshold": 80
            },
            "scanning": {
                "default_ports": "1-1000",
                "timeout": 2,
                "threads": 50
            },
            "theme": {
                "primary_color": "\033[92m",
                "secondary_color": "\033[94m",
                "warning_color": "\033[93m",
                "error_color": "\033[91m",
                "reset_color": "\033[0m"
            },
            "database": "cyber_tool.db",
            "log_file": "cyber_tool.log",
            "max_history": 1000
        }
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Deep merge with defaults
                    def deep_merge(default, loaded):
                        result = default.copy()
                        for key, value in loaded.items():
                            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                                result[key] = deep_merge(result[key], value)
                            else:
                                result[key] = value
                        return result
                    return deep_merge(self.default_config, loaded_config)
            except Exception as e:
                print(f"Error loading config: {e}")
                return self.default_config.copy()
        return self.default_config.copy()
    
    def save_config(self) -> bool:
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def get(self, key: str, default=None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value if value is not None else default

# Logging setup
class LogManager:
    """Log management class"""
    def __init__(self, config: Config):
        self.config = config
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                RotatingFileHandler(
                    self.config.get('log_file', 'cyber_tool.log'),
                    maxBytes=10*1024*1024,  # 10MB
                    backupCount=5
                ),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('CyberSecurityTool')

# Database management
class DatabaseManager:
    """Database management class"""
    def __init__(self, config: Config):
        self.config = config
        self.db_file = config.get('database', 'cyber_tool.db')
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Command history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    command TEXT,
                    source TEXT,
                    result TEXT
                )
            ''')
            
            # Monitoring targets table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS monitoring_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT UNIQUE,
                    target_type TEXT,
                    added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    last_check DATETIME,
                    status TEXT
                )
            ''')
            
            # Scan results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    scan_type TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    results TEXT
                )
            ''')
            
            # Threat intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT,
                    indicator_type TEXT,
                    source TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT,
                    description TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            print(f"✅ Database initialized: {self.db_file}")
        except Exception as e:
            print(f"❌ Database initialization error: {e}")
    
    def execute_query(self, query: str, params: tuple = ()) -> List[Tuple]:
        """Execute SQL query"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
            conn.commit()
            conn.close()
            return result
        except Exception as e:
            print(f"Database error: {e}")
            return []
    
    def log_command(self, command: str, source: str, result: str = ""):
        """Log command to database"""
        query = "INSERT INTO command_history (command, source, result) VALUES (?, ?, ?)"
        self.execute_query(query, (command, source, result))

# Network utilities
class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_ipv6(ip: str) -> bool:
        """Validate IPv6 address"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def ping_host(ip: str, ipv6: bool = False) -> Dict[str, Any]:
        """Ping a host"""
        try:
            if ipv6:
                # Use ping3 library for cross-platform compatibility
                response_time = ping3.ping(ip, timeout=4)
                success = response_time is not None
                return {
                    "success": success,
                    "response_time": response_time,
                    "output": f"Response time: {response_time}ms" if success else "Timeout"
                }
            else:
                response_time = ping3.ping(ip, timeout=4)
                success = response_time is not None
                return {
                    "success": success,
                    "response_time": response_time,
                    "output": f"Response time: {response_time}ms" if success else "Timeout"
                }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def port_scan(target: str, ports: List[int], timeout: int = 2) -> Dict[int, str]:
        """Perform port scan"""
        results = {}
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except:
                            service = "unknown"
                        return port, f"open - {service}"
                    else:
                        return port, "closed"
            except Exception:
                return port, "error"
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(ports))) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port, status = future.result()
                results[port] = status
        
        return results
    
    @staticmethod
    def traceroute(target: str, ipv6: bool = False) -> List[Dict[str, Any]]:
        """Perform traceroute"""
        try:
            if ipv6:
                command = ["traceroute6", "-w", "2", "-q", "1", "-n", target]
            else:
                command = ["traceroute", "-w", "2", "-q", "1", "-n", target]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            hops = []
            
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('traceroute'):
                    parts = line.split()
                    if len(parts) >= 2:
                        hop_info = {
                            "hop": parts[0],
                            "ip": parts[1],
                            "time": parts[2] if len(parts) > 2 else "N/A"
                        }
                        hops.append(hop_info)
            
            return hops
        except FileNotFoundError:
            return [{"error": "traceroute command not found. Install it first."}]
        except Exception as e:
            return [{"error": str(e)}]
    
    @staticmethod
    def dns_lookup(domain: str, record_type: str = "A") -> List[str]:
        """Perform DNS lookup"""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except Exception as e:
            return [f"Error: {str(e)}"]
    
    @staticmethod
    def get_geolocation(ip: str) -> Dict[str, str]:
        """Get IP geolocation"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            if data["status"] == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "lat": str(data.get("lat", "Unknown")),
                    "lon": str(data.get("lon", "Unknown"))
                }
            else:
                return {"error": data.get("message", "Unknown error")}
        except Exception as e:
            return {"error": str(e)}

# Security scanning
class SecurityScanner:
    """Security scanning utilities"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def deep_scan(self, target: str, ipv6: bool = False) -> Dict[str, Any]:
        """Perform deep security scan"""
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "ports": {},
            "services": {},
            "vulnerabilities": [],
            "recommendations": []
        }
        
        # Scan common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
        results["ports"] = NetworkUtils.port_scan(target, common_ports)
        
        # Service detection
        results["services"] = self.detect_services(target, results["ports"])
        
        # Vulnerability assessment
        results["vulnerabilities"] = self.assess_vulnerabilities(target, results["services"])
        
        # Generate recommendations
        results["recommendations"] = self.generate_recommendations(results)
        
        return results
    
    def detect_services(self, target: str, port_results: Dict[int, str]) -> Dict[int, Dict]:
        """Detect services running on open ports"""
        services = {}
        
        for port, status in port_results.items():
            if "open" in status:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((target, port))
                    
                    # Try to receive banner
                    try:
                        # Send a simple probe
                        sock.send(b"\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    except:
                        banner = ""
                    
                    service_info = {
                        "port": port,
                        "state": "open",
                        "banner": banner.strip(),
                        "service": status.split(" - ")[-1] if " - " in status else "unknown"
                    }
                    
                    services[port] = service_info
                    sock.close()
                except Exception as e:
                    services[port] = {
                        "port": port,
                        "state": "open",
                        "error": str(e),
                        "service": "unknown"
                    }
        
        return services
    
    def assess_vulnerabilities(self, target: str, services: Dict[int, Dict]) -> List[Dict]:
        """Basic vulnerability assessment"""
        vulnerabilities = []
        
        for port, service in services.items():
            # Check for common vulnerabilities based on service
            banner = service.get("banner", "").upper()
            
            if port == 21:  # FTP
                if "ANONYMOUS" in banner or "220" in banner:
                    vulnerabilities.append({
                        "port": port,
                        "service": "FTP",
                        "risk": "Medium",
                        "description": "FTP service may allow anonymous access",
                        "recommendation": "Disable anonymous FTP access"
                    })
            
            elif port == 22:  # SSH
                if "SSH" in banner:
                    vulnerabilities.append({
                        "port": port,
                        "service": "SSH",
                        "risk": "Low",
                        "description": "SSH service exposed",
                        "recommendation": "Use key-based authentication, disable root login"
                    })
            
            elif port == 23:  # Telnet
                vulnerabilities.append({
                    "port": port,
                    "service": "Telnet",
                    "risk": "High",
                    "description": "Telnet transmits data in clear text",
                    "recommendation": "Use SSH instead of Telnet"
                })
            
            elif port == 80 or port == 443:  # HTTP/HTTPS
                vulnerabilities.append({
                    "port": port,
                    "service": "Web",
                    "risk": "Medium",
                    "description": "Web service exposed",
                    "recommendation": "Ensure HTTPS, security headers, and regular updates"
                })
        
        return vulnerabilities
    
    def generate_recommendations(self, scan_results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        open_ports = [port for port, status in scan_results["ports"].items() if "open" in status]
        
        if len(open_ports) > 10:
            recommendations.append("Too many open ports. Close unnecessary services.")
        
        if any(vuln["risk"] == "High" for vuln in scan_results["vulnerabilities"]):
            recommendations.append("Address high-risk vulnerabilities immediately")
        
        if any(port in [21, 23, 25] for port in open_ports):  # FTP, Telnet, SMTP
            recommendations.append("Consider replacing insecure protocols (FTP, Telnet) with secure alternatives")
        
        return recommendations

# Monitoring system
class MonitoringSystem:
    """Continuous monitoring system"""
    
    def __init__(self, config: Config, db: DatabaseManager):
        self.config = config
        self.db = db
        self.monitoring_targets = {}
        self.is_monitoring = False
        self.monitoring_thread = None
        self.load_targets()
    
    def load_targets(self):
        """Load monitoring targets from database"""
        try:
            query = "SELECT target, target_type FROM monitoring_targets WHERE is_active = 1"
            results = self.db.execute_query(query)
            for target, target_type in results:
                self.monitoring_targets[target] = {
                    "type": target_type,
                    "last_status": "unknown",
                    "last_check": None,
                    "response_times": []
                }
        except Exception as e:
            print(f"Error loading targets: {e}")
    
    def add_target(self, target: str, target_type: str = "ipv4") -> bool:
        """Add target to monitoring"""
        try:
            # Validate target
            if target_type == "ipv4" and not NetworkUtils.validate_ip(target):
                return False
            elif target_type == "ipv6" and not NetworkUtils.validate_ipv6(target):
                return False
            
            query = "INSERT OR REPLACE INTO monitoring_targets (target, target_type, is_active) VALUES (?, ?, 1)"
            self.db.execute_query(query, (target, target_type))
            
            self.monitoring_targets[target] = {
                "type": target_type,
                "last_status": "unknown",
                "last_check": None,
                "response_times": []
            }
            return True
        except Exception as e:
            print(f"Error adding target: {e}")
            return False
    
    def remove_target(self, target: str) -> bool:
        """Remove target from monitoring"""
        try:
            query = "UPDATE monitoring_targets SET is_active = 0 WHERE target = ?"
            self.db.execute_query(query, (target,))
            
            if target in self.monitoring_targets:
                del self.monitoring_targets[target]
            return True
        except Exception as e:
            print(f"Error removing target: {e}")
            return False
    
    def start_monitoring(self) -> bool:
        """Start monitoring all targets"""
        if self.is_monitoring:
            return False
        
        if not self.monitoring_targets:
            print("❌ No targets to monitor. Add targets first.")
            return False
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        return True
    
    def stop_monitoring(self) -> bool:
        """Stop monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        return True
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        print(f"🔍 Starting monitoring of {len(self.monitoring_targets)} targets...")
        
        while self.is_monitoring:
            for target, info in list(self.monitoring_targets.items()):
                if not self.is_monitoring:
                    break
                
                try:
                    start_time = time.time()
                    ping_result = NetworkUtils.ping_host(target, info["type"] == "ipv6")
                    response_time = (time.time() - start_time) * 1000
                    
                    status = "up" if ping_result["success"] else "down"
                    
                    # Update target info
                    info["last_status"] = status
                    info["last_check"] = datetime.now()
                    if ping_result["success"]:
                        info["response_times"].append(response_time)
                    
                    # Keep only last 10 response times
                    if len(info["response_times"]) > 10:
                        info["response_times"] = info["response_times"][-10:]
                    
                    # Update database
                    query = "UPDATE monitoring_targets SET last_check = ?, status = ? WHERE target = ?"
                    self.db.execute_query(query, (info["last_check"], status, target))
                    
                    # Log status changes
                    if info["last_status"] != status:
                        print(f"📊 {target} changed status: {info['last_status']} → {status}")
                    
                except Exception as e:
                    print(f"Monitoring error for {target}: {e}")
            
            # Sleep between monitoring cycles
            time.sleep(self.config.get('monitoring.interval', 60))
    
    def get_status(self) -> str:
        """Get monitoring status"""
        if not self.monitoring_targets:
            return "No targets being monitored"
        
        status_text = f"📊 Monitoring {len(self.monitoring_targets)} targets:\n"
        for target, info in self.monitoring_targets.items():
            status_text += f"  {target} ({info['type']}): {info['last_status']}\n"
            if info['response_times']:
                avg_time = sum(info['response_times']) / len(info['response_times'])
                status_text += f"    Avg response: {avg_time:.2f}ms\n"
        
        return status_text

# Telegram integration
class TelegramBot:
    """Telegram bot integration"""
    
    def __init__(self, config: Config, db: DatabaseManager):
        self.config = config
        self.db = db
        self.application = None
        self.bot = None
        if TELEGRAM_AVAILABLE:
            self.setup_bot()
    
    def setup_bot(self):
        """Setup Telegram bot"""
        token = self.config.get('telegram.token')
        if not token:
            print("❌ Telegram token not configured")
            return
        
        try:
            self.bot = telegram.Bot(token=token)
            self.application = Application.builder().token(token).build()
            self._setup_handlers()
            print("✅ Telegram bot configured")
        except Exception as e:
            print(f"❌ Telegram bot setup error: {e}")
    
    def _setup_handlers(self):
        """Setup Telegram command handlers"""
        if not self.application:
            return
        
        # Add command handlers
        self.application.add_handler(CommandHandler("start", self._cmd_start))
        self.application.add_handler(CommandHandler("help", self._cmd_help))
        self.application.add_handler(CommandHandler("ping_ip", self._cmd_ping_ip))
        self.application.add_handler(CommandHandler("status", self._cmd_status))
        self.application.add_handler(CommandHandler("scan_ip", self._cmd_scan_ip))
    
    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        await update.message.reply_text(
            "🔒 Cybersecurity Monitoring Bot Started!\n"
            "Use /help for available commands."
        )
    
    async def _cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_text = """
🔒 *Cybersecurity Tool Commands:*

*Monitoring Commands:*
/start - Start the bot
/help - Show this help message
/ping_ip <IP> - Ping IPv4 address
/status - Show monitoring status
/scan_ip <IP> - Quick port scan

*More commands available in the CLI version*
        """
        await update.message.reply_text(help_text, parse_mode='Markdown')
    
    async def _cmd_ping_ip(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /ping_ip command"""
        if not context.args:
            await update.message.reply_text("Usage: /ping_ip <IP_ADDRESS>")
            return
        
        ip = context.args[0]
        if not NetworkUtils.validate_ip(ip):
            await update.message.reply_text("❌ Invalid IP address")
            return
        
        result = NetworkUtils.ping_host(ip)
        response = f"🏓 Ping results for {ip}:\n"
        response += f"Status: {'✅ Up' if result['success'] else '❌ Down'}\n"
        if result.get('response_time'):
            response += f"Response time: {result['response_time']:.2f}ms\n"
        
        await update.message.reply_text(response)
    
    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command"""
        status_text = "📊 Bot is running\nUse the CLI for full monitoring features"
        await update.message.reply_text(status_text)
    
    async def _cmd_scan_ip(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /scan_ip command"""
        if not context.args:
            await update.message.reply_text("Usage: /scan_ip <IP_ADDRESS>")
            return
        
        ip = context.args[0]
        await update.message.reply_text(f"🔍 Scanning {ip}...")
        
        # Implement scanning logic
        ports = [21, 22, 23, 25, 53, 80, 443, 3389]
        results = NetworkUtils.port_scan(ip, ports)
        
        response = f"Scan results for {ip}:\n"
        open_ports = 0
        for port, status in sorted(results.items()):
            if "open" in status:
                open_ports += 1
                response += f"✅ Port {port}: {status}\n"
            else:
                response += f"❌ Port {port}: {status}\n"
        
        response += f"\n📊 Found {open_ports} open ports"
        await update.message.reply_text(response)
    
    def start_bot(self):
        """Start the Telegram bot"""
        if self.application:
            try:
                print("🤖 Starting Telegram bot...")
                self.application.run_polling()
            except Exception as e:
                print(f"❌ Telegram bot error: {e}")
    
    def send_message(self, chat_id: str, message: str) -> bool:
        """Send message via Telegram"""
        try:
            if self.bot:
                self.bot.send_message(chat_id=chat_id, text=message)
                return True
        except Exception as e:
            print(f"Telegram send error: {e}")
        return False

# Main application
class CyberSecurityTool:
    """Main cybersecurity tool application"""
    
    def __init__(self):
        self.config = Config()
        self.log_manager = LogManager(self.config)
        self.logger = self.log_manager.logger
        self.db = DatabaseManager(self.config)
        self.network_utils = NetworkUtils()
        self.scanner = SecurityScanner(self.config)
        self.monitor = MonitoringSystem(self.config, self.db)
        self.telegram_bot = TelegramBot(self.config, self.db)
        
        self.running = True
        self.command_history = []
        self.current_view = "main"
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        self.monitor.stop_monitoring()
    
    def print_banner(self):
        """Print application banner"""
        theme = self.config.get('theme', {})
        primary_color = theme.get('primary_color', '\033[92m')
        reset_color = theme.get('reset_color', '\033[0m')
        
        banner = f"""
{primary_color}
╔══════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                
         🔒 ACCURATE CYBER DEFENSE NEWTWORK PENTEST TOOL                            
║        Community: https://github.com/Accurate-Cyber-Defense                       
║        Doc:https://accurate-cyber-defense.github.io/accurate-cyber-defense-web/   
║        
║                                                               
╚══════════════════════════════════════════════════════════════════════════════════════════════╝
{reset_color}
        """
        print(banner)
    
    def print_prompt(self):
        """Print command prompt"""
        theme = self.config.get('theme', {})
        primary_color = theme.get('primary_color', '\033[92m')
        reset_color = theme.get('reset_color', '\033[0m')
        prompt = f"{primary_color}accuratebot>{reset_color} "
        return input(prompt)
    
    def execute_command(self, command: str, source: str = "cli") -> str:
        """Execute a command and return result"""
        self.command_history.append(command)
        self.db.log_command(command, source)
        
        parts = command.strip().split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd == "help":
                return self.cmd_help()
            elif cmd == "clear":
                return self.cmd_clear()
            elif cmd == "ping":
                return self.cmd_ping(args)
            elif cmd == "scan":
                return self.cmd_scan(args)
            elif cmd == "deepscan":
                return self.cmd_deepscan(args)
            elif cmd == "traceroute":
                return self.cmd_traceroute(args)
            elif cmd == "dig":
                return self.cmd_dig(args)
            elif cmd == "add":
                return self.cmd_add(args)
            elif cmd == "remove":
                return self.cmd_remove(args)
            elif cmd == "start":
                return self.cmd_start_monitoring()
            elif cmd == "stop":
                return self.cmd_stop_monitoring()
            elif cmd == "status":
                return self.cmd_status()
            elif cmd == "view":
                return self.cmd_view(args)
            elif cmd == "history":
                return self.cmd_history()
            elif cmd == "location":
                return self.cmd_location(args)
            elif cmd == "config":
                return self.cmd_config(args)
            elif cmd == "test":
                return self.cmd_test_telegram()
            elif cmd == "exit":
                self.running = False
                return "Goodbye!"
            else:
                return f"Unknown command: {cmd}. Type 'help' for available commands."
        
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def cmd_help(self) -> str:
        """Display help information"""
        help_text = """
🔒 Cybersecurity Tool Commands:

📊 Monitoring Commands:
  ping IP                 - Ping IPv4 address
  add IP                 - Add IP to monitoring
  remove IP              - Remove IP from monitoring
  start                  - Start monitoring
  stop                   - Stop monitoring
  status                 - Show monitoring status

🔍 Scanning Commands:
  scan IP                - Quick port scan
  deepscan IP            - Deep security scan
  traceroute IP          - Trace route to IP

🌐 Information Commands:
  dig <domain>           - DNS lookup
  location IP            - IP geolocation

📁 Utility Commands:
  history                - Command history
  view targets           - View monitoring targets
  config telegram <token> <chat_id> - Configure Telegram
  test telegram          - Test Telegram connection
  clear                  - Clear screen
  exit                   - Exit application
        """
        return help_text
    
    def cmd_ping(self, args: List[str]) -> str:
        """Ping command implementation"""
        if len(args) < 1:
            return "Usage: ping <IP_ADDRESS>"
        
        target = args[0]
        ipv6 = NetworkUtils.validate_ipv6(target)
        
        result = NetworkUtils.ping_host(target, ipv6)
        
        if result["success"]:
            return f"✅ {target} is reachable\nResponse time: {result.get('response_time', 'N/A')}ms"
        else:
            return f"❌ {target} is not reachable\nError: {result.get('error', 'Unknown error')}"
    
    def cmd_scan(self, args: List[str]) -> str:
        """Port scan command"""
        if len(args) < 1:
            return "Usage: scan <IP_ADDRESS>"
        
        target = args[0]
        if not NetworkUtils.validate_ip(target) and not NetworkUtils.validate_ipv6(target):
            return "❌ Invalid IP address"
        
        # Scan common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
        print(f"🔍 Scanning {target}...")
        results = NetworkUtils.port_scan(target, common_ports)
        
        response = f"📊 Port scan results for {target}:\n"
        open_ports = 0
        for port, status in sorted(results.items()):
            if "open" in status:
                open_ports += 1
                response += f"✅ Port {port}: {status}\n"
            else:
                response += f"❌ Port {port}: {status}\n"
        
        response += f"\n📈 Summary: {open_ports} open ports out of {len(common_ports)} scanned"
        return response
    
    def cmd_deepscan(self, args: List[str]) -> str:
        """Deep scan command"""
        if len(args) < 1:
            return "Usage: deepscan <IP_ADDRESS>"
        
        target = args[0]
        print(f"🔍 Starting deep security scan of {target}...")
        
        results = self.scanner.deep_scan(target)
        
        response = f"📊 Deep scan results for {target}:\n\n"
        
        # Ports
        open_ports = [p for p, s in results["ports"].items() if "open" in s]
        response += f"📡 Ports: {len(open_ports)} open\n"
        for port in open_ports:
            response += f"  Port {port}: {results['ports'][port]}\n"
        
        # Vulnerabilities
        if results["vulnerabilities"]:
            response += f"\n⚠️  Vulnerabilities found: {len(results['vulnerabilities'])}\n"
            for vuln in results["vulnerabilities"]:
                response += f"  {vuln['port']}/{vuln['service']}: {vuln['risk']} - {vuln['description']}\n"
        else:
            response += "\n✅ No significant vulnerabilities detected\n"
        
        # Recommendations
        if results["recommendations"]:
            response += f"\n💡 Recommendations:\n"
            for rec in results["recommendations"]:
                response += f"  • {rec}\n"
        
        return response
    
    def cmd_traceroute(self, args: List[str]) -> str:
        """Traceroute command"""
        if len(args) < 1:
            return "Usage: traceroute <IP_ADDRESS_or_DOMAIN>"
        
        target = args[0]
        ipv6 = NetworkUtils.validate_ipv6(target)
        
        results = NetworkUtils.traceroute(target, ipv6)
        
        response = f"🛣️  Traceroute to {target}:\n"
        for hop in results:
            if "error" in hop:
                return f"❌ Error: {hop['error']}"
            else:
                response += f"Hop {hop['hop']}: {hop['ip']} - {hop['time']}\n"
        
        return response
    
    def cmd_dig(self, args: List[str]) -> str:
        """DNS lookup command"""
        if len(args) < 1:
            return "Usage: dig <DOMAIN>"
        
        domain = args[0]
        record_types = ["A", "AAAA", "MX", "NS", "TXT"]
        
        response = f"🌐 DNS lookup for {domain}:\n"
        for record_type in record_types:
            try:
                results = NetworkUtils.dns_lookup(domain, record_type)
                if results and not results[0].startswith("Error"):
                    response += f"\n{record_type} records:\n"
                    for result in results:
                        response += f"  {result}\n"
            except Exception as e:
                response += f"\n{record_type} lookup failed: {e}\n"
        
        return response
    
    def cmd_add(self, args: List[str]) -> str:
        """Add monitoring target"""
        if len(args) < 1:
            return "Usage: add <IP_ADDRESS>"
        
        target = args[0]
        if NetworkUtils.validate_ipv6(target):
            target_type = "ipv6"
        elif NetworkUtils.validate_ip(target):
            target_type = "ipv4"
        else:
            return "❌ Invalid IP address"
        
        if self.monitor.add_target(target, target_type):
            return f"✅ Added {target} to monitoring"
        else:
            return f"❌ Failed to add {target}"
    
    def cmd_remove(self, args: List[str]) -> str:
        """Remove monitoring target"""
        if len(args) < 1:
            return "Usage: remove <IP_ADDRESS>"
        
        target = args[0]
        if self.monitor.remove_target(target):
            return f"✅ Removed {target} from monitoring"
        else:
            return f"❌ Failed to remove {target}"
    
    def cmd_start_monitoring(self) -> str:
        """Start monitoring"""
        if self.monitor.start_monitoring():
            return "✅ Monitoring started"
        else:
            return "❌ Monitoring already running or no targets"
    
    def cmd_stop_monitoring(self) -> str:
        """Stop monitoring"""
        if self.monitor.stop_monitoring():
            return "✅ Monitoring stopped"
        else:
            return "❌ Monitoring not running"
    
    def cmd_status(self) -> str:
        """Get monitoring status"""
        return self.monitor.get_status()
    
    def cmd_view(self, args: List[str]) -> str:
        """View command"""
        if len(args) < 1:
            return "Usage: view <targets|config>"
        
        subcmd = args[0].lower()
        if subcmd == "targets":
            return self.monitor.get_status()
        elif subcmd == "config":
            return f"Configuration: {json.dumps(self.config.config, indent=2)}"
        else:
            return "Unknown view command"
    
    def cmd_location(self, args: List[str]) -> str:
        """Get IP location"""
        if len(args) < 1:
            return "Usage: location <IP_ADDRESS>"
        
        ip = args[0]
        if not NetworkUtils.validate_ip(ip):
            return "❌ Invalid IP address"
        
        location = NetworkUtils.get_geolocation(ip)
        if "error" in location:
            return f"❌ Error getting location: {location['error']}"
        
        response = f"🌍 Location for {ip}:\n"
        response += f"Country: {location['country']}\n"
        response += f"Region: {location['region']}\n"
        response += f"City: {location['city']}\n"
        response += f"ISP: {location['isp']}\n"
        response += f"Coordinates: {location['lat']}, {location['lon']}\n"
        
        return response
    
    def cmd_config(self, args: List[str]) -> str:
        """Configure settings"""
        if len(args) < 3:
            return "Usage: config <section> <key> <value>"
        
        section, key, value = args[0], args[1], " ".join(args[2:])
        
        # Update config
        if section in self.config.config and key in self.config.config[section]:
            self.config.config[section][key] = value
            self.config.save_config()
            return f"✅ Updated {section}.{key} = {value}"
        else:
            return f"❌ Invalid config section or key"
    
    def cmd_test_telegram(self) -> str:
        """Test Telegram connection"""
        if not TELEGRAM_AVAILABLE:
            return "❌ Telegram library not installed"
        
        token = self.config.get('telegram.token')
        if not token:
            return "❌ Telegram token not configured"
        
        try:
            bot = telegram.Bot(token=token)
            updates = bot.get_updates()
            return f"✅ Telegram connection successful. Updates: {len(updates)}"
        except Exception as e:
            return f"❌ Telegram connection failed: {e}"
    
    def cmd_clear(self) -> str:
        """Clear screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
        return ""
    
    def cmd_history(self) -> str:
        """Show command history"""
        if not self.command_history:
            return "No command history available."
        
        response = "📜 Command History (last 10):\n"
        for i, cmd in enumerate(self.command_history[-10:], 1):
            response += f"{i}: {cmd}\n"
        
        return response
    
    def run_cli(self):
        """Run the command-line interface"""
        self.print_banner()
        print("Type 'help' for available commands\n")
        
        # Start Telegram bot in background thread if configured
        token = self.config.get('telegram.token')
        if token and TELEGRAM_AVAILABLE:
            telegram_thread = threading.Thread(target=self.telegram_bot.start_bot)
            telegram_thread.daemon = True
            telegram_thread.start()
            print("✅ Telegram bot started in background")
        else:
            print("ℹ️  Telegram not configured. Use 'config telegram <token> <chat_id>' to enable.")
        
        # Load existing monitoring targets
        print(f"📊 Loaded {len(self.monitor.monitoring_targets)} monitoring targets")
        
        while self.running:
            try:
                command = self.print_prompt()
                result = self.execute_command(command)
                if result:
                    print(result)
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit the application")
            except EOFError:
                break
            except Exception as e:
                print(f"❌ Error: {e}")
        
        print("\nShutting down Accurate Cyber Defense Cyber Security Bot  ...")
        self.monitor.stop_monitoring()

def main():
    """Main entry point"""
    # Check for required dependencies
    try:
        import dns.resolver
        import ping3
    except ImportError as e:
        print(f"❌ Missing required dependency: {e}")
        print("Install with: pip install dnspython ping3")
        sys.exit(1)
    
    try:
        tool = CyberSecurityTool()
        tool.run_cli()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()