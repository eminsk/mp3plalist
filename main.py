import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Menu
import urllib.request
import urllib.error
import socket
from typing import Dict, List, Optional, Callable, Set, Any, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
import json
import threading
from dataclasses import dataclass, field
from functools import partial, lru_cache, reduce
import operator
import time
import subprocess
import os
import sys
import ipaddress
import requests
import aiohttp
import asyncio
import dns.resolver
import dns.reversename
import re

@dataclass(frozen=True)
class IPInfo:
    """Immutable IP information container."""
    ip: str
    asn: Optional[int] = None
    isp: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    
    def __str__(self) -> str:
        parts = [f"IP: {self.ip}"]
        if self.asn:
            parts.append(f"AS{self.asn}")
        if self.isp:
            parts.append(f"ISP: {self.isp}")
        if self.city:
            parts.append(f"City: {self.city}")
        if self.country:
            parts.append(f"Country: {self.country}")
        return " | ".join(parts)


class EnhancedIPResolver:
    """High-performance IP geolocation and AS Number resolver."""
    
    def __init__(self, cache_size: int = 1024):
        self.cache_size = cache_size
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'Enhanced-IP-Resolver/1.0',
            'Accept': 'application/json'
        })
    
    @lru_cache(maxsize=1024)
    def resolve_ip_info(self, ip: str) -> IPInfo:
        """
        Resolve IP address to comprehensive information including ASN, ISP, and location.
        
        Args:
            ip: IP address string (IPv4 or IPv6)
            
        Returns:
            IPInfo object with all available information
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return IPInfo(ip=ip)
        
        clean_ip = str(ip_obj)
        
        info = self._ipinfo_comprehensive_lookup(clean_ip)
        if info.asn or info.isp:
            return info
        
        info = self._ipapi_lookup(clean_ip)
        if info.asn or info.isp:
            return info
        
        asn = self._dns_asn_lookup(clean_ip)
        return IPInfo(ip=clean_ip, asn=asn) if asn else IPInfo(ip=clean_ip)
    
    def _ipinfo_comprehensive_lookup(self, ip: str) -> IPInfo:
        """IPInfo.io comprehensive lookup with geolocation and ASN data."""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = self._session.get(url, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            
            asn = None
            isp = None
            org = data.get('org', '')
            if org:
                parts = org.split(' ', 1)
                if parts[0].startswith('AS'):
                    try:
                        asn = int(parts[0][2:])
                        isp = parts[1] if len(parts) > 1 else None
                    except ValueError:
                        isp = org
                else:
                    isp = org
            
            loc = data.get('loc', '').split(',')
            latitude = float(loc[0]) if len(loc) >= 2 and loc[0] else None
            longitude = float(loc[1]) if len(loc) >= 2 and loc[1] else None
            
            return IPInfo(
                ip=ip,
                asn=asn,
                isp=isp,
                city=data.get('city'),
                country=data.get('country'),
                country_code=data.get('country'),
                region=data.get('region'),
                latitude=latitude,
                longitude=longitude
            )
            
        except (requests.RequestException, ValueError, KeyError):
            return IPInfo(ip=ip)
    
    def _ipapi_lookup(self, ip: str) -> IPInfo:
        """IP-API.com lookup (free, unlimited for non-commercial use)."""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = self._session.get(url, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') != 'success':
                return IPInfo(ip=ip)
            
            return IPInfo(
                ip=ip,
                asn=data.get('as', '').split()[0][2:] if data.get('as', '').startswith('AS') else None,
                isp=data.get('isp') or data.get('org'),
                city=data.get('city'),
                country=data.get('country'),
                country_code=data.get('countryCode'),
                region=data.get('regionName'),
                latitude=data.get('lat'),
                longitude=data.get('lon')
            )
            
        except (requests.RequestException, ValueError, KeyError):
            return IPInfo(ip=ip)
    
    def _dns_asn_lookup(self, ip: str) -> Optional[int]:
        """DNS-based ASN lookup using Cymru DNS service."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.version == 4:
                octets = ip.split('.')
                query = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
            else:
                reversed_ip = dns.reversename.from_address(ip)
                query = str(reversed_ip).replace('.ip6.arpa.', '.origin6.asn.cymru.com.')
            
            answers = dns.resolver.resolve(query, 'TXT')
            response = str(answers[0]).strip('"')
            
            asn = response.split('|')[0].strip()
            return int(asn) if asn.isdigit() else None
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, 
                ValueError, IndexError):
            return None
    
    def _cymru_whois_lookup(self, ip: str) -> IPInfo:
        """Enhanced Cymru WHOIS lookup with ISP information."""
        try:
            url = "https://whois.cymru.com/cgi-bin/whois.cgi"
            data = {"action": "do_whois", "family": "ipv4", "bulk_paste": ip}
            
            response = self._session.post(url, data=data, timeout=5)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            for line in lines:
                if ip in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 3:
                        asn = int(parts[0]) if parts[0].isdigit() else None
                        country = parts[2] if len(parts) > 2 else None
                        return IPInfo(ip=ip, asn=asn, country_code=country)
                    
        except (requests.RequestException, ValueError, IndexError):
            pass
        
        return IPInfo(ip=ip)
    
    def resolve_bulk(self, ips: list[str], max_workers: int = 10) -> Dict[str, IPInfo]:
        """
        Resolve multiple IP addresses to comprehensive information concurrently.
        
        Args:
            ips: List of IP addresses
            max_workers: Maximum number of concurrent threads
            
        Returns:
            Dictionary mapping IP addresses to IPInfo objects
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.resolve_ip_info, ip): ip for ip in ips}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    results[ip] = future.result()
                except Exception:
                    results[ip] = IPInfo(ip=ip)
        
        return results
    
    def get_asn_only(self, ip: str) -> Optional[int]:
        """Get only AS Number for backward compatibility."""
        return self.resolve_ip_info(ip).asn


# Convenience functions
def get_ip_info(ip: str) -> IPInfo:
    """
    Get comprehensive IP information including ASN, ISP, and location.
    
    Args:
        ip: IP address string
        
    Returns:
        IPInfo object with all available information
    """
    return EnhancedIPResolver().resolve_ip_info(ip)

def get_asn(ip: str) -> Optional[int]:
    """Get only AS Number for backward compatibility."""
    return get_ip_info(ip).asn

@dataclass(frozen=True)
class IPBlock:
    """Immutable IP block representation with built-in validation."""
    network: str
    
    def __post_init__(self):
        ipaddress.ip_network(self.network, strict=False)
    
    @property
    def network_obj(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.network, strict=False)


class ISPBlockLookup:
    """
    High-performance ISP IP block lookup with multiple data sources.
    Uses BGPView, RIPE, and Hurricane Electric APIs for comprehensive coverage.
    """
    
    __slots__ = ('_session', '_cache', '_apis')
    
    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache: dict = {}
        self._apis = {
            'bgpview': 'https://api.bgpview.io/asn/{}/prefixes',
            'ripe': 'https://rest.db.ripe.net/search.json',
            'hurricane': 'https://bgp.he.net/AS{}'
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=10, limit_per_host=5),
            headers={'User-Agent': 'ISPBlockLookup/1.0'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._session.close() if self._session else None
    
    @staticmethod
    def _normalize_as_number(as_number: str) -> str:
        """Normalize AS number to numeric format."""
        return re.sub(r'[^\d]', '', as_number)
    
    @lru_cache(maxsize=256)
    def _extract_all_cidrs(self, text: str) -> frozenset:
        """Extract all possible CIDR blocks from text."""
        patterns = [
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}\b',  # Standard CIDR
            r'"prefix":\s*"([^"]+)"',  # JSON prefix field
            r'route:\s*([^\s\n]+)',  # RIPE route field
            r'origin:\s*AS[0-9]+\s+([^\s\n]+)',  # Origin with prefix
        ]
        
        candidates = set()
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
            candidates.update(matches)
        
        return frozenset(filter(None, map(self._validate_cidr, candidates)))
    
    @staticmethod
    def _validate_cidr(cidr: str) -> Optional[str]:
        """Validate and normalize CIDR notation - IPv4 only."""
        try:
            cidr = cidr.strip().replace(' ', '')
            network = ipaddress.ip_network(cidr, strict=False)
            return str(network) if network.version == 4 else None
        except (ipaddress.AddressValueError, ValueError):
            return None
    
    async def _fetch_with_retry(self, url: str, params: Optional[dict] = None, 
                               headers: Optional[dict] = None, max_retries: int = 3) -> Optional[str]:
        """Fetch data with retry logic."""
        for attempt in range(max_retries):
            try:
                async with self._session.get(url, params=params, headers=headers) as response:
                    return await response.text() if response.status == 200 else None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(2 ** attempt) if attempt < max_retries - 1 else None
        return None
    
    async def _query_bgpview(self, as_number: str) -> Set[str]:
        """Query BGPView API for AS prefixes."""
        url = self._apis['bgpview'].format(as_number)
        
        try:
            async with self._session.get(url) as response:
                data = await response.json() if response.status == 200 else {}
                
                prefixes = data.get('data', {}).get('ipv4_prefixes', [])
                return {
                    self._validate_cidr(prefix.get('prefix', ''))
                    for prefix in prefixes
                    if self._validate_cidr(prefix.get('prefix', ''))
                }
        except Exception:
            return set()
    
    async def _query_ripe_db(self, as_number: str) -> Set[str]:
        """Query RIPE database for route objects."""
        params = {
            'query-string': f'AS{as_number}',
            'type-filter': 'route',
            'flags': 'no-referenced,no-filtering'
        }
        
        response_text = await self._fetch_with_retry(self._apis['ripe'], params=params)
        return self._extract_all_cidrs(response_text or '')
    
    async def _query_hurricane_electric(self, as_number: str) -> Set[str]:
        """Query Hurricane Electric BGP toolkit."""
        url = self._apis['hurricane'].format(as_number)
        
        response_text = await self._fetch_with_retry(url)
        return self._extract_all_cidrs(response_text or '')
    
    async def _query_ripe_stat(self, as_number: str) -> Set[str]:
        """Query RIPEstat API as additional source."""
        url = f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{as_number}'
        
        try:
            async with self._session.get(url) as response:
                data = await response.json() if response.status == 200 else {}
                
                prefixes = data.get('data', {}).get('prefixes', [])
                return {
                    self._validate_cidr(prefix.get('prefix', ''))
                    for prefix in prefixes
                    if self._validate_cidr(prefix.get('prefix', ''))
                }
        except Exception:
            return set()
    
    def _consolidate_networks(self, networks: Set[str]) -> Set[str]:
        """Consolidate overlapping IPv4 networks functionally."""
        ipv4_networks = []
        for net in networks:
            if net:
                try:
                    network_obj = ipaddress.ip_network(net, strict=False)
                    if network_obj.version == 4:
                        ipv4_networks.append(network_obj)
                except (ipaddress.AddressValueError, ValueError):
                    continue
        
        sorted_networks = sorted(
            ipv4_networks, 
            key=lambda x: (x.network_address, x.prefixlen)
        )
        
        def consolidate_reducer(consolidated: List[ipaddress.IPv4Network], 
                              current: ipaddress.IPv4Network) -> List[ipaddress.IPv4Network]:
            return (
                consolidated
                if consolidated and any(net.supernet_of(current) for net in consolidated)
                else consolidated + [current]
            )
        
        final_networks = reduce(consolidate_reducer, sorted_networks, [])
        return {str(net) for net in final_networks}
    
    async def lookup_ip_blocks(self, as_number: str) -> Set[str]:
        """
        Main method to lookup IP blocks for given AS number.
        
        Args:
            as_number: AS number (e.g., 'AS15169' or '15169')
            
        Returns:
            Set of unique, consolidated CIDR blocks
        """
        normalized_as = self._normalize_as_number(as_number)
        
        cache_key = f"blocks_{normalized_as}"
        cached_result = self._cache.get(cache_key)
        if cached_result:
            return cached_result
        
        print(f"Querying multiple sources for AS{normalized_as}...")
        
        tasks = [
            self._query_bgpview(normalized_as),
            self._query_ripe_db(normalized_as),
            self._query_hurricane_electric(normalized_as),
            self._query_ripe_stat(normalized_as)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_blocks = reduce(
            operator.or_,
            (result for result in results if isinstance(result, set)),
            set()
        )
        
        print(f"Raw blocks found: {len(all_blocks)}")
        
        valid_blocks = {block for block in all_blocks if block}
        consolidated = self._consolidate_networks(valid_blocks)
        
        self._cache[cache_key] = consolidated
        
        return consolidated
    
    def get_statistics(self, blocks: Set[str]) -> Dict[str, Any]:
        """Get comprehensive statistics about the IPv4 blocks."""
        return {} if not blocks else {
            'total_blocks': len(blocks),
            'total_ip_addresses': sum(
                ipaddress.IPv4Network(block, strict=False).num_addresses
                for block in blocks
            ),
            'prefix_distribution': reduce(
                lambda dist, block: {
                    **dist,
                    ipaddress.IPv4Network(block, strict=False).prefixlen: 
                    dist.get(ipaddress.IPv4Network(block, strict=False).prefixlen, 0) + 1
                },
                {},
                blocks
            )
        }

@dataclass(eq=False) # eq=False because we want to modify instances
class StreamChannel:
    """Represents a single stream channel with metadata."""
    name: str
    url: str
    status: Optional[bool] = None
    last_checked: Optional[float] = None
    group: str = ""
    logo: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'url': self.url,
            'status': self.status,
            'last_checked': self.last_checked,
            'group': self.group,
            'logo': self.logo
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'StreamChannel':
        return cls(
            name=data['name'],
            url=data['url'],
            status=data.get('status'),
            last_checked=data.get('last_checked'),
            group=data.get('group', ''),
            logo=data.get('logo', '')
        )

@dataclass(frozen=True)
class M3UStream:
    """Represents a multicast stream with IP and port."""
    ip: str
    port: int

    def to_url(self, udpxy_ip: str, udpxy_port: int) -> str:
        """Generates a UDPXY-proxied URL for this multicast stream."""
        return f"http://{udpxy_ip}:{udpxy_port}/udp/{self.ip}:{self.port}"


class StreamChecker:
    """High-performance stream checker with minimal memory footprint."""
    
    @staticmethod
    def check_stream(url: str, timeout: float = 3.0) -> bool:
        """Check single stream availability with optimized performance."""
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'StreamChecker/1.0',
                'Range': 'bytes=0-512'
            })
            
            socket.setdefaulttimeout(timeout)
            
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return (response.status == 200 and 
                       len(response.read(512)) > 0 and
                       any(response.headers.get('Content-Type', '').startswith(ct) 
                           for ct in ('video/', 'application/octet-stream', 'multipart/')))
        
        except (urllib.error.URLError, urllib.error.HTTPError, 
                socket.timeout, socket.error, OSError):
            return False
    
    @staticmethod
    def check_udpxy_server(ip: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a single UDPXY server is working."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            # Send a minimal HTTP GET request to the /status page to confirm it's a UDPXY server
            sock.sendall(b"GET /status HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = sock.recv(1024) # Read some response data
            sock.close()
            
            # Check for common UDPXY indicators in the response
            return b"udpxy" in data.lower() or b"stream" in data.lower() or b"http/1." in data.lower()
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        except Exception as e:
            # Log other unexpected errors but treat as unavailable for this check
            print(f"Error checking UDPXY {ip}:{port}: {e}")
            return False

    @staticmethod
    def batch_check(channels: List[StreamChannel], 
                   timeout: float = 3.0, 
                   max_workers: int = 20,
                   progress_callback: Optional[Callable] = None) -> Dict[str, bool]:
        """Batch check streams with progress reporting."""
        results = {}
        
        with ThreadPoolExecutor(max_workers=min(len(channels), max_workers)) as executor:
            future_to_channel = {
                executor.submit(StreamChecker.check_stream, channel.url, timeout): channel
                for channel in channels
            }
            
            completed = 0
            for future in as_completed(future_to_channel):
                channel = future_to_channel[future]
                results[channel.url] = future.result()
                completed += 1
                
                progress_callback and progress_callback(completed, len(channels))
        
        return results

    @staticmethod
    def check_multicast_through_udpxy(udpxy_ip: str, udpxy_port: int, multicast_stream: M3UStream, timeout: float = 3.0) -> bool:
        """Checks if a UDPXY server can successfully proxy a given multicast stream."""
        try:
            # Construct the UDPXY URL for the multicast stream
            udpxy_url = f"http://{udpxy_ip}:{udpxy_port}/udp/{multicast_stream.ip}:{multicast_stream.port}"
            
            req = urllib.request.Request(udpxy_url, headers={
                'User-Agent': 'StreamChecker/1.0',
                'Range': 'bytes=0-512' # Request a small chunk to confirm availability
            })
            
            socket.setdefaulttimeout(timeout)
            
            with urllib.request.urlopen(req, timeout=timeout) as response:
                # Check for successful HTTP status and some content length
                return (response.status == 200 and 
                       len(response.read(512)) > 0 and
                       any(response.headers.get('Content-Type', '').startswith(ct) 
                           for ct in ('video/', 'application/octet-stream', 'multipart/')))
        
        except (urllib.error.URLError, urllib.error.HTTPError, 
                socket.timeout, socket.error, OSError) as e:
            # print(f"UDPXY multicast check failed for {udpxy_ip}:{udpxy_port} -> {multicast_stream.ip}:{multicast_stream.port}: {e}")
            return False
        except Exception as e:
            # print(f"An unexpected error occurred during UDPXY multicast check: {e}")
            return False


class ModernTreeview(ttk.Treeview):
    """Enhanced Treeview with modern styling and functionality."""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.configure_style()
        self.bind('<Double-1>', self.on_double_click)
        self.bind('<Button-3>', self.on_right_click)
        
    def configure_style(self):
        """Configure modern styling for the treeview."""
        style = ttk.Style()
        style.configure("Modern.Treeview", 
                       background="white",
                       foreground="black",
                       fieldbackground="white",
                       borderwidth=0,
                       relief="flat")
        style.configure("Modern.Treeview.Heading",
                       background="#f0f0f0",
                       foreground="black",
                       relief="flat",
                       borderwidth=1)
        self.configure(style="Modern.Treeview")
    
    def on_double_click(self, event):
        """Handle double-click events."""
        item = self.selection()[0] if self.selection() else None
        if item:
            self.event_generate('<<TreeviewPlay>>')
    
    def on_right_click(self, event):
        """Handle right-click events."""
        item = self.identify_row(event.y)
        if item:
            self.selection_set(item)
            self.event_generate('<<TreeviewContext>>')

class StreamManagerGUI:
    """Main GUI application for UDPXY stream management."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.channels: List[StreamChannel] = []
        self.checker = StreamChecker()
        self.is_checking = False
        self.mpv_path = self.find_mpv_path()
        self.mpv_process: Optional[subprocess.Popen] = None # To store the MPV process
        self.udpxy_scan_event = threading.Event() # For cancelling UDPXY scan
        self.udpxy_search_entry = None
        self.udpxy_progress_var = tk.DoubleVar()
        self.udpxy_progress_bar = None
        self.udpxy_status_label = None
        
        self.setup_window()
        self.create_widgets()
        self.setup_bindings()
    
    def find_mpv_path(self) -> Optional[str]:
        """Find MPV executable path relative to project directory."""
        # Get the directory where the script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Look for mpv in the same directory
        possible_paths = [
            os.path.join(script_dir, 'mpv.exe'),  # Windows
            os.path.join(script_dir, 'mpv'),      # Linux/Mac
            os.path.join(script_dir, 'mpv', 'mpv.exe'),  # Windows in subfolder
            os.path.join(script_dir, 'mpv', 'mpv'),      # Linux/Mac in subfolder
        ]
        
        for path in possible_paths:
            if os.path.isfile(path):
                return path
        
        # If not found locally, try system PATH
        try:
            result = subprocess.run(['which', 'mpv'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        # Try Windows where
        try:
            result = subprocess.run(['where', 'mpv'], capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except:
            pass
        
        return None
    
    def setup_window(self):
        """Configure main window properties."""
        self.root.title("UDPXY Stream Manager Pro")
        self.root.geometry("1200x700")
        self.root.minsize(800, 500)
        self.root.configure(bg='#f8f9fa')
        
        # Center window on screen
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (self.root.winfo_width() // 2)
        y = (self.root.winfo_screenheight() // 2) - (self.root.winfo_height() // 2)
        self.root.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        """Create and layout all GUI widgets."""
        self.create_menubar()
        self.create_toolbar()
        self.create_main_frame()
        self.create_status_bar()
    
    def create_menubar(self):
        """Create application menu bar."""
        menubar = Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Playlist", command=self.new_playlist, accelerator="Ctrl+N")
        file_menu.add_command(label="Open Playlist", command=self.load_playlist, accelerator="Ctrl+O")
        file_menu.add_command(label="Save Playlist", command=self.save_playlist, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As...", command=self.save_playlist_as, accelerator="Ctrl+Shift+S")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")
        
        # Edit menu
        edit_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Add Channel", command=self.add_channel, accelerator="Ctrl+Shift+A")
        edit_menu.add_command(label="Edit Channel", command=self.edit_channel, accelerator="Ctrl+E")
        edit_menu.add_command(label="Delete Channel", command=self.delete_channel, accelerator="Delete")
        edit_menu.add_separator()
        edit_menu.add_command(label="Move Up", command=self.move_channels_up, accelerator="Ctrl+Up")
        edit_menu.add_command(label="Move Down", command=self.move_channels_down, accelerator="Ctrl+Down")
        edit_menu.add_separator()
        edit_menu.add_command(label="Select All", command=self.select_all, accelerator="Ctrl+A")
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Play with MPV", command=self.play_with_mpv, accelerator="Enter")
        tools_menu.add_separator()
        tools_menu.add_command(label="Check Selected", command=self.check_selected, accelerator="F5")
        tools_menu.add_command(label="Check All", command=self.check_all, accelerator="Ctrl+F5")
        tools_menu.add_command(label="Clear Status", command=self.clear_status)
    
    def create_toolbar(self):
        """Create toolbar with action buttons."""
        toolbar = tk.Frame(self.root, bg='#e9ecef', height=50)
        toolbar.pack(fill=tk.X, padx=5, pady=2)
        toolbar.pack_propagate(False)
        
        # Button style configuration
        button_style = {'font': ('Segoe UI', 9), 'padx': 15, 'pady': 5, 'relief': 'flat', 'bd': 1}
        
        # File operations
        tk.Button(toolbar, text="📂 Открыть", command=self.load_playlist, 
                 bg='#007bff', fg='white', **button_style).pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="💾 Сохранить", command=self.save_playlist, 
                 bg='#28a745', fg='white', **button_style).pack(side=tk.LEFT, padx=2)
        
        # Channel operations
        tk.Button(toolbar, text="➕ Добавить", command=self.add_channel, 
                 bg='#17a2b8', fg='white', **button_style).pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="✏️ Изменить", command=self.edit_channel, 
                 bg='#ffc107', fg='black', **button_style).pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="🗑️ Удалить", command=self.delete_channel, 
                 bg='#dc3545', fg='white', **button_style).pack(side=tk.LEFT, padx=2)
        
        # Movement operations
        tk.Button(toolbar, text="⬆️ Вверх", command=self.move_channels_up, 
                 bg='#6c757d', fg='white', **button_style).pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="⬇️ Вниз", command=self.move_channels_down, 
                 bg='#6c757d', fg='white', **button_style).pack(side=tk.LEFT, padx=2)
        
        # Play button
        mpv_status = "▶️ Воспроизвести" if self.mpv_path else "❌ MPV"
        tk.Button(toolbar, text=mpv_status, command=self.play_with_mpv, 
                 bg='#e91e63', fg='white', **button_style).pack(side=tk.LEFT, padx=10)
        
        # Check operations
        tk.Button(toolbar, text="🔍 Проверить выбранные", command=self.check_selected, 
                 bg='#6f42c1', fg='white', **button_style).pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="🔍 Проверить все", command=self.check_all, 
                 bg='#6f42c1', fg='white', **button_style).pack(side=tk.LEFT, padx=2)
        
        # UDPXY Scanner elements
        tk.Label(toolbar, text="UDPXY Диапазон:", font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(10,2))
        self.udpxy_search_entry = tk.Entry(toolbar, width=20, font=('Segoe UI', 9))
        self.udpxy_search_entry.insert(0, "192.168.1.0/24") # Default value
        self.udpxy_search_entry.pack(side=tk.LEFT, padx=2)
        
        tk.Button(toolbar, text="⚡ Сканировать UDPXY", command=self.start_udpxy_scan, 
                 bg='#00aced', fg='white', **button_style).pack(side=tk.LEFT, padx=2)
        
        tk.Button(toolbar, text="✖️ Отменить сканирование", command=self.cancel_udpxy_scan, 
                 bg='#ff6347', fg='white', **button_style).pack(side=tk.LEFT, padx=2)
        
        # New: Auto-Scan UDPXY button
        tk.Button(toolbar, text="🌐 Авто-сканирование UDPXY", command=self.auto_scan_udpxy,
                 bg='#8a2be2', fg='white', **button_style).pack(side=tk.LEFT, padx=10)
        
        # New: Multicast URL for verification
        tk.Label(toolbar, text="Мультикаст для проверки:", font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(10,2))
        self.multicast_verify_entry = tk.Entry(toolbar, width=30, font=('Segoe UI', 9))
        self.multicast_verify_entry.insert(0, "235.10.10.17:1234") # Default multicast for verification
        self.multicast_verify_entry.pack(side=tk.LEFT, padx=2)
        
        self.udpxy_progress_bar = ttk.Progressbar(toolbar, variable=self.udpxy_progress_var, 
                                                   mode='determinate', length=150)
        self.udpxy_progress_bar.pack(side=tk.LEFT, padx=10)
        
        self.udpxy_status_label = tk.Label(toolbar, text="", bg='#e9ecef', font=('Segoe UI', 9))
        self.udpxy_status_label.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(toolbar, variable=self.progress_var, 
                                           mode='determinate', length=200)
        self.progress_bar.pack(side=tk.RIGHT, padx=10)
    
    def create_main_frame(self):
        """Create main content frame with channel list."""
        main_frame = tk.Frame(self.root, bg='#f8f9fa')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview with scrollbars
        tree_frame = tk.Frame(main_frame, bg='white', relief='sunken', bd=1)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview с дополнительной колонкой для группы
        columns = ('Name', 'URL', 'Group', 'Status', 'Last Checked')
        self.tree = ModernTreeview(tree_frame, columns=columns, show='tree headings', height=15)
        
        # Configure columns
        self.tree.heading('#0', text='#')
        self.tree.column('#0', width=50, minwidth=50)
        
        column_widths = {'Name': 200, 'URL': 250, 'Group': 120, 'Status': 100, 'Last Checked': 120}
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=column_widths.get(col, 150), minwidth=80)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    def create_status_bar(self):
        """Create status bar with information display."""
        self.status_bar = tk.Frame(self.root, bg='#e9ecef', relief='sunken', bd=1)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_text = tk.Label(self.status_bar, text="Готов", bg='#e9ecef', 
                                   anchor=tk.W, font=('Segoe UI', 9))
        self.status_text.pack(side=tk.LEFT, padx=5)
        
        # MPV status
        mpv_text = f"MPV: {self.mpv_path}" if self.mpv_path else "MPV: Не найден"
        self.mpv_status = tk.Label(self.status_bar, text=mpv_text, bg='#e9ecef',
                                  font=('Segoe UI', 9))
        self.mpv_status.pack(side=tk.LEFT, padx=20)
        
        self.channel_count = tk.Label(self.status_bar, text="Каналов: 0", bg='#e9ecef',
                                     font=('Segoe UI', 9))
        self.channel_count.pack(side=tk.RIGHT, padx=5)
    
    def setup_bindings(self):
        """Setup keyboard shortcuts and event bindings."""
        # Keyboard shortcuts
        self.root.bind('<Control-n>', lambda e: self.new_playlist())
        self.root.bind('<Control-o>', lambda e: self.load_playlist())
        self.root.bind('<Control-s>', lambda e: self.save_playlist())
        self.root.bind('<Control-Shift-S>', lambda e: self.save_playlist_as())
        self.root.bind('<Control-a>', lambda e: self.add_channel())
        self.root.bind('<Control-e>', lambda e: self.edit_channel())
        self.root.bind('<Delete>', lambda e: self.delete_channel())
        self.root.bind('<F5>', lambda e: self.check_selected())
        self.root.bind('<Control-F5>', lambda e: self.check_all())
        self.root.bind('<Return>', lambda e: self.play_with_mpv())
        self.root.bind('<KP_Enter>', lambda e: self.play_with_mpv())
        
        # Movement shortcuts
        # Adjusted bindings to pass the event object, though not strictly needed by the methods themselves,
        # it's good practice for event handlers.
        self.root.bind('<Control-Up>', self.move_channels_up)
        self.root.bind('<Control-Down>', self.move_channels_down)
        
        # Tree events
        self.tree.bind('<<TreeviewPlay>>', lambda e: self.play_with_mpv())
        self.tree.bind('<<TreeviewContext>>', self.show_context_menu)
        
        # Tree focus bindings
        self.tree.bind('<Return>', lambda e: self.play_with_mpv())
        self.tree.bind('<KP_Enter>', lambda e: self.play_with_mpv())

        # Bind Ctrl+Shift+A for Add Channel, and Ctrl+A for Select All
        self.root.bind('<Control-Shift-A>', lambda e: self.add_channel())
        self.root.bind('<Control-a>', lambda e: self.select_all())

        # New: F2 for Add Channel
        self.root.bind('<F2>', lambda e: self.add_channel())
        # New: F4 for Edit Channel
        self.root.bind('<F4>', lambda e: self.edit_channel())
    
    def update_status(self, message: str):
        """Update status bar message."""
        self.status_text.config(text=message)
        self.root.update_idletasks()
    
    def update_channel_count(self):
        """Update channel count display."""
        count = len(self.channels)
        active = sum(1 for ch in self.channels if ch.status is True)
        self.channel_count.config(text=f"Каналов: {count} | Активных: {active}")
    
    def refresh_tree(self):
        """Refresh the treeview with current channel data."""
        # Store current selection to restore it later
        selected_urls = set()
        for item_id in self.tree.selection():
            try:
                # Assuming URL is unique and is in the second column
                selected_urls.add(self.tree.item(item_id, 'values')[1])
            except IndexError:
                continue

        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add channels
        new_selection_ids = []
        for i, channel in enumerate(self.channels, 1):
            status_text = "✅ Активный" if channel.status is True else "❌ Неактивный" if channel.status is False else "⏳ Неизвестно"
            last_checked = time.strftime('%H:%M:%S', time.localtime(channel.last_checked)) if channel.last_checked else "Никогда"
            
            item_id = self.tree.insert('', 'end', text=str(i), values=(
                channel.name, 
                channel.url, 
                channel.group or "—",
                status_text, 
                last_checked
            ))
            
            # Color coding based on status
            if channel.status is True:
                self.tree.item(item_id, tags=('active',))
            elif channel.status is False:
                self.tree.item(item_id, tags=('inactive',))
            
            # Check if this item should be re-selected
            if channel.url in selected_urls:
                new_selection_ids.append(item_id)

        # Configure tags
        self.tree.tag_configure('active', background='#d4edda')
        self.tree.tag_configure('inactive', background='#f8d7da')
        
        # Restore selection
        if new_selection_ids:
            self.tree.selection_set(new_selection_ids)
        
        self.update_channel_count()
    
    def play_with_mpv(self):
        """Play selected channel(s) with MPV."""
        if not self.mpv_path:
            messagebox.showerror("MPV Не найден", 
                               "MPV плеер не найден. Пожалуйста, поместите mpv.exe в ту же папку, что и это приложение.")
            return
        
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Нет выбора", "Пожалуйста, выберите канал для воспроизведения")
            return
        
        # Get selected channels
        selected_channels = []
        for item in selection:
            try:
                index = self.tree.index(item)
                selected_channels.append(self.channels[index])
            except (ValueError, IndexError):
                continue
        
        if not selected_channels:
            return
        
        # Terminate existing MPV process if any
        if self.mpv_process and self.mpv_process.poll() is None:
            self.update_status("Закрытие предыдущего потока MPV...")
            try:
                self.mpv_process.terminate()
                # Give it a moment to terminate gracefully
                for _ in range(5): # Check up to 5 times with 0.1 second delay
                    if self.mpv_process.poll() is not None:
                        break
                    time.sleep(0.1)
                
                if self.mpv_process.poll() is None: # If it's still running, kill it
                    self.mpv_process.kill()
                    self.update_status("Предыдущий поток MPV принудительно завершен.")
            except Exception as e:
                print(f"Ошибка при завершении предыдущего процесса MPV: {e}")
                self.update_status(f"Ошибка при завершении MPV: {e}")
            finally:
                self.mpv_process = None
        
        # Play channels
        for channel in selected_channels:
            try:
                # Construct the command as a list of arguments for Popen
                # This is generally safer than shell=True and gives better process control.
                cmd = [self.mpv_path, f'--title=Поток: {channel.name}', channel.url]
                
                # Start MPV process and store its reference
                self.mpv_process = subprocess.Popen(cmd, 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                
                self.update_status(f"Запущен MPV для: {channel.name}")
                
            except Exception as e:
                messagebox.showerror("Ошибка MPV", f"Не удалось запустить MPV для {channel.name}: {str(e)}")
    
    def move_channels_up(self, event=None):
        """
        Move selected channels up in the list, handling multiple selections correctly.
        """
        selection = self.tree.selection()
        if not selection:
            return

        # Get indices of selected items and sort them
        indices = sorted([self.tree.index(item) for item in selection])
        
        # If the topmost selected item is already at the top, or no items are selected, do nothing
        if not indices or indices[0] == 0:
            return

        # Extract the channel objects to be moved
        channels_to_move = [self.channels[i] for i in indices]

        # Remove selected channels from the original list (iterate in reverse to avoid index issues)
        for i in reversed(indices):
            del self.channels[i]

        # Calculate the new insertion position for the block of channels
        # It's one position above the original topmost selected item's index
        new_pos = indices[0] - 1

        # Insert the block of channels at the new position, maintaining their relative order
        for i, channel in enumerate(channels_to_move):
            self.channels.insert(new_pos + i, channel)

        # Refresh the treeview to reflect the changes
        self.refresh_tree()

        # Re-select the moved items at their new positions
        new_item_ids_to_select = []
        children = self.tree.get_children() # Get all current item IDs in the treeview
        for i in range(new_pos, new_pos + len(channels_to_move)):
            if i < len(children): # Ensure the index is within the bounds of the new children list
                new_item_ids_to_select.append(children[i])
        
        if new_item_ids_to_select:
            self.tree.selection_set(new_item_ids_to_select)
            # Scroll to make the first moved item visible
            self.tree.see(new_item_ids_to_select[0])
    
    def move_channels_down(self, event=None):
        """
        Move selected channels down in the list, handling multiple selections correctly.
        """
        selection = self.tree.selection()
        if not selection:
            return

        # Get indices of selected items and sort them
        # For moving down, sorting is still ascending, but we check the last item's boundary
        indices = sorted([self.tree.index(item) for item in selection])

        # If the bottommost selected item is already at the bottom, or no items are selected, do nothing
        if not indices or indices[-1] == len(self.channels) - 1:
            return

        # Extract the channel objects to be moved
        channels_to_move = [self.channels[i] for i in indices]

        # Remove selected channels from the original list (iterate in reverse to avoid index issues)
        for i in reversed(indices):
            del self.channels[i]

        # Calculate the new insertion position for the block of channels
        # It's one position below the original topmost selected item's index,
        # relative to the *shrunk* list after deletions.
        # The new position for the first item will be its original index + 1
        new_pos = indices[0] + 1 

        # Insert the block of channels at the new position, maintaining their relative order
        for i, channel in enumerate(channels_to_move):
            self.channels.insert(new_pos + i, channel)

        # Refresh the treeview to reflect the changes
        self.refresh_tree()

        # Re-select the moved items at their new positions
        new_item_ids_to_select = []
        children = self.tree.get_children() # Get all current item IDs in the treeview
        for i in range(new_pos, new_pos + len(channels_to_move)):
             if i < len(children): # Ensure the index is within the bounds of the new children list
                new_item_ids_to_select.append(children[i])

        if new_item_ids_to_select:
            self.tree.selection_set(new_item_ids_to_select)
            # Scroll to make the last moved item visible
            self.tree.see(new_item_ids_to_select[-1])
    
    def new_playlist(self):
        """Create new empty playlist."""
        if self.channels and messagebox.askyesno("Новый плейлист", "Отменить текущий плейлист?"):
            self.channels.clear()
            self.refresh_tree()
            self.update_status("Создан новый плейлист")
    
    def load_playlist(self):
        """Load playlist from M3U or JSON file."""
        file_path = filedialog.askopenfilename(
            title="Открыть плейлист",
            filetypes=[
                ("M3U files", "*.m3u"),
                ("M3U8 files", "*.m3u8"), 
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Определяем тип файла по расширению
            if file_path.lower().endswith(('.m3u', '.m3u8')):
                # Basic M3U parsing
                channels_data = self.parse_m3u(content)
                self.channels = [
                    StreamChannel(
                        name=ch['name'],
                        url=ch['url'],
                        group=ch.get('group', ''),
                        logo=ch.get('logo', '')
                    ) for ch in channels_data
                ]
            else:
                # Парсим JSON
                data = json.loads(content)
                # Проверяем, является ли корневой элемент словарем с ключом 'channels'
                if isinstance(data, dict) and 'channels' in data and isinstance(data['channels'], list):
                    self.channels = [StreamChannel.from_dict(ch) for ch in data.get('channels', [])]
                elif isinstance(data, list): # Если JSON - это просто список каналов
                    self.channels = [StreamChannel.from_dict(ch) for ch in data]
                else:
                    raise ValueError("Неподдерживаемая структура JSON-файла.")

            self.refresh_tree()
            self.update_status(f"Загружено {len(self.channels)} каналов из {file_path}")
        
        except json.JSONDecodeError as e:
            messagebox.showerror("Ошибка JSON", f"Ошибка декодирования JSON: {e}\nУбедитесь, что файл является действительным JSON.")
        except ValueError as e:
            messagebox.showerror("Ошибка загрузки", f"Ошибка загрузки плейлиста: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить плейлист: {str(e)}")
    
    def parse_m3u(self, content: str) -> List[Dict]:
        """Simple M3U parser."""
        channels = []
        lines = content.strip().split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            if line.startswith('#EXTINF:'):
                # Parse EXTINF line
                name = line.split(',', 1)[-1] if ',' in line else "Unknown"
                group = ""
                logo = ""
                
                # Extract group and logo from attributes
                if 'group-title=' in line:
                    group = line.split('group-title="')[1].split('"')[0]
                if 'tvg-logo=' in line:
                    logo = line.split('tvg-logo="')[1].split('"')[0]
                
                # Get URL from next line
                if i + 1 < len(lines):
                    url = lines[i + 1].strip()
                    if url and not url.startswith('#'):
                        channels.append({
                            'name': name,
                            'url': url,
                            'group': group,
                            'logo': logo
                        })
                        i += 1
            
            i += 1
        
        return channels

    def save_playlist(self):
        """Save current playlist to M3U or JSON file."""
        file_path = filedialog.asksaveasfilename(
            title="Сохранить плейлист",
            filetypes=[
                ("M3U files", "*.m3u"),
                ("M3U8 files", "*.m3u8"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ],
            defaultextension=".m3u"
        )
        
        if not file_path:
            return
        
        try:
            # Определяем тип файла по расширению
            if file_path.lower().endswith(('.m3u', '.m3u8')):
                # Save as M3U
                content = self.generate_m3u()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            else:
                # Save as JSON
                data = {
                    'channels': [ch.to_dict() for ch in self.channels],
                    'saved_at': time.time()
                }
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            
            self.update_status(f"Сохранено {len(self.channels)} каналов в {file_path}")
        
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить плейлист: {str(e)}")
    
    def generate_m3u(self) -> str:
        """Generate M3U content from channels."""
        lines = ["#EXTM3U"]
        
        for channel in self.channels:
            extinf = f"#EXTINF:-1"
            if channel.group:
                extinf += f' group-title="{channel.group}"'
            if channel.logo:
                extinf += f' tvg-logo="{channel.logo}"'
            extinf += f",{channel.name}"
            
            lines.append(extinf)
            lines.append(channel.url)
        
        return '\n'.join(lines)
    
    def save_playlist_as(self):
        """Save playlist with new filename."""
        self.save_playlist()
    
    def add_channel(self):
        """Add new channel via dialog."""
        dialog = ChannelDialog(self.root, "Добавить канал")
        if dialog.result:
            channel = StreamChannel(
                name=dialog.result['name'], 
                url=dialog.result['url'],
                group=dialog.result.get('group', '')
            )
            self.channels.append(channel)
            self.refresh_tree()
            self.update_status(f"Добавлен канал: {channel.name}")

    def edit_channel(self):
        """Edit selected channel."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Нет выбора", "Пожалуйста, выберите канал для редактирования")
            return
        
        item = selection[0]
        index = self.tree.index(item)
        channel = self.channels[index]
        
        dialog = ChannelDialog(self.root, "Изменить канал", channel.name, channel.url, channel.group)
        if dialog.result:
            channel.name = dialog.result['name']
            channel.url = dialog.result['url']
            channel.group = dialog.result.get('group', '')
            channel.status = None
            channel.last_checked = None
            self.refresh_tree()
            self.update_status(f"Обновлен канал: {channel.name}")

    def delete_channel(self):
        """Delete selected channel(s)."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Нет выбора", "Пожалуйста, выберите канал(ы) для удаления")
            return
        
        indices = sorted([self.tree.index(item) for item in selection])
        
        if not indices:
            return
        
        count = len(indices)
        if not messagebox.askyesno("Подтвердить удаление", f"Удалить {count} канал(ов)?"):
            return
        
        for index in reversed(indices):
            del self.channels[index]
        
        self.refresh_tree()
        self.update_status(f"Удалено {count} канал(ов)")

    def check_selected(self):
        """Check status of selected channels."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Нет выбора", "Пожалуйста, выберите каналы для проверки")
            return
        
        selected_channels = []
        for item in selection:
            try:
                index = self.tree.index(item)
                selected_channels.append(self.channels[index])
            except (ValueError, IndexError):
                continue
        
        if not selected_channels:
            return
        
        self.check_channels(selected_channels, sequential=False)

    def check_all(self):
        """Check status of all channels and discover new ones."""
        if not self.channels:
            messagebox.showwarning("Нет каналов", "Нет каналов для проверки или использования в качестве шаблона для обнаружения. Пожалуйста, сначала загрузите плейлист.")
            return
        
        self.check_channels(self.channels, sequential=True, discover=True)

    def check_channels(self, channels: List[StreamChannel], sequential: bool = False, discover: bool = False):
        """Check status of specified channels, with options for sequential checking and discovery."""
        if self.is_checking:
            messagebox.showwarning("Уже проверяется", "Проверка каналов уже выполняется")
            return
        
        self.is_checking = True
        self.progress_var.set(0)
        self.update_status(f"Проверка {len(channels)} каналов...")
        
        if sequential:
            worker_target = self._sequential_check_worker
            args = (channels, discover)
        else:
            worker_target = self._parallel_check_worker
            args = (channels,)
        
        threading.Thread(target=worker_target, args=args, daemon=True).start()

    def _update_ui_for_sequential_check(self, current_idx: int, total: int, channel_name: str, is_discovery: bool):
        """Helper to update UI from the sequential worker."""
        progress = ((current_idx + 1) / total) * 100
        self.progress_var.set(progress)
        
        status_msg = f"Обнаружение: {channel_name}" if is_discovery else f"Проверено {current_idx+1}/{total}: {channel_name}"
        self.update_status(status_msg)
        
        # Refresh tree only if a new channel was added or an existing one's status changed
        # This is handled by a separate call after adding a new channel or at finish_check
        # For sequential checks, we refresh at the end to avoid flickering.
        # However, for discovery, we need to add new channels as they are found.
        # This is why the `append` is done via `self.root.after`
        # self.refresh_tree() 

    def _get_discovery_params(self) -> Tuple[Optional[str], Optional[str], Set[str]]:
        """
        Analyzes the current playlist to find a template for discovering new channels.
        Returns a tuple of (base_template, port, existing_urls_set).
        Example: ('http://.../udp/239.1.1.', '1234', {'http://.../udp/239.1.1.67:1234'})
        """
        if not self.channels:
            return None, None, set()

        template_url = None
        for ch in self.channels:
            # Look for URLs that are UDPXY-proxied multicast streams
            if '/udp/' in ch.url and re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/udp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', ch.url):
                template_url = ch.url
                break
        
        if not template_url:
            return None, None, set()

        # Extract the base UDPXY part, the first three octets of the multicast IP, and the port
        match = re.search(r'^(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/udp/)(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}:(\d+)$', template_url)
        if not match:
            return None, None, set()

        udpxy_base = match.group(1) # e.g., "http://192.168.1.1:8080/udp/"
        multicast_ip_prefix = match.group(2) # e.g., "239.1.1."
        port = match.group(3) # e.g., "1234"
        
        base_template = f"{udpxy_base}{multicast_ip_prefix}"
        existing_urls = {ch.url for ch in self.channels}
        
        return base_template, port, existing_urls

    def _sequential_check_worker(self, channels_to_check: List[StreamChannel], discover: bool = False):
        """Worker for sequential channel checking, with optional discovery."""
        try:
            items_to_process: List[Union[StreamChannel, str]] = list(channels_to_check)
            
            # Prepare a set of current URLs for quick lookup to avoid adding duplicates
            current_playlist_urls = {ch.url for ch in self.channels}

            if discover:
                base_template, port, _ = self._get_discovery_params() # _ is existing_urls, we use current_playlist_urls for real-time check
                if base_template and port:
                    self.root.after(0, lambda: self.update_status("Подготовка к обнаружению каналов..."))
                    # Add potential new channels to items_to_process
                    for i in range(1, 256): # Iterate for the last octet from 1 to 255
                        # Reconstruct the multicast IP part using the prefix and the current octet 'i'
                        # The base_template already contains "http://udpxy_ip:port/udp/multicast_prefix."
                        new_url = f"{base_template}{i}:{port}"
                        
                        if new_url not in current_playlist_urls: # Check against the current state of the playlist
                            items_to_process.append(new_url)
                            # Add to current_playlist_urls immediately to prevent adding duplicates within this scan
                            current_playlist_urls.add(new_url) 
                else:
                    self.root.after(0, lambda: self.update_status("Обнаружение пропущено: В плейлисте не найден подходящий URL мультикаста для создания шаблона."))
                    self.root.after(0, lambda: messagebox.showinfo("Информация об обнаружении", "Обнаружение пропущено: В вашем плейлисте не найден подходящий URL мультикаста UDPXY (например, http://IP:PORT/udp/MULTICAST_IP:PORT) для создания шаблона для новых каналов."))

            total = len(items_to_process)
            
            for i, item in enumerate(items_to_process):
                # Check for cancellation
                if self.udpxy_scan_event.is_set(): # Using the same event for general cancellation
                    self.root.after(0, lambda: self.update_status("Проверка каналов отменена."))
                    break

                is_new_discovery = isinstance(item, str) # True if this is a newly generated URL
                url_to_check = item if is_new_discovery else item.url
                
                channel_name = ""
                if is_new_discovery:
                    # Extract the multicast IP:Port part for display
                    multicast_ip_port_match = re.search(r'/udp/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)$', url_to_check)
                    if multicast_ip_port_match:
                        channel_name = f"Обнаружено {multicast_ip_port_match.group(1)}"
                    else:
                        channel_name = f"Обнаруженный канал {i+1}" # Fallback name
                else:
                    channel_name = item.name

                self.root.after(0, lambda idx=i, name=channel_name, new=is_new_discovery: self._update_ui_for_sequential_check(idx, total, name, new))

                status = self.checker.check_stream(url_to_check)
                
                if is_new_discovery:
                    if status:
                        new_channel = StreamChannel(
                            name=channel_name,
                            url=url_to_check,
                            status=True,
                            last_checked=time.time(),
                            group="Обнаруженные" # Assign a default group for discovered channels
                        )
                        # Add the new channel to the main list on the UI thread
                        self.root.after(0, lambda ch=new_channel: self.channels.append(ch))
                        self.root.after(0, self.refresh_tree) # Refresh immediately to show new channel
                else:
                    # Update status for existing channels
                    item.status = status
                    item.last_checked = time.time()
                    # For existing channels, refresh will happen at the end for performance.

                time.sleep(0.1) # Small delay to avoid overwhelming the network/UI

            self.root.after(0, self.finish_check)
        except Exception as e:
            self.root.after(0, lambda: self.handle_check_error(str(e)))

    def _parallel_check_worker(self, channels_to_check: List[StreamChannel]):
        """Worker for fast, parallel channel checking."""
        try:
            def progress_callback(completed, total):
                progress = (completed / total) * 100
                self.progress_var.set(progress)
                self.root.update_idletasks()

            results = self.checker.batch_check(channels_to_check, progress_callback=progress_callback)
            
            for channel in channels_to_check:
                if channel.url in results:
                    channel.status = results[channel.url]
                    channel.last_checked = time.time()
            
            self.root.after(0, self.finish_check)
        except Exception as e:
            self.root.after(0, lambda: self.handle_check_error(str(e)))

    def finish_check(self):
        """Finish channel checking process."""
        self.is_checking = False
        self.progress_var.set(0)
        self.refresh_tree() # Final refresh to update all statuses
        
        active = sum(1 for ch in self.channels if ch.status is True)
        inactive = sum(1 for ch in self.channels if ch.status is False)
        
        self.update_status(f"Проверка завершена: {active} активных, {inactive} неактивных")

    def handle_check_error(self, error_msg):
        """Handle errors during channel checking."""
        self.is_checking = False
        self.progress_var.set(0)
        self.update_status("Проверка не удалась")
        messagebox.showerror("Ошибка проверки", f"Не удалось проверить каналы: {error_msg}")

    def clear_status(self):
        """Clear all channel statuses."""
        for channel in self.channels:
            channel.status = None
            channel.last_checked = None
        
        self.refresh_tree()
        self.update_status("Статусы каналов очищены")

    def select_all(self):
        """Select all channels in the tree."""
        for item in self.tree.get_children():
            self.tree.selection_add(item)

    def show_context_menu(self, event):
        """Show context menu for treeview."""
        context_menu = Menu(self.root, tearoff=0)
        
        if self.mpv_path:
            context_menu.add_command(label="Воспроизвести с MPV", command=self.play_with_mpv)
            context_menu.add_separator()
        
        context_menu.add_command(label="Изменить канал", command=self.edit_channel)
        context_menu.add_command(label="Удалить канал", command=self.delete_channel)
        context_menu.add_separator()
        context_menu.add_command(label="Проверить статус", command=self.check_selected)
        context_menu.add_separator()
        context_menu.add_command(label="Переместить вверх", command=self.move_channels_up)
        context_menu.add_command(label="Переместить вниз", command=self.move_channels_down)
        
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()

    def _update_udpxy_status_label(self, message: str):
        """Update the UDPXY scan status label."""
        self.udpxy_status_label.config(text=message)
        self.root.update_idletasks()

    def start_udpxy_scan(self):
        """Initiate the UDPXY server scan."""
        if self.udpxy_scan_event.is_set():
            messagebox.showwarning("Сканирование в процессе", "Сканирование UDPXY уже выполняется. Пожалуйста, подождите или отмените его.")
            return
        
        search_range_str = self.udpxy_search_entry.get().strip()
        if not search_range_str:
            messagebox.showerror("Ошибка ввода", "Пожалуйста, введите диапазон IP (например, 192.168.1.0/24).")
            return
            
        try:
            network = ipaddress.ip_network(search_range_str, strict=False)
        except ValueError:
            messagebox.showerror("Ошибка ввода", "Неверный формат диапазона IP. Используйте нотацию CIDR (например, 192.168.1.0/24).")
            return
            
        self.udpxy_scan_event.clear()
        self.udpxy_progress_var.set(0)
        self._update_udpxy_status_label("Сканирование...")
        
        threading.Thread(target=self._find_udpxy_servers_in_range_worker, 
                         args=(network, self.udpxy_scan_event), 
                         daemon=True).start()

    def cancel_udpxy_scan(self):
        """Cancel the ongoing UDPXY server scan."""
        if not self.udpxy_scan_event.is_set():
            self.udpxy_scan_event.set()
            self._update_udpxy_status_label("Сканирование отменено.")
            messagebox.showinfo("Сканирование отменено", "Сканирование сервера UDPXY было отменено.")
        else:
            messagebox.showinfo("Нет сканирования", "В настоящее время активное сканирование UDPXY отсутствует.")

    def _find_udpxy_servers_in_range_worker(self, network: ipaddress.IPv4Network, cancel_event: threading.Event, progress_callback: Optional[Callable[[float], None]] = None) -> Tuple[List[str], int]:
        """Worker function to find working UDPXY servers in a given IP range."""
        found_servers = []
        common_udpxy_ports = [8080, 81, 8000]
        timeout = 1.0
        
        ips_to_check = []
        for ip_obj in network.hosts():
            for port in common_udpxy_ports:
                ips_to_check.append((str(ip_obj), port))
                
        total_combinations = len(ips_to_check)
        completed_checks = 0
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip_port = {
                executor.submit(StreamChecker.check_udpxy_server, ip, port, timeout): (ip, port)
                for ip, port in ips_to_check
                if not cancel_event.is_set()
            }
            
            for future in as_completed(future_to_ip_port):
                if cancel_event.is_set():
                    for f in future_to_ip_port:
                        f.cancel()
                    return found_servers, completed_checks
                    
                ip, port = future_to_ip_port[future]
                is_working = future.result()
                completed_checks += 1
                
                if progress_callback and total_combinations > 0:
                    current_block_progress = (completed_checks / total_combinations) * 100
                    progress_callback(current_block_progress)
                
                if is_working:
                    found_servers.append(f"{ip}:{port}")
                    
        return found_servers, completed_checks

    def _display_udpxy_results(self, servers: List[str]):
        """Display the found UDPXY servers in a message box and offer to copy them."""
        if not servers:
            return

        results_message = "Найденные UDPXY серверы:\n" + "\n".join(servers)
        
        results_window = tk.Toplevel(self.root)
        results_window.title("Результаты сканирования UDPXY")
        results_window.transient(self.root)
        results_window.grab_set()
        
        text_frame = tk.Frame(results_window)
        text_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        text_widget = tk.Text(text_frame, wrap=tk.WORD, height=15, width=60)
        text_widget.insert(tk.END, results_message)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(text_frame, command=text_widget.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.config(yscrollcommand=scrollbar.set)

        def copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(servers))
            messagebox.showinfo("Скопировано", "Список серверов UDPXY скопирован в буфер обмена!")
            results_window.destroy()

        copy_button = tk.Button(results_window, text="Скопировать в буфер обмена", command=copy_to_clipboard)
        copy_button.pack(pady=5)

        close_button = tk.Button(results_window, text="Закрыть", command=results_window.destroy)
        close_button.pack(pady=5)

        results_window.protocol("WM_DELETE_WINDOW", results_window.destroy)
        results_window.wait_window()

    def _get_public_ip(self) -> Optional[str]:
        """Attempts to get the current public IP address."""
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            response.raise_for_status()
            return response.json()['ip']
        except requests.RequestException as e:
            print(f"Error getting public IP: {e}")
            return None

    def auto_scan_udpxy(self):
        """Automatically scan for UDPXY servers based on public IP and ISP blocks."""
        if self.udpxy_scan_event.is_set():
            messagebox.showwarning("Сканирование в процессе", "Сканирование UDPXY уже выполняется. Пожалуйста, подождите или отмените его.")
            return
        
        self.udpxy_scan_event.clear()
        self.udpxy_progress_var.set(0)
        self._update_udpxy_status_label("Определение провайдера и блоков...")
        
        threading.Thread(target=self._auto_scan_udpxy_worker, daemon=True).start()

    def _auto_scan_udpxy_worker(self):
        """Worker function for automatic UDPXY scanning with detailed progress and verification."""
        progress_dialog = None
        try:
            # Stage 0: Initialize Progress Dialog
            self.root.after(0, lambda: self._update_udpxy_status_label("Запуск авто-сканирования..."))
            progress_dialog = ProgressDialog(self.root, "Прогресс авто-сканирования UDPXY")
            progress_dialog.append_message("Запуск авто-сканирования UDPXY...")

            # Determine Multicast URL from selected channel or input field
            multicast_stream: Optional[M3UStream] = None
            selected_item = self.tree.selection() # Get selected item from the main treeview

            if selected_item:
                progress_dialog.append_message("Выбран канал. Попытка получить мультикаст из него.")
                try:
                    # Get the selected channel object
                    index = self.tree.index(selected_item[0])
                    selected_channel = self.channels[index]
                    progress_dialog.append_message(f"  URL выбранного канала: {selected_channel.url}")
                    
                    # Attempt to parse multicast IP and port from channel URL
                    match = re.search(r'/udp/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$', selected_channel.url)
                    if match:
                        multicast_ip = match.group(1)
                        multicast_port = int(match.group(2))
                        multicast_stream = M3UStream(multicast_ip, multicast_port)
                        progress_dialog.append_message(f"  ✅ Успешно разобран мультикаст из выбранного канала: {multicast_stream.ip}:{multicast_stream.port}")
                        self.root.after(0, lambda: self.multicast_verify_entry.delete(0, tk.END))
                        self.root.after(0, lambda: self.multicast_verify_entry.insert(0, f"{multicast_stream.ip}:{multicast_stream.port}"))
                    else:
                        progress_dialog.append_message("  ❌ URL выбранного канала не содержит действительного мультикаст-потока (например, формат /udp/IP:PORT не найден). Используется ручной ввод.")
                except (IndexError, ValueError, AttributeError) as e:
                    progress_dialog.append_message(f"  ❌ Ошибка получения мультикаста из выбранного канала: {e}. Используется ручной ввод.")
            else:
                progress_dialog.append_message("Канал не выбран. Используется поле ручного ввода для проверки мультикаста.")
            
            if not multicast_stream:
                multicast_url_str = self.multicast_verify_entry.get().strip()
                if not multicast_url_str:
                    self.root.after(0, lambda: messagebox.showerror("Ошибка ввода", "Пожалуйста, введите URL мультикаста для проверки или выберите канал с ним."))
                    progress_dialog.append_message("Ошибка: Требуется URL мультикаста.")
                    return

                multicast_ip_match = re.match(r'^\D*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$', multicast_url_str)
                if not multicast_ip_match:
                    self.root.after(0, lambda: messagebox.showerror("Ошибка ввода", "Неверный формат URL мультикаста. Используйте IP:PORT (например, 235.10.10.17:1234)."))
                    progress_dialog.append_message("Ошибка: Неверный формат URL мультикаста.")
                    return
                
                multicast_ip = multicast_ip_match.group(1)
                multicast_port = int(multicast_ip_match.group(2))
                multicast_stream = M3UStream(multicast_ip, multicast_port)
                progress_dialog.append_message(f"Используется мультикаст для проверки (из поля ввода): {multicast_stream.ip}:{multicast_stream.port}")

            target_ip_for_asn_lookup: Optional[str] = None
            if selected_item:
                try:
                    index = self.tree.index(selected_item[0])
                    selected_channel = self.channels[index]
                    udpxy_ip_match = re.match(r'^https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+/', selected_channel.url)
                    if udpxy_ip_match:
                        target_ip_for_asn_lookup = udpxy_ip_match.group(1)
                        progress_dialog.append_message(f"  Используется IP UDPXY из выбранного канала для поиска ASN: {target_ip_for_asn_lookup}")
                    else:
                        progress_dialog.append_message("  URL выбранного канала не содержит действительного IP UDPXY. Возврат к публичному IP для поиска ASN.")
                except (IndexError, ValueError, AttributeError) as e:
                    progress_dialog.append_message(f"  Ошибка извлечения IP UDPXY из выбранного канала: {e}. Возврат к публичному IP для поиска ASN.")
            
            if not target_ip_for_asn_lookup:
                progress_dialog.append_message("1. Нет IP UDPXY из канала. Получение публичного IP-адреса для поиска ASN...")
                public_ip = self._get_public_ip()
                if not public_ip:
                    self.root.after(0, lambda: messagebox.showerror("Ошибка авто-сканирования", "Не удалось определить публичный IP-адрес."))
                    progress_dialog.append_message("Ошибка: Не удалось определить публичный IP.")
                    return
                target_ip_for_asn_lookup = public_ip
                progress_dialog.append_message(f"   Публичный IP для поиска ASN: {public_ip}")

            progress_dialog.append_message(f"2. Разрешение информации об IP для {target_ip_for_asn_lookup}...")
            ip_resolver = EnhancedIPResolver()
            ip_info = ip_resolver.resolve_ip_info(target_ip_for_asn_lookup)
            
            if self.udpxy_scan_event.is_set():
                progress_dialog.append_message("Сканирование отменено.")
                return

            if not ip_info.asn:
                self.root.after(0, lambda: messagebox.showerror("Ошибка авто-сканирования", f"Не удалось определить ASN для {target_ip_for_asn_lookup}. Невозможно найти блоки IP."))
                progress_dialog.append_message("Ошибка: Не удалось определить ASN. Невозможно найти блоки IP.")
                return
            progress_dialog.append_message(f"   ISP: {ip_info.isp or 'Неизвестно'}, ASN: AS{ip_info.asn}")

            progress_dialog.append_message(f"3. Поиск IP-блоков для AS{ip_info.asn}...")
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                block_lookup = ISPBlockLookup()
                
                async def _lookup_blocks_async():
                    async with block_lookup:
                        return await block_lookup.lookup_ip_blocks(str(ip_info.asn))
                
                ip_blocks = loop.run_until_complete(_lookup_blocks_async())
                loop.close()
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Ошибка авто-сканирования", f"Не удалось найти IP-блоки: {e}"))
                progress_dialog.append_message(f"Ошибка: Не удалось найти IP-блоки: {e}")
                return
            
            if self.udpxy_scan_event.is_set():
                progress_dialog.append_message("Сканирование отменено.")
                return

            if not ip_blocks:
                self.root.after(0, lambda: messagebox.showinfo("Результаты авто-сканирования", "IP-блоки для вашего провайдера не найдены. Может потребоваться ручное сканирование."))
                progress_dialog.append_message("IP-блоки для вашего провайдера не найдены.")
                return
            
            progress_dialog.append_message("Открытие диалога выбора блоков...")
            self.root.after(0, progress_dialog.withdraw)

            selected_ip_blocks_from_dialog = []
            def open_block_selection_dialog():
                nonlocal selected_ip_blocks_from_dialog
                dialog = ScannedBlocksDialog(self.root, ip_blocks)
                selected_ip_blocks_from_dialog = dialog.result_blocks

            future = threading.Event()
            self.root.after(0, lambda: [open_block_selection_dialog(), future.set()])
            future.wait()

            self.root.after(0, progress_dialog.deiconify)

            if not selected_ip_blocks_from_dialog:
                progress_dialog.append_message("Выбор IP-блоков отменен пользователем.")
                self.root.after(0, lambda: messagebox.showinfo("Авто-сканирование отменено", "Выбор IP-блоков отменен. Авто-сканирование прервано."))
                return

            networks_to_scan = []
            for block in selected_ip_blocks_from_dialog:
                try:
                    networks_to_scan.append(ipaddress.ip_network(block, strict=False))
                except ValueError:
                    continue
            
            if not networks_to_scan:
                self.root.after(0, lambda: messagebox.showinfo("Результаты авто-сканирования", "Не выбраны действительные диапазоны IP для сканирования."))
                progress_dialog.append_message("Не выбраны действительные диапазоны IP для сканирования.")
                return
            
            display_range = ", ".join(str(net) for net in networks_to_scan)
            self.root.after(0, lambda: self.udpxy_search_entry.delete(0, tk.END))
            self.root.after(0, lambda: self.udpxy_search_entry.insert(0, display_range[:70] + "..." if len(display_range) > 70 else display_range))
            progress_dialog.append_message(f"   Найдено {len(networks_to_scan)} IP-блоков: {display_range[:50]}...")
            
            total_blocks = len(networks_to_scan)
            verified_udpxy_servers = []

            common_udpxy_ports = [8080, 81, 8000]
            total_combinations_to_check_overall = sum(len(list(network.hosts())) * len(common_udpxy_ports) for network in networks_to_scan)
            current_combinations_checked_overall = 0

            estimated_seconds = total_combinations_to_check_overall * 0.005
            estimated_time_str = ""
            if estimated_seconds < 60:
                estimated_time_str = f"{estimated_seconds:.0f} секунд"
            elif estimated_seconds < 3600:
                minutes = estimated_seconds // 60
                seconds = estimated_seconds % 60
                estimated_time_str = f"{int(minutes)} минут {int(seconds)} секунд"
            else:
                hours = estimated_seconds // 3600
                minutes = (estimated_seconds % 3600) // 60
                estimated_time_str = f"{int(hours)} часов {int(minutes)} минут"
            
            self.root.after(0, lambda: progress_dialog.update_estimated_time(estimated_time_str))
            progress_dialog.append_message(f"Предполагаемое время сканирования: {estimated_time_str}")

            progress_dialog.append_message(f"4. Запуск последовательного сканирования UDPXY ({total_blocks} блоков)...")

            for i, network in enumerate(networks_to_scan):
                if self.udpxy_scan_event.is_set():
                    progress_dialog.append_message("Сканирование отменено.")
                    break

                block_message = f"Сканирование блока {i+1}/{total_blocks}: {network}..."
                progress_dialog.append_message(f"   {block_message}")
                self.root.after(0, lambda msg=block_message: progress_dialog.update_block_status(msg))
                self.root.after(0, lambda: progress_dialog.update_block_progress(0))
                
                def per_block_progress_callback(value: float):
                    self.root.after(0, lambda: progress_dialog.update_block_progress(value))

                found_servers_in_block, num_checked_in_block = self._find_udpxy_servers_in_range_worker(
                    network, self.udpxy_scan_event, per_block_progress_callback
                )
                current_combinations_checked_overall += num_checked_in_block

                if total_combinations_to_check_overall > 0:
                    overall_progress = (current_combinations_checked_overall / total_combinations_to_check_overall) * 100
                else:
                    overall_progress = 100
                self.root.after(0, lambda: progress_dialog.update_overall_progress(overall_progress))

                if found_servers_in_block:
                    progress_dialog.append_message(f"     Найдено {len(found_servers_in_block)} потенциальных серверов UDPXY в {network}. Проверка...")
                    for udpxy_server in found_servers_in_block:
                        if self.udpxy_scan_event.is_set():
                            progress_dialog.append_message("Сканирование отменено во время проверки.")
                            break

                        udpxy_ip, udpxy_port_str = udpxy_server.split(':')
                        udpxy_port = int(udpxy_port_str)

                        progress_dialog.append_message(f"       Проверка {udpxy_server} с мультикастом {multicast_stream.ip}:{multicast_stream.port}...")
                        is_verified = StreamChecker.check_multicast_through_udpxy(
                            udpxy_ip, udpxy_port, multicast_stream
                        )
                        if is_verified:
                            verified_udpxy_servers.append(udpxy_server)
                            progress_dialog.append_message(f"         ✅ Найден проверенный сервер UDPXY: {udpxy_server}")
                            break 
                        else:
                            progress_dialog.append_message(f"         ❌ {udpxy_server} не прошел проверку с мультикастом.")
                else:
                    progress_dialog.append_message(f"     Потенциальные серверы UDPXY в {network} не найдены.")
                
                if verified_udpxy_servers:
                    progress_dialog.append_message("Остановка сканирования: Найден первый проверенный сервер UDPXY.")
                    break

            if self.udpxy_scan_event.is_set():
                final_message = "Авто-сканирование UDPXY отменено."
                self.root.after(0, lambda: self._update_udpxy_status_label("Авто-сканирование отменено."))
            elif verified_udpxy_servers:
                final_message = f"Авто-сканирование UDPXY завершено: Найдено {len(verified_udpxy_servers)} проверенных серверов UDPXY!\n\n" \
                                + "Проверенные серверы:\n" + "\n".join(verified_udpxy_servers)
                self.root.after(0, lambda: self._update_udpxy_status_label(f"Авто-сканирование завершено: Найдено {len(verified_udpxy_servers)} серверов."))
                
                first_verified_server = verified_udpxy_servers[0]
                apply_message = f"Найден проверенный сервер UDPXY: {first_verified_server}.\nВы хотите применить его ко всем каналам в текущем плейлисте?"
                
                self.root.after(0, lambda: progress_dialog.append_message(f"Требуется действие: {apply_message.replace('\n',' ')}"))
                
                apply_decision = threading.Event()
                apply_result = {"answer": False}
                
                def ask_and_set_result():
                    apply_result["answer"] = messagebox.askyesno("Применить UDPXY к плейлисту", apply_message)
                    apply_decision.set()
                    
                self.root.after(0, ask_and_set_result)
                apply_decision.wait(timeout=60)
                
                if apply_result["answer"]:
                    self.root.after(0, lambda: progress_dialog.append_message(f"Применение {first_verified_server} ко всем каналам..."))
                    self.root.after(0, partial(self._apply_udpxy_to_all_channels, first_verified_server))
                    self.root.after(0, lambda: messagebox.showinfo("UDPXY применен", f"Успешно применен {first_verified_server} ко всем каналам."))

                    if self.channels:
                        self.root.after(0, lambda: progress_dialog.append_message("\nЗапуск последовательной проверки каналов..."))
                        self.root.after(0, lambda: progress_dialog.update_channel_check_status("Проверка каналов..."))
                        
                        total_channels = len(self.channels)
                        for idx, channel in enumerate(self.channels):
                            if self.udpxy_scan_event.is_set():
                                progress_dialog.append_message("Проверка канала отменена.")
                                break

                            original_url = channel.url
                            
                            udpxy_pattern = r'^(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/udp/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)$'
                            multicast_pattern_udp = r'^udp://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)$'
                            multicast_pattern_raw = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)$'

                            udpxy_match = re.match(udpxy_pattern, original_url)
                            multicast_match_udp = re.match(multicast_pattern_udp, original_url)
                            multicast_match_raw = re.match(multicast_pattern_raw, original_url)
                            
                            if udpxy_match:
                                multicast_part = udpxy_match.group(2)
                                check_url = f"http://{first_verified_server}/udp/{multicast_part}"
                            elif multicast_match_udp:
                                multicast_part = multicast_match_udp.group(1)
                                check_url = f"http://{first_verified_server}/udp/{multicast_part}"
                            elif multicast_match_raw:
                                multicast_part = multicast_match_raw.group(1)
                                check_url = f"http://{first_verified_server}/udp/{multicast_part}"
                            else:
                                check_url = original_url

                            status_message = f"Проверка канала {idx+1}/{total_channels}: {channel.name} ({check_url})..."
                            self.root.after(0, lambda msg=status_message: progress_dialog.update_channel_check_status(msg))
                            self.root.after(0, lambda val=((idx+1)/total_channels)*100: progress_dialog.update_channel_check_progress(val))

                            is_online = StreamChecker.check_stream(check_url)
                            channel.status = is_online
                            channel.last_checked = time.time()
                            self.root.after(0, self.refresh_tree)

                            if is_online:
                                progress_dialog.append_message(f"    ✅ {channel.name} в сети.")
                            else:
                                progress_dialog.append_message(f"    ❌ {channel.name} не в сети.")
                            
                            time.sleep(0.1) # Small delay between checks

                        progress_dialog.append_message("Последовательная проверка каналов завершена.")
                    else:
                        progress_dialog.append_message("Каналы не загружены для выполнения последовательной проверки.")

                else:
                    self.root.after(0, lambda: messagebox.showinfo("Результаты авто-сканирования", final_message))
                    self.root.after(0, partial(self._display_udpxy_results, verified_udpxy_servers))
            else:
                final_message = "Авто-сканирование UDPXY завершено: Проверенные серверы UDPXY не найдены."
                self.root.after(0, lambda: self._update_udpxy_status_label("Авто-сканирование завершено (серверы не найдены)."))
                self.root.after(0, lambda: messagebox.showinfo("Результаты авто-сканирования", final_message))

            progress_dialog.append_message(f"\n{final_message}")

        except Exception as e:
            error_msg = f"Произошла непредвиденная ошибка во время авто-сканирования: {e}"
            print(error_msg)
            if progress_dialog:
                progress_dialog.append_message(f"Ошибка: {error_msg}")
            self.root.after(0, lambda: messagebox.showerror("Ошибка авто-сканирования", error_msg))
            self.root.after(0, lambda: self._update_udpxy_status_label("Авто-сканирование не удалось."))
        finally:
            self.udpxy_scan_event.clear()
            self.root.after(0, lambda: self.udpxy_progress_var.set(0))
            if progress_dialog:
                self.root.after(5000, progress_dialog.close) # Close dialog after 5 seconds

    def run(self):
        """Start the application."""
        self.update_status("Готов")
        self.root.mainloop()

    def _apply_udpxy_to_all_channels(self, new_udpxy_server: str):
        """Applies the given UDPXY server to all channels in the current playlist."""
        updated_count = 0
        for channel in self.channels:
            original_url = channel.url
            new_url = original_url
            
            udpxy_pattern = r'^(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/udp/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)$'
            multicast_pattern_udp = r'^udp://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)$'
            multicast_pattern_raw = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)$'

            udpxy_match = re.match(udpxy_pattern, original_url)
            multicast_match_udp = re.match(multicast_pattern_udp, original_url)
            multicast_match_raw = re.match(multicast_pattern_raw, original_url)
            
            if udpxy_match:
                multicast_part = udpxy_match.group(2)
                new_url = f"http://{new_udpxy_server}/udp/{multicast_part}"
            elif multicast_match_udp:
                multicast_part = multicast_match_udp.group(1)
                new_url = f"http://{new_udpxy_server}/udp/{multicast_part}"
            elif multicast_match_raw:
                multicast_part = multicast_match_raw.group(1)
                new_url = f"http://{new_udpxy_server}/udp/{multicast_part}"
            
            if new_url != original_url:
                channel.url = new_url
                channel.status = None
                channel.last_checked = None
                updated_count += 1

        self.refresh_tree()
        self.update_status(f"Применен {new_udpxy_server} к {updated_count} каналам.")


class ProgressDialog(tk.Toplevel):
    """A custom Toplevel dialog for displaying detailed progress messages."""

    def __init__(self, parent, title: str = "Progress", width: int = 500, height: int = 300):
        super().__init__(parent)
        self.title(title)
        self.geometry(f"{width}x{height}")
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.disable_event)

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

        self.block_status_label = tk.Label(self, text="", font=('Segoe UI', 9, 'bold'))
        self.block_status_label.pack(pady=(5, 0), padx=10, anchor=tk.W)

        self.block_progress_var = tk.DoubleVar()
        self.block_progress_bar = ttk.Progressbar(self, variable=self.block_progress_var, mode='determinate', length=width - 20)
        self.block_progress_bar.pack(pady=(0, 5), padx=10)

        self.overall_label = tk.Label(self, text="Общий прогресс:", font=('Segoe UI', 9, 'bold'))
        self.overall_label.pack(pady=(5, 0), padx=10, anchor=tk.W)

        self.overall_progress_var = tk.DoubleVar()
        self.overall_progress_bar = ttk.Progressbar(self, variable=self.overall_progress_var, mode='determinate', length=width - 20)
        self.overall_progress_bar.pack(pady=(0, 10), padx=10)

        self.estimated_time_label = ttk.Label(self, text="Предполагаемое время: Расчет...", font=('Segoe UI', 9))
        self.estimated_time_label.pack(pady=(0,5), padx=10, anchor=tk.W)

        self.channel_check_label = tk.Label(self, text="Прогресс проверки канала:", font=('Segoe UI', 9, 'bold'))
        self.channel_check_label.pack(pady=(5, 0), padx=10, anchor=tk.W)
        self.channel_check_label.pack_forget()

        self.channel_check_progress_var = tk.DoubleVar()
        self.channel_check_progress_bar = ttk.Progressbar(self, variable=self.channel_check_progress_var, mode='determinate', length=width - 20)
        self.channel_check_progress_bar.pack(pady=(0, 10), padx=10)
        self.channel_check_progress_bar.pack_forget()

        self.channel_check_status_label = tk.Label(self, text="", font=('Segoe UI', 9))
        self.channel_check_status_label.pack(pady=(0, 5), padx=10, anchor=tk.W)
        self.channel_check_status_label.pack_forget()

        self.text_widget = tk.Text(self, wrap=tk.WORD, state=tk.DISABLED, font=('Segoe UI', 9))
        self.text_widget.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        self.scrollbar = ttk.Scrollbar(self.text_widget, command=self.text_widget.yview)
        self.text_widget.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.update_idletasks()

    def update_block_status(self, message: str):
        self.block_status_label.config(text=message)
        self.update_idletasks()

    def update_block_progress(self, value: float):
        self.block_progress_var.set(value)
        self.update_idletasks()

    def update_overall_progress(self, value: float):
        self.overall_progress_var.set(value)
        self.update_idletasks()

    def update_estimated_time(self, time_str: str):
        self.estimated_time_label.config(text=f"Предполагаемое время: {time_str}")
        self.update_idletasks()

    def update_channel_check_status(self, message: str):
        self.channel_check_label.pack(pady=(5, 0), padx=10, anchor=tk.W)
        self.channel_check_progress_bar.pack(pady=(0, 10), padx=10)
        self.channel_check_status_label.pack(pady=(0, 5), padx=10, anchor=tk.W)
        self.channel_check_status_label.config(text=message)
        self.update_idletasks()

    def update_channel_check_progress(self, value: float):
        self.channel_check_progress_var.set(value)
        self.update_idletasks()

    def append_message(self, message: str):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, message + "\n")
        self.text_widget.see(tk.END)
        self.text_widget.config(state=tk.DISABLED)
        self.update_idletasks()

    def disable_event(self):
        pass

    def close(self):
        self.grab_release()
        self.destroy()


class ChannelDialog:
    """Dialog for adding/editing channel information."""
    
    def __init__(self, parent, title, name="", url="", group=""):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("500x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set() # Исправлено: вызываем grab_set() для self.dialog
        
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        self.create_widgets(name, url, group)
        
        self.name_entry.focus_set()
        self.name_entry.select_range(0, tk.END)
        
        self.dialog.wait_window()
    
    def create_widgets(self, name, url, group):
        """Create dialog widgets."""
        main_frame = tk.Frame(self.dialog, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text="Название канала:", font=('Segoe UI', 10)).pack(anchor=tk.W)
        self.name_entry = tk.Entry(main_frame, font=('Segoe UI', 10), width=60)
        self.name_entry.pack(fill=tk.X, pady=(5, 15))
        self.name_entry.insert(0, name)
        
        tk.Label(main_frame, text="URL потока:", font=('Segoe UI', 10)).pack(anchor=tk.W)
        self.url_entry = tk.Entry(main_frame, font=('Segoe UI', 10), width=60)
        self.url_entry.pack(fill=tk.X, pady=(5, 15))
        self.url_entry.insert(0, url)
        
        tk.Label(main_frame, text="Группа (необязательно):", font=('Segoe UI', 10)).pack(anchor=tk.W)
        self.group_entry = tk.Entry(main_frame, font=('Segoe UI', 10), width=60)
        self.group_entry.pack(fill=tk.X, pady=(5, 15))
        self.group_entry.insert(0, group)
        
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        tk.Button(button_frame, text="Отмена", command=self.cancel, 
                 font=('Segoe UI', 10), padx=20, pady=5).pack(side=tk.RIGHT, padx=(5, 0))
        tk.Button(button_frame, text="ОК", command=self.ok, 
                 font=('Segoe UI', 10), padx=20, pady=5).pack(side=tk.RIGHT)
        
        self.dialog.bind('<Return>', lambda e: self.ok())
        self.dialog.bind('<Escape>', lambda e: self.cancel())
    
    def ok(self):
        """Handle OK button click."""
        name = self.name_entry.get().strip()
        url = self.url_entry.get().strip()
        group = self.group_entry.get().strip()
        
        if not name:
            messagebox.showerror("Ошибка", "Требуется название канала")
            return
        
        if not url:
            messagebox.showerror("Ошибка", "Требуется URL потока")
            return
        
        self.result = {
            'name': name,
            'url': url,
            'group': group
        }
        self.dialog.destroy()
    
    def cancel(self):
        """Handle Cancel button click."""
        self.dialog.destroy()

class ScannedBlocksDialog(tk.Toplevel):
    """Dialog for displaying and selecting IP blocks for scanning."""

    def __init__(self, parent, ip_blocks: Set[str]):
        super().__init__(parent)
        self.title("Выбрать IP-блоки для сканирования")
        self.geometry("600x400")
        self.transient(parent)
        self.grab_set()
        self.result_blocks: List[str] = []

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

        self.create_widgets(ip_blocks)

        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.wait_window()

    def create_widgets(self, ip_blocks: Set[str]):
        main_frame = tk.Frame(self, padx=10, pady=10)
        main_frame.pack(expand=True, fill=tk.BOTH)

        tk.Label(main_frame, text="Обнаруженные IP-блоки:", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W, pady=(0, 5))

        tree_frame = tk.Frame(main_frame)
        tree_frame.pack(expand=True, fill=tk.BOTH)

        columns = ('Block',)
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings', selectmode='extended')
        self.tree.heading('#0', text='#')
        self.tree.column('#0', width=50, minwidth=30, stretch=tk.NO)
        self.tree.heading('Block', text='IP-блок (CIDR)')
        self.tree.column('Block', width=300, minwidth=150, stretch=tk.YES)

        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        sorted_blocks = sorted(list(ip_blocks), key=lambda x: ipaddress.ip_network(x).network_address)
        for i, block in enumerate(sorted_blocks, 1):
            self.tree.insert('', 'end', text=str(i), values=(block,))
        
        for item in self.tree.get_children():
            self.tree.selection_add(item)

        button_frame = tk.Frame(self, pady=10)
        button_frame.pack(fill=tk.X)

        tk.Button(button_frame, text="Сканировать выбранные блоки", command=self.scan_selected,
                  font=('Segoe UI', 10, 'bold'), bg='#007bff', fg='white', padx=15, pady=5).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="Отмена", command=self.cancel,
                  font=('Segoe UI', 10), padx=15, pady=5).pack(side=tk.RIGHT, padx=10)

    def scan_selected(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Нет выбора", "Пожалуйста, выберите хотя бы один IP-блок для сканирования.")
            return

        self.result_blocks = [self.tree.item(item, 'values')[0] for item in selected_items]
        self.destroy_and_release()

    def cancel(self):
        self.result_blocks = []
        self.destroy_and_release()

    def destroy_and_release(self):
        self.grab_release()
        self.destroy()


if __name__ == "__main__":
    app = StreamManagerGUI()
    app.run()
