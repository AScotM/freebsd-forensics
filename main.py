import argparse
import concurrent.futures
import dataclasses
import datetime
import difflib
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter, defaultdict
from typing import Any

VERSION = '1.0.0'
DEFAULT_DB = os.path.expanduser('~/.local/share/freebsd-forensics/history.sqlite3')
SECTIONS = ('identity', 'kernel', 'security', 'services', 'packages', 'jails', 'storage', 'zfs', 'network', 'processes', 'firewall', 'boot', 'logs')
REDACT_PATTERN = re.compile(r'(?i)(password|passwd|secret|token|credential|private.key|api.key)')


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def safe_text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return str(value)


def parse_lines(text):
    return [line.rstrip() for line in text.splitlines() if line.strip()]


def key_value_lines(text, separator=':'):
    result = {}
    for line in text.splitlines():
        if separator in line:
            key, value = line.split(separator, 1)
            key = key.strip()
            if key:
                result[key] = value.strip()
    return result


def redact(value):
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if REDACT_PATTERN.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


@dataclasses.dataclass
class CommandResult:
    argv: list
    returncode: int | None
    stdout: str
    stderr: str
    elapsed: float
    status: str

    def to_dict(self):
        return dataclasses.asdict(self)


class Runner:
    def __init__(self, timeout=8.0, max_output=524288, allow_privileged=False):
        self.timeout = timeout
        self.max_output = max_output
        self.allow_privileged = allow_privileged
        self.lock = threading.Lock()
        self.counts = Counter()

    def run(self, *args, timeout=None):
        argv = [str(x) for x in args]
        start = time.monotonic()
        if not argv or not shutil.which(argv[0]):
            result = CommandResult(argv, None, '', 'Command unavailable', 0.0, 'unavailable')
        else:
            try:
                proc = subprocess.run(argv, capture_output=True, timeout=timeout or self.timeout, check=False)
                out = safe_text(proc.stdout[:self.max_output])
                err = safe_text(proc.stderr[:self.max_output])
                result = CommandResult(argv, proc.returncode, out, err, round(time.monotonic()-start, 4), 'ok' if proc.returncode == 0 else 'error')
            except subprocess.TimeoutExpired as exc:
                result = CommandResult(argv, None, safe_text((exc.stdout or b'')[:self.max_output]), 'Timed out', round(time.monotonic()-start, 4), 'timeout')
            except (OSError, ValueError) as exc:
                result = CommandResult(argv, None, '', safe_text(exc), round(time.monotonic()-start, 4), 'error')
        with self.lock:
            self.counts[result.status] += 1
        return result.to_dict()

    def stdout(self, *args, timeout=None):
        result = self.run(*args, timeout=timeout)
        return result['stdout'] if result['status'] == 'ok' else ''


class Collector:
    name = 'unknown'

    def __init__(self, runner, options):
        self.r = runner
        self.options = options

    def command(self, *args, timeout=None):
        return self.r.run(*args, timeout=timeout)

    def text(self, *args, timeout=None):
        return self.r.stdout(*args, timeout=timeout)

    def collect(self):
        raise NotImplementedError


class IdentityCollector(Collector):
    name = 'identity'

    def collect(self):
        return {
            'hostname': socket.gethostname(),
            'platform': sys.platform,
            'python': sys.version.split()[0],
            'uid': os.getuid() if hasattr(os, 'getuid') else None,
            'freebsd_version': self.command('freebsd-version', '-kru'),
            'uname': self.command('uname', '-a'),
            'uptime': self.command('uptime'),
            'date': self.command('date', '-u'),
            'architecture': self.text('uname', '-m').strip(),
            'virtualization': self.command('sysctl', '-n', 'kern.vm_guest'),
        }


class KernelCollector(Collector):
    name = 'kernel'

    def collect(self):
        keys = ('kern.ostype', 'kern.osrelease', 'kern.version', 'kern.bootfile', 'kern.securelevel', 'kern.maxproc', 'kern.maxfiles', 'kern.ipc.somaxconn', 'hw.model', 'hw.ncpu', 'hw.physmem', 'vm.stats.vm.v_free_count', 'vm.stats.vm.v_page_size', 'vm.swap_total', 'security.bsd.see_other_uids')
        sysctls = {}
        for key in keys:
            response = self.command('sysctl', '-n', key)
            sysctls[key] = response['stdout'].strip() if response['status'] == 'ok' else None
        return {'sysctls': sysctls, 'modules': self.command('kldstat'), 'kernel_config': self.command('sysctl', 'kern.conftxt'), 'swap': self.command('swapinfo', '-h'), 'vmstat': self.command('vmstat', '-s')}


class SecurityCollector(Collector):
    name = 'security'

    def collect(self):
        keys = ('kern.securelevel', 'security.bsd.see_other_uids', 'security.bsd.see_other_gids', 'security.bsd.unprivileged_read_msgbuf', 'security.bsd.unprivileged_proc_debug', 'security.mac', 'security.jail.jailed', 'security.jail.allow_raw_sockets', 'net.inet.ip.forwarding', 'net.inet6.ip6.forwarding', 'net.inet.tcp.blackhole', 'net.inet.udp.blackhole', 'kern.randompid', 'kern.elf64.aslr.enable', 'kern.elf32.aslr.enable', 'kern.elf64.aslr.pie_enable')
        values = {}
        for key in keys:
            output = self.command('sysctl', '-n', key)
            values[key] = output['stdout'].strip() if output['status'] == 'ok' else None
        return {
            'sysctls': values,
            'mac_modules': self.command('kldstat', '-v'),
            'audit': self.command('service', 'auditd', 'onestatus'),
            'sshd': self.command('service', 'sshd', 'onestatus'),
            'users': self.command('pw', 'usershow', 'root'),
            'lastlog': self.command('last', '-n', '12'),
            'mounts': self.command('mount', '-p'),
        }


class ServicesCollector(Collector):
    name = 'services'

    def collect(self):
        enabled = self.command('service', '-e')
        all_services = self.command('service', '-l')
        rcvars = self.command('sysrc', '-a')
        return {'enabled': enabled, 'available': all_services, 'rc_configuration': rcvars, 'enabled_names': parse_lines(enabled['stdout']), 'rc_variables': key_value_lines(rcvars['stdout'], ':')}


class PackagesCollector(Collector):
    name = 'packages'

    def collect(self):
        installed = self.command('pkg', 'query', '%n\t%v\t%o')
        packages = []
        for line in parse_lines(installed['stdout']):
            parts = line.split('\t')
            if len(parts) >= 2:
                packages.append({'name': parts[0], 'version': parts[1], 'origin': parts[2] if len(parts)>2 else ''})
        packages.sort(key=lambda x: x['name'])
        base = [x for x in packages if x['name'].startswith('FreeBSD-')]
        return {'installed_count': len(packages), 'packages': packages, 'pkgbase_count': len(base), 'pkgbase_packages': base, 'repositories': self.command('pkg', '-vv'), 'audit': self.command('pkg', 'audit', '-F', timeout=15) if self.options.online else {'status': 'skipped', 'reason': 'requires online mode'}, 'integrity': self.command('pkg', 'check', '-d', '-a') if self.options.deep else {'status': 'skipped'}}


class JailsCollector(Collector):
    name = 'jails'

    def collect(self):
        jls = self.command('jls', '-n')
        records = []
        for line in parse_lines(jls['stdout']):
            entry = {}
            for match in re.finditer(r'([\w.]+)=((?:"[^"]*")|(?:\S+))', line):
                entry[match.group(1)] = match.group(2).strip('"')
            if entry:
                records.append(entry)
        return {'jails': records, 'jls': jls, 'configuration': self.command('sysrc', 'jail_enable'), 'jail_sysctls': self.command('sysctl', 'security.jail'), 'jail_list': self.command('jls')}


class StorageCollector(Collector):
    name = 'storage'

    def collect(self):
        return {
            'df': self.command('df', '-kT'),
            'mounts': self.command('mount', '-p'),
            'partitions': self.command('gpart', 'show', '-p'),
            'geom_disks': self.command('geom', 'disk', 'list'),
            'geom_labels': self.command('geom', 'label', 'list'),
            'swap': self.command('swapinfo', '-k'),
            'camcontrol': self.command('camcontrol', 'devlist'),
            'fstab': self.read_file('/etc/fstab'),
        }

    def read_file(self, path):
        try:
            return {'status': 'ok', 'content': pathlib.Path(path).read_text(errors='replace')[:65536]}
        except OSError as exc:
            return {'status': 'error', 'error': str(exc)}


class ZFSCollector(Collector):
    name = 'zfs'

    def collect(self):
        return {'pools': self.command('zpool', 'list', '-Hp', '-o', 'name,size,alloc,free,health,fragmentation'), 'pool_status': self.command('zpool', 'status', '-P'), 'datasets': self.command('zfs', 'list', '-Hp', '-o', 'name,used,available,refer,mountpoint,compression'), 'snapshots': self.command('zfs', 'list', '-Hp', '-t', 'snapshot', '-o', 'name,used,refer,creation'), 'boot_environments': self.command('bectl', 'list', '-H'), 'arc': self.command('sysctl', 'kstat.zfs.misc.arcstats.size')}


class NetworkCollector(Collector):
    name = 'network'

    def collect(self):
        return {
            'interfaces': self.command('ifconfig', '-a'),
            'routes_ipv4': self.command('netstat', '-rn', '-f', 'inet'),
            'routes_ipv6': self.command('netstat', '-rn', '-f', 'inet6'),
            'sockets_ipv4': self.command('sockstat', '-4'),
            'sockets_ipv6': self.command('sockstat', '-6'),
            'sockets_unix': self.command('sockstat', '-u'),
            'protocol_stats': self.command('netstat', '-s', '-p', 'tcp'),
            'arp': self.command('arp', '-an'),
            'ndp': self.command('ndp', '-an'),
            'resolver': self.read_resolver(),
            'ip_forwarding': self.command('sysctl', 'net.inet.ip.forwarding', 'net.inet6.ip6.forwarding'),
        }

    def read_resolver(self):
        try:
            return pathlib.Path('/etc/resolv.conf').read_text(errors='replace')[:32768]
        except OSError:
            return ''


class ProcessesCollector(Collector):
    name = 'processes'

    def collect(self):
        output = self.command('ps', '-axo', 'pid,ppid,uid,state,%cpu,%mem,rss,etime,comm')
        records = []
        for line in parse_lines(output['stdout'])[1:]:
            fields = line.split(None, 8)
            if len(fields) == 9:
                records.append(dict(zip(('pid','ppid','uid','state','cpu','mem','rss','elapsed','command'), fields)))
        records.sort(key=lambda x: int(x['pid']) if x['pid'].isdigit() else -1)
        result = {'count': len(records), 'processes': records, 'ps': output, 'resource_limits': self.command('limits', '-a'), 'top': self.command('top', '-b', '-n', '1')}
        if self.options.deep:
            pids = [p['pid'] for p in sorted(records, key=lambda x: float(x['cpu']) if re.fullmatch(r'\d+(?:\.\d+)?', x['cpu']) else 0, reverse=True)[:self.options.process_limit]]
            result['procstat'] = {pid: {'files': self.command('procstat', '-f', pid), 'vm': self.command('procstat', '-v', pid), 'threads': self.command('procstat', '-t', pid)} for pid in pids}
        return result


class FirewallCollector(Collector):
    name = 'firewall'

    def collect(self):
        pf_status = self.command('pfctl', '-s', 'info')
        ipfw_status = self.command('ipfw', 'list')
        return {'pf_status': pf_status, 'pf_rules': self.command('pfctl', '-sr') if pf_status['status'] == 'ok' else {'status': 'unavailable'}, 'pf_nat': self.command('pfctl', '-sn') if pf_status['status'] == 'ok' else {'status': 'unavailable'}, 'ipfw_rules': ipfw_status, 'ipfw_tables': self.command('ipfw', 'table', 'all', 'list') if ipfw_status['status'] == 'ok' else {'status': 'unavailable'}, 'firewall_rc': self.command('sysrc', 'firewall_enable', 'pf_enable', 'ipfw_enable')}


class BootCollector(Collector):
    name = 'boot'

    def collect(self):
        return {'boot_time': self.command('sysctl', 'kern.boottime'), 'dmesg': self.command('dmesg', '-a'), 'loader_conf': self.read_config('/boot/loader.conf'), 'rc_conf': self.read_config('/etc/rc.conf'), 'sysctl_conf': self.read_config('/etc/sysctl.conf'), 'boot_environments': self.command('bectl', 'list')}

    def read_config(self, path):
        try:
            lines = pathlib.Path(path).read_text(errors='replace').splitlines()
            return {'status': 'ok', 'lines': [line for line in lines if line.strip() and not line.lstrip().startswith('#')][:1000]}
        except OSError as exc:
            return {'status': 'error', 'error': str(exc)}


class LogsCollector(Collector):
    name = 'logs'

    def collect(self):
        candidates = ('/var/log/messages', '/var/log/security', '/var/log/auth.log', '/var/log/daemon.log')
        results = {}
        for filename in candidates:
            try:
                with open(filename, 'rb') as handle:
                    handle.seek(0, os.SEEK_END)
                    size = handle.tell()
                    handle.seek(max(0, size-self.options.log_bytes))
                    raw = handle.read(self.options.log_bytes)
                lines = raw.decode('utf-8', 'replace').splitlines()
                if size > self.options.log_bytes and lines:
                    lines = lines[1:]
                results[filename] = {'status': 'ok', 'size': size, 'tail': lines[-self.options.log_lines:]}
            except OSError as exc:
                results[filename] = {'status': 'error', 'error': str(exc)}
        return {'files': results, 'last_boots': self.command('last', 'reboot', '-n', '10')}


COLLECTORS = {cls.name: cls for cls in (IdentityCollector, KernelCollector, SecurityCollector, ServicesCollector, PackagesCollector, JailsCollector, StorageCollector, ZFSCollector, NetworkCollector, ProcessesCollector, FirewallCollector, BootCollector, LogsCollector)}


class FindingsEngine:
    def __init__(self, report):
        self.report = report
        self.findings = []

    def add(self, severity, code, section, title, evidence, recommendation):
        self.findings.append({'severity': severity, 'code': code, 'section': section, 'title': title, 'evidence': evidence, 'recommendation': recommendation})

    def value(self, section, *keys):
        obj = self.report.get('sections', {}).get(section, {})
        for key in keys:
            if not isinstance(obj, dict):
                return None
            obj = obj.get(key)
        return obj

    def evaluate(self):
        security = self.value('security', 'sysctls') or {}
        for key in ('net.inet.ip.forwarding', 'net.inet6.ip6.forwarding'):
            if security.get(key) == '1':
                self.add('info', 'FORWARDING_ENABLED', 'security', 'IP forwarding enabled', key, 'Verify that routing is intentional and firewall policy is appropriate')
        if security.get('security.bsd.see_other_uids') == '1':
            self.add('low', 'PROCESS_VISIBILITY', 'security', 'Users can see other users processes', 'security.bsd.see_other_uids=1', 'Consider restricting process visibility on multiuser hosts')
        if security.get('kern.securelevel') == '-1':
            self.add('info', 'SECURELEVEL_DEFAULT', 'security', 'Securelevel is -1', 'kern.securelevel=-1', 'Assess securelevel policy for the intended workload')
        packages = self.value('packages') or {}
        if packages.get('pkgbase_count', 0):
            self.add('info', 'PKGBASE_PRESENT', 'packages', 'PkgBase packages detected', str(packages['pkgbase_count']), 'Use pkg-based base system updates rather than freebsd-update')
        audit = packages.get('audit', {})
        if isinstance(audit, dict) and audit.get('status') == 'ok' and re.search(r'\b\d+ problem\(s\)', audit.get('stdout', '')):
            self.add('high', 'PACKAGE_AUDIT', 'packages', 'Package audit reported potential vulnerabilities', audit['stdout'][-2000:], 'Review pkg audit output and update affected packages')
        storage = self.value('storage', 'df', 'stdout') or ''
        for line in parse_lines(storage)[1:]:
            fields = line.split()
            for field in fields:
                if field.endswith('%') and field[:-1].isdigit() and int(field[:-1]) >= 90:
                    self.add('medium', 'FILESYSTEM_USAGE', 'storage', 'Filesystem usage at or above 90 percent', line, 'Investigate disk consumption and filesystem capacity')
                    break
        zfs = self.value('zfs', 'pool_status', 'stdout') or ''
        if re.search(r'(?im)^\s*state:\s*(DEGRADED|FAULTED|UNAVAIL|SUSPENDED)', zfs):
            self.add('high', 'ZFS_HEALTH', 'zfs', 'ZFS pool reports unhealthy state', zfs[:2000], 'Inspect zpool status and underlying storage')
        firewall = self.value('firewall') or {}
        if firewall:
            pf = firewall.get('pf_status', {}).get('status')
            ipfw = firewall.get('ipfw_rules', {}).get('status')
            if pf != 'ok' and ipfw != 'ok':
                self.add('info', 'FIREWALL_NOT_OBSERVED', 'firewall', 'No active PF or IPFW rules were confirmed', 'PF and IPFW queries did not succeed', 'Verify firewall configuration and permissions; another filtering mechanism may be present')
        self.findings.sort(key=lambda x: ({'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x['severity'], 5), x['code']))
        return self.findings


class History:
    def __init__(self, path):
        self.path = os.path.expanduser(path)
        pathlib.Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=15)
        self.db.execute('PRAGMA busy_timeout=15000')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS snapshots (
                id TEXT PRIMARY KEY,
                captured_at TEXT NOT NULL,
                hostname TEXT NOT NULL,
                digest TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS snapshots_host_time ON snapshots(hostname,captured_at DESC);
            CREATE TABLE IF NOT EXISTS changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                previous_id TEXT NOT NULL,
                current_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                changes_json TEXT NOT NULL
            );
        ''')
        self.db.commit()

    def save(self, report):
        identifier = report['id']
        self.db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?)', (identifier, report['captured_at'], report['hostname'], digest(report), json.dumps(report, ensure_ascii=False, sort_keys=True)))
        self.db.commit()
        return identifier

    def list(self, hostname=None, limit=20):
        if hostname:
            rows = self.db.execute('SELECT id,captured_at,hostname,digest FROM snapshots WHERE hostname=? ORDER BY captured_at DESC LIMIT ?', (hostname, limit)).fetchall()
        else:
            rows = self.db.execute('SELECT id,captured_at,hostname,digest FROM snapshots ORDER BY captured_at DESC LIMIT ?', (limit,)).fetchall()
        return [dict(zip(('id','captured_at','hostname','digest'), row)) for row in rows]

    def load(self, identifier):
        if identifier == 'latest':
            row = self.db.execute('SELECT payload FROM snapshots ORDER BY captured_at DESC LIMIT 1').fetchone()
        elif identifier == 'previous':
            row = self.db.execute('SELECT payload FROM snapshots ORDER BY captured_at DESC LIMIT 1 OFFSET 1').fetchone()
        else:
            row = self.db.execute('SELECT payload FROM snapshots WHERE id=?', (identifier,)).fetchone()
        if not row:
            raise ValueError('Snapshot not found: ' + identifier)
        return json.loads(row[0])

    def record_changes(self, old, new, changes):
        self.db.execute('INSERT INTO changes(previous_id,current_id,created_at,changes_json) VALUES(?,?,?,?)', (old['id'], new['id'], utcnow(), json.dumps(changes, ensure_ascii=False)))
        self.db.commit()

    def close(self):
        self.db.close()


VOLATILE_KEYS = {'elapsed', 'uptime', 'date', 'boot_time', 'dmesg', 'top', 'vmstat', 'lastlog', 'last_boots', 'protocol_stats', 'sockets_ipv4', 'sockets_ipv6', 'sockets_unix', 'arp', 'ndp', 'processes', 'ps', 'procstat', 'resource_limits', 'swap', 'last_boots', 'captured_at', 'duration_seconds', 'id', 'counts', 'findings', 'digest', 'size', 'tail'}


def normalize(value, stable=True):
    if isinstance(value, dict):
        if 'argv' in value and 'status' in value:
            return {'status': value['status'], 'stdout': value.get('stdout', '').strip() if value['status'] == 'ok' else ''}
        return {k: normalize(v, stable) for k, v in sorted(value.items()) if not (stable and k in VOLATILE_KEYS)}
    if isinstance(value, list):
        return [normalize(v, stable) for v in value]
    return value


def flatten(value, prefix=''):
    result = {}
    if isinstance(value, dict):
        for key, val in value.items():
            result.update(flatten(val, prefix + '.' + str(key) if prefix else str(key)))
    elif isinstance(value, list):
        if len(value) > 100:
            result[prefix] = {'count': len(value), 'digest': digest(value)}
        else:
            for index, val in enumerate(value):
                result.update(flatten(val, prefix + '[' + str(index) + ']'))
    else:
        result[prefix] = value
    return result


def compare_reports(old, new, stable=True, limit=1000):
    a = flatten(normalize(old.get('sections', {}), stable))
    b = flatten(normalize(new.get('sections', {}), stable))
    changes = []
    for key in sorted(set(a) | set(b)):
        if a.get(key) != b.get(key):
            changes.append({'path': key, 'kind': 'added' if key not in a else 'removed' if key not in b else 'modified', 'old': a.get(key), 'new': b.get(key)})
            if len(changes) >= limit:
                break
    return {'previous_id': old.get('id'), 'current_id': new.get('id'), 'stable': stable, 'changes': changes, 'count': len(changes), 'truncated': len(changes) >= limit}


def run_collectors(names, runner, options):
    start = time.monotonic()
    result = {}
    errors = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(options.workers, len(names))) as executor:
        futures = {executor.submit(COLLECTORS[name](runner, options).collect): name for name in names}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                result[name] = future.result()
            except Exception as exc:
                errors[name] = {'type': type(exc).__name__, 'message': str(exc)}
    return {name: result[name] for name in names if name in result}, errors, round(time.monotonic()-start, 3)


def inspect(options):
    names = SECTIONS if options.all else tuple(dict.fromkeys(options.section or SECTIONS))
    runner = Runner(options.timeout, options.max_output)
    sections, errors, elapsed = run_collectors(names, runner, options)
    report = {'schema': 'freebsd-forensics/v1', 'version': VERSION, 'id': str(uuid.uuid4()), 'captured_at': utcnow(), 'hostname': socket.gethostname(), 'platform': sys.platform, 'duration_seconds': elapsed, 'sections': sections, 'collector_errors': errors, 'command_counts': dict(runner.counts)}
    report['findings'] = FindingsEngine(report).evaluate()
    return redact(report) if options.redact else report


def print_summary(report):
    print('FREEBSD FORENSICS', report.get('version', VERSION))
    print('Host:', report.get('hostname', 'unknown'))
    print('Captured:', report.get('captured_at', 'unknown'))
    print('Snapshot:', report.get('id', 'unknown'))
    print('Sections:', ', '.join(report.get('sections', {})))
    print('Duration:', report.get('duration_seconds', '?'), 'seconds')
    print('Commands:', report.get('command_counts', {}))
    if report.get('collector_errors'):
        print('Collector errors:', json.dumps(report['collector_errors'], ensure_ascii=False))
    print('Findings:', len(report.get('findings', [])))
    for finding in report.get('findings', []):
        print('  [{severity}] {code}: {title}'.format(**finding))
    for name, section in report.get('sections', {}).items():
        print('\n[' + name.upper() + ']')
        if name == 'identity':
            print('Hostname:', section.get('hostname'))
            print('Architecture:', section.get('architecture'))
            print('Version:', section.get('freebsd_version', {}).get('stdout', '').strip().replace('\n', ', '))
        elif name == 'packages':
            print('Installed packages:', section.get('installed_count'))
            print('PkgBase packages:', section.get('pkgbase_count'))
        elif name == 'jails':
            print('Running jails:', len(section.get('jails', [])))
            for jail in section.get('jails', []):
                print(' ', jail.get('name', '?'), jail.get('jid', '?'))
        elif name == 'processes':
            print('Processes:', section.get('count'))
        elif name == 'services':
            print('Enabled services:', len(section.get('enabled_names', [])))
            for service in section.get('enabled_names', [])[:20]:
                print(' ', service)
        elif name == 'kernel':
            for key, value in section.get('sysctls', {}).items():
                if value is not None:
                    print(' ', key, '=', value[:160])
        else:
            for key, value in section.items():
                if isinstance(value, dict) and 'status' in value:
                    print(' ', key + ':', value['status'], '(' + str(len(value.get('stdout', ''))) + ' bytes)')
                elif isinstance(value, (list, dict)):
                    print(' ', key + ':', len(value), 'entries')
                else:
                    print(' ', key + ':', str(value)[:120])


def render(payload, fmt='text', output=None):
    if fmt == 'json':
        data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str)
    elif fmt == 'jsonl':
        if isinstance(payload, list):
            data = '\n'.join(json.dumps(x, ensure_ascii=False, sort_keys=True, default=str) for x in payload)
        else:
            data = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    else:
        if isinstance(payload, dict) and 'sections' in payload:
            if output:
                from io import StringIO
                import contextlib
                buffer = StringIO()
                with contextlib.redirect_stdout(buffer):
                    print_summary(payload)
                data = buffer.getvalue()
            else:
                print_summary(payload)
                return
        elif isinstance(payload, dict) and 'changes' in payload:
            lines = ['Changes: ' + str(payload['count'])]
            for change in payload['changes']:
                lines.append('{kind}: {path}'.format(**change))
                lines.append('  old: ' + str(change.get('old'))[:300])
                lines.append('  new: ' + str(change.get('new'))[:300])
            data = '\n'.join(lines)
        else:
            data = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    if output:
        path = pathlib.Path(output).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data + '\n', encoding='utf-8')
        print('Written:', path)
    else:
        print(data)


def parser():
    p = argparse.ArgumentParser(prog='freebsd-forensics', description='Read-only FreeBSD diagnostics and forensic snapshot framework')
    p.add_argument('--version', action='version', version=VERSION)
    sub = p.add_subparsers(dest='action')
    def common(s):
        s.add_argument('--format', choices=('text','json','jsonl'), default='text')
        s.add_argument('--output')
    def scanning(s):
        common(s)
        s.add_argument('--section', action='append', choices=SECTIONS)
        s.add_argument('--all', action='store_true')
        s.add_argument('--timeout', type=float, default=8)
        s.add_argument('--max-output', type=int, default=524288)
        s.add_argument('--workers', type=int, default=4)
        s.add_argument('--deep', action='store_true')
        s.add_argument('--online', action='store_true')
        s.add_argument('--process-limit', type=int, default=8)
        s.add_argument('--log-bytes', type=int, default=131072)
        s.add_argument('--log-lines', type=int, default=100)
        s.add_argument('--redact', action='store_true')
        s.add_argument('--db', default=DEFAULT_DB)
    scanning(sub.add_parser('inspect', help='Inspect selected FreeBSD subsystems'))
    scanning(sub.add_parser('snapshot', help='Collect and store a snapshot in SQLite'))
    listing = sub.add_parser('history', help='List saved snapshots')
    listing.add_argument('--db', default=DEFAULT_DB)
    listing.add_argument('--hostname')
    listing.add_argument('--limit', type=int, default=20)
    common(listing)
    show = sub.add_parser('show', help='Show stored snapshot')
    show.add_argument('id', nargs='?', default='latest')
    show.add_argument('--db', default=DEFAULT_DB)
    common(show)
    diff = sub.add_parser('diff', help='Compare two stored snapshots')
    diff.add_argument('previous', nargs='?', default='previous')
    diff.add_argument('current', nargs='?', default='latest')
    diff.add_argument('--db', default=DEFAULT_DB)
    diff.add_argument('--full', action='store_true', help='Include volatile metrics')
    diff.add_argument('--limit', type=int, default=1000)
    common(diff)
    findings = sub.add_parser('findings', help='Display findings from a stored snapshot')
    findings.add_argument('--id', default='latest')
    findings.add_argument('--db', default=DEFAULT_DB)
    findings.add_argument('--severity', choices=('critical','high','medium','low','info'))
    common(findings)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.action is None:
        parser().print_help()
        return 0
    if args.action in ('inspect', 'snapshot'):
        if args.workers < 1 or args.timeout <= 0 or args.max_output < 1024 or args.process_limit < 0 or args.log_bytes < 0 or args.log_lines < 0:
            raise ValueError('Invalid collector limits')
        report = inspect(args)
        if args.action == 'snapshot':
            history = History(args.db)
            try:
                history.save(report)
            finally:
                history.close()
        render(report, args.format, args.output)
        return 0
    history = History(args.db)
    try:
        if args.action == 'history':
            result = history.list(args.hostname, args.limit)
        elif args.action == 'show':
            result = history.load(args.id)
        elif args.action == 'diff':
            result = compare_reports(history.load(args.previous), history.load(args.current), not args.full, args.limit)
        elif args.action == 'findings':
            result = history.load(args.id).get('findings', [])
            if args.severity:
                result = [f for f in result if f['severity'] == args.severity]
        else:
            raise ValueError('Unknown command')
    finally:
        history.close()
    render(result, args.format, args.output)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, sqlite3.Error, OSError) as exc:
        print('Error:', exc, file=sys.stderr)
        sys.exit(2)
