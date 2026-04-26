"""
SNSS-parser-win.py

Chrome forensic extractor for Windows profiles.

Usage:
    python3 SNSS-parser-win.py C:/          # scan entire C drive → all users
    python3 SNSS-parser-win.py /tmp/D1      # scan mounted Windows image
    python3 SNSS-parser-win.py C:/Users/bob # single user
    python3 SNSS-parser-win.py              # auto-detect current machine

Output columns: #, Source, Date Time (UTC), URL, Title, Comments, User
"""

import struct, os, datetime, sqlite3, sys, shutil, tempfile, json, csv

# — Tee stderr to log file —————————————————————————
class _TeeStderr:
    """Mirror sys.stderr to both console and a log file."""
    def __init__(self, path):
        self._con = sys.__stderr__
        self._log = open(path, 'w', encoding='utf-8', errors='replace')
    def write(self, msg):
        self._con.write(msg)
        self._log.write(msg)
    def flush(self):
        self._con.flush()
        self._log.flush()
    def close(self):
        self._log.close()

# — Binary helpers ————————————————————————————————

def align4(n): return (n + 3) & ~3

def read_int32(p, pos):
    if pos + 4 > len(p): return None, pos
    return struct.unpack_from('<i', p, pos)[0], pos + 4

def read_uint32(p, pos):
    if pos + 4 > len(p): return None, pos
    return struct.unpack_from('<I', p, pos)[0], pos + 4

def read_int64(p, pos):
    if pos + 8 > len(p): return None, pos
    return struct.unpack_from('<q', p, pos)[0], pos + 8

def read_string(p, pos):
    length, pos = read_uint32(p, pos)
    if length is None or length > 500000 or pos + length > len(p): return None, pos
    s = p[pos:pos+length].decode('utf-8', errors='replace')
    return s, pos + align4(length)

def read_string16(p, pos):
    lc, pos = read_uint32(p, pos)
    if lc is None or lc > 250000: return None, pos
    bl = lc * 2
    if pos + bl > len(p): return None, pos
    s = p[pos:pos+bl].decode('utf-16-le', errors='replace')
    return s, pos + align4(bl)

# — Chrome timestamp ————————————————————————————

CHROME_EPOCH_US = 11644473600 * 1_000_000

def chrome_ts(us):
    try:
        return datetime.datetime.utcfromtimestamp(
            (us - CHROME_EPOCH_US) / 1e6
        ).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return None

# — SNSS version map ——————————————————————————

SNSS_VERSION_MAP = {
    1: {'chrome': '< 91', 'supported': True,  'note': 'Legacy (pre May 2021)'},
    2: {'chrome': 'N/A',  'supported': False, 'note': 'Encrypted, never shipped'},
    3: {'chrome': '91+',  'supported': True,  'note': 'Current format (May 2021+)'},
    4: {'chrome': 'N/A',  'supported': False, 'note': 'Encrypted, never shipped'},
    5: {'chrome': 'TBD',  'supported': False, 'note': 'Upcoming, not released'},
}

def check_snss_version(path, label=None):
    try:
        data = open(path, 'rb').read(8)
        if data[:4] != b'SNSS': return None
        version = struct.unpack_from('<I', data, 4)[0]
        info = SNSS_VERSION_MAP.get(version, {'chrome': 'Unknown', 'supported': False, 'note': 'Unrecognised'})
        fname = label or os.path.basename(path)
        status = '✅' if info['supported'] else '❌'
        print(f"  [{fname}]  SNSS v{version}  Chrome {info['chrome']}  {status}  ({info['note']})")
        return version if info['supported'] else None
    except Exception as e:
        print(f"  [{label or os.path.basename(path)}]  Could not read: {e}")
        return None

# — SNSS parser ——————————————————————————————

def parse_session(path):
    data = open(path, 'rb').read()
    if data[:4] != b'SNSS': return []
    offset = 8
    nav_map = {}
    while offset + 3 <= len(data):
        sf = struct.unpack_from('<H', data, offset)[0]
        if sf == 0: break
        total = 2 + sf
        if offset + total > len(data): break
        cmd_id = data[offset + 2]
        contents = data[offset + 3: offset + 2 + sf]
        offset += total
        if cmd_id != 6 or len(contents) < 4: continue
        ps = struct.unpack_from('<I', contents, 0)[0]
        payload = contents[4:4+ps]
        pos = 0
        tab_id, pos = read_int32(payload, pos)
        nav_idx, pos = read_int32(payload, pos)
        url, pos = read_string(payload, pos)
        if not url or not url.startswith('http'): continue
        title, pos = read_string16(payload, pos)
        _, pos = read_string(payload, pos)
        _, pos = read_int32(payload, pos)
        _, pos = read_int32(payload, pos)
        _, pos = read_string(payload, pos)
        _, pos = read_int32(payload, pos)
        _, pos = read_string(payload, pos)
        _, pos = read_int32(payload, pos)
        ts_us, pos = read_int64(payload, pos)
        ts = chrome_ts(ts_us) if ts_us else None
        if tab_id not in nav_map: nav_map[tab_id] = {}
        nav_map[tab_id][nav_idx] = (ts, url, title or '', tab_id, nav_idx)

    results = []
    for navs in nav_map.values():
        for ts, url, title, tab_id, nav_idx in navs.values():
            results.append((ts, url, title, 'SESSION', f'tab={tab_id} nav={nav_idx}'))
    return results

# — Profile discovery ————————————————————————————

CHROME_VARIANTS = [
    os.path.join('AppData', 'Local', 'Google', 'Chrome', 'User Data'),
    os.path.join('AppData', 'Local', 'Google', 'Chrome Beta', 'User Data'),
    os.path.join('AppData', 'Local', 'Google', 'Chrome SxS', 'User Data'),
    os.path.join('AppData', 'Local', 'Chromium', 'User Data'),
]

def get_profiles(base_dir):
    """Return all subdirectories of base_dir that contain a History file."""
    if not os.path.isdir(base_dir):
        return []
    try:
        return [d for d in os.listdir(base_dir)
                if os.path.isdir(os.path.join(base_dir, d))
                and os.path.isfile(os.path.join(base_dir, d, 'History'))]
    except PermissionError:
        return []

LEGACY_SESSION_FILES = ['Current Session', 'Last Session', 'Current Tabs', 'Last Tabs']

def normalise_path(p):
    return p.replace('\\', os.sep).replace('/', os.sep)

def is_snss(path):
    try:
        with open(path, 'rb') as f: return f.read(4) == b'SNSS'
    except:
        return False

def is_sqlite(path):
    try:
        with open(path, 'rb') as f: return f.read(6) == b'SQLite'
    except:
        return False

def collect_from_profile(profile):
    h = os.path.join(profile, 'History')
    history = h if os.path.isfile(h) else None
    sessions = []
    s_dir = os.path.join(profile, 'Sessions')
    if os.path.isdir(s_dir):
        sessions.extend([os.path.join(s_dir, f) for f in sorted(os.listdir(s_dir))
                         if os.path.isfile(os.path.join(s_dir, f))])

    for name in LEGACY_SESSION_FILES:
        lp = os.path.join(profile, name)
        if os.path.isfile(lp) and is_snss(lp):
            sessions.append(lp)

    return history, sessions

def extract_username(profile_path, root):
    """Extract Windows username from profile path."""
    parts = profile_path.replace('\\', '/').split('/')
    # Look for pattern: .../Users/<username>/AppData/...
    for i, part in enumerate(parts):
        if part.lower() == 'users' and i + 1 < len(parts):
            return parts[i + 1]
    return os.path.basename(profile_path)


def find_all_profiles(root):
    """
    Scan root for all Chrome profiles across all users.
    Returns list of (profile_path, username, browser_label).
    """
    root = normalise_path(root)
    found = []

    # If root itself is a profile dir (has History)
    if os.path.isfile(os.path.join(root, 'History')):
        user = os.path.basename(root)
        found.append((root, user, 'Chrome'))
        return found

    # If root contains a Default/ profile dir directly (e.g. extracted zip)
    default_path = os.path.join(root, 'Default')
    if os.path.isdir(default_path) and os.path.isfile(os.path.join(default_path, 'History')):
        user = os.path.basename(root)
        found.append((default_path, user, 'Chrome/Default'))
        return found

    # Scan Users/* subdirectories
    users_dir = None
    for candidate in [root, os.path.join(root, 'Users')]:
        if os.path.isdir(candidate):
            users_dir = candidate
            break

    if users_dir:
        try:
            user_dirs = [
                d for d in os.listdir(users_dir)
                if os.path.isdir(os.path.join(users_dir, d))
                and d.lower() not in ('all users', 'default', 'default user', 'public')
            ]
        except PermissionError:
            user_dirs = []

        for username in user_dirs:
            user_home = os.path.join(users_dir, username)
            for variant in CHROME_VARIANTS:
                user_data = os.path.join(user_home, variant)
                if not os.path.isdir(user_data):
                    continue

                browser_label = variant.split(os.sep)[-3] if len(variant.split(os.sep)) >= 3 else 'Chrome'

                for prof_name in get_profiles(user_data):
                    profile_path = os.path.join(user_data, prof_name)
                    label = f'{browser_label}/{prof_name}'
                    found.append((profile_path, username, label))

    # Fallback: check if root is a user home
    if not found:
        for variant in CHROME_VARIANTS:
            user_data = os.path.join(root, variant)
            if not os.path.isdir(user_data):
                continue

            for prof_name in get_profiles(user_data):
                profile_path = os.path.join(user_data, prof_name)
                username = os.path.basename(root)
                found.append((profile_path, username, f'Chrome/{prof_name}'))

    return found


# — Per-profile parser —
# Every entry tuple: (ts, url, title, source, comment, user)

def parse_profile(profile, username):
    entries = []
    history_arg, session_args = collect_from_profile(profile)

    # Sessions
    print(f"  [Session Files]")
    for path in session_args:
        if not os.path.isfile(path):
            continue

        tmp = tempfile.mktemp(suffix='.snss')
        try:
            shutil.copy2(path, tmp)
            version = check_snss_version(tmp, label=os.path.basename(path))
            if version:
                for ts, url, title, source, comment in parse_session(tmp):
                    entries.append((ts, url, title, source, comment, username))
        except Exception as e:
            print(f"  [!] {os.path.basename(path)}: {e}", file=sys.stderr)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # History + Downloads
    if history_arg:
        tmp = tempfile.mktemp(suffix='.db')
        try:
            shutil.copy2(history_arg, tmp)
        except Exception as e:
            print(f"  [!] History (copy failed – Chrome may be open): {e}", file=sys.stderr)
            history_arg = None
        if history_arg:
            try:
                conn = sqlite3.connect(tmp)
                cur = conn.cursor()
                cur.execute("""
                    SELECT datetime((v.visit_time/1000000)-11644473600,'unixepoch'),
                           u.url, u.title, u.visit_count
                    FROM visits v JOIN urls u ON v.url = u.id
                    ORDER BY v.visit_time ASC
                """)
                for ts, url, title, visit_count in cur.fetchall():
                    entries.append((ts, url, title or '', 'HISTORY', f'visits={visit_count}', username))
                try:
                    DOWNLOAD_STATE = {1: 'COMPLETE', 2: 'CANCELLED', 4: 'INTERRUPTED'}
                    cur.execute("""
                        SELECT datetime((start_time/1000000)-11644473600,'unixepoch'),
                               tab_url, target_path, state, received_bytes, total_bytes
                        FROM downloads ORDER BY start_time ASC
                    """)
                    for ts, url, path, state, received, total in cur.fetchall():
                        status = DOWNLOAD_STATE.get(state, f'state={state}')
                        size = f'{received}/{total} bytes' if total else ''
                        comment = f'{status} | saved={path or ""} | {size}'
                        entries.append((ts, url or '', os.path.basename(path or ''), 'DOWNLOAD', comment, username))
                except Exception:
                    pass
                try:
                    cur.execute("""
                        SELECT datetime((v.visit_time/1000000)-11644473600,'unixepoch'),
                               u.url, kst.term
                        FROM keyword_search_terms kst
                        JOIN urls u ON kst.url_id = u.id
                        JOIN visits v ON v.url = u.id
                        ORDER BY v.visit_time ASC
                    """)
                    for ts, url, term in cur.fetchall():
                        entries.append((ts, url or '', term or '', 'SEARCH', f'query={term}', username))
                except Exception:
                    pass
                try:
                    cur.execute("""
                        SELECT datetime((last_visit_time/1000000)-11644473600,'unixepoch'),
                               url, title, typed_count
                        FROM urls WHERE typed_count > 0
                        ORDER BY last_visit_time ASC
                    """)
                    for ts, url, title, typed_count in cur.fetchall():
                        entries.append((ts, url or '', title or '', 'TYPED_URL', f'typed={typed_count} times', username))
                except Exception:
                    pass
                try:
                    cur.execute("SELECT url, title, datetime((last_visit_time/1000000)-11644473600,'unixepoch') FROM urls WHERE hidden = 1")
                    for url, title, ts in cur.fetchall():
                        entries.append((ts, url or '', title or '', 'HIDDEN_URL', 'hidden=1 – suppressed from omnibox (redirect/subframe, not user-deleted)', username))
                except Exception:
                    pass
                try:
                    CLEAR_PERIOD = {0: 'All time', 1: 'Last hour', 2: 'Last day', 3: 'Last week', 4: 'Last 4 weeks'}
                    clear_period = 'unknown'
                    for pf in ('Preferences', 'Secure Preferences'):
                        pp = os.path.join(profile, pf)
                        if os.path.isfile(pp):
                            try:
                                pd = json.load(open(pp, encoding='utf-8', errors='replace'))
                                tp = pd.get('browser', {}).get('clear_data', {}).get('time_period')
                                if tp is not None:
                                    clear_period = CLEAR_PERIOD.get(tp, f'period={tp}')
                                    break
                            except Exception:
                                pass
                    cur.execute("SELECT id, datetime((visit_time/1000000)-11644473600,'unixepoch') FROM visits ORDER BY id ASC")
                    rows = cur.fetchall()
                    for i in range(len(rows) - 1):
                        id_before, ts_before = rows[i]
                        id_after, ts_after = rows[i + 1]
                        gap = id_after - id_before - 1
                        if gap > 0:
                            comment = f'visit ids {id_before+1}-{id_after-1} missing ({gap} records deleted) | range={clear_period} | after={ts_before} before={ts_after}'
                            entries.append((ts_before, '', f'GAP of {gap} deleted visits', 'CLEARED_GAP', comment, username))
                except Exception:
                    pass
                conn.close()
            except Exception as e:
                print(f"  [!] History: {e}", file=sys.stderr)
            finally:
                if os.path.exists(tmp): os.unlink(tmp)

    # Favicons without History (visited but cleared)
    favicons_path = os.path.join(profile, 'Favicons')
    if os.path.isfile(favicons_path) and history_arg:
        from urllib.parse import urlparse
        history_hosts = set()
        tmp_h = tempfile.mktemp(suffix='.db')
        try:
            shutil.copy2(history_arg, tmp_h)
            try:
                c = sqlite3.connect(tmp_h)
                for (u,) in c.execute('SELECT url FROM urls'): history_hosts.add(urlparse(u).netloc)
                c.close()
            except Exception:
                pass
        except Exception as e:
            print(f"  [!] Favicons/History (copy failed – Chrome may be open): {e}", file=sys.stderr)
        finally:
            if os.path.exists(tmp_h): os.unlink(tmp_h)
        tmp_f = tempfile.mktemp(suffix='.db')
        try:
            shutil.copy2(favicons_path, tmp_f)
        except Exception as e:
            print(f"  [!] Favicons (copy failed – Chrome may be open): {e}", file=sys.stderr)
            tmp_f = None
        if tmp_f:
            seen_favicon_hosts = set()
            try:
                c = sqlite3.connect(tmp_f)
                for (page_url,) in c.execute('SELECT page_url FROM icon_mapping'):
                    host = urlparse(page_url).netloc
                    if host and host not in history_hosts and host not in seen_favicon_hosts:
                        seen_favicon_hosts.add(host)
                        entries.append((None, page_url, host, 'FAVICON_ONLY', 'favicon exists but no history – likely cleared', username))
                c.close()
            except Exception:
                pass
            finally:
                if os.path.exists(tmp_f): os.unlink(tmp_f)
    # Cookies
    cookies_path = os.path.join(profile, 'Network', 'Cookies')
    if os.path.isfile(cookies_path):
        tmp = tempfile.mktemp(suffix='.db')
        try:
            shutil.copy2(cookies_path, tmp)
        except Exception as e:
            print(f"  [!] Cookies (copy failed – Chrome may be open): {e}", file=sys.stderr)
            tmp = None
        if tmp:
            try:
                conn = sqlite3.connect(tmp)
                cur = conn.cursor()
                cur.execute("""
                    SELECT datetime((creation_utc/1000000)-11644473600,'unixepoch'),
                           host_key, name,
                           datetime((expires_utc/1000000)-11644473600,'unixepoch'),
                           is_secure, is_httponly
                    FROM cookies ORDER BY creation_utc ASC
                """)
                for ts, host, name, expires, secure, httponly in cur.fetchall():
                    url = 'https://' + host.strip('.')
                    flags = []
                    if secure: flags.append('secure')
                    if httponly: flags.append('httponly')
                    comment = f'expires={expires}' + (f" | {','.join(flags)}" if flags else '')
                    entries.append((ts, url, name or '', 'COOKIE', comment, username))
                conn.close()
            except Exception:
                pass
            finally:
                if os.path.exists(tmp): os.unlink(tmp)

    # Bookmarks
    bookmarks_path = os.path.join(profile, 'Bookmarks')
    if os.path.isfile(bookmarks_path):
        try:
            def _walk(node, folder, out):
                if node.get('type') == 'url':
                    ts_us = int(node.get('date_added', 0))
                    ts = chrome_ts(ts_us) if ts_us else None
                    out.append((ts, node.get('url', ''), node.get('name', ''),
                                'BOOKMARK', f'folder={folder}', username))
                for child in node.get('children', []):
                    _walk(child, node.get('name', folder), out)

            data = json.load(open(bookmarks_path, encoding='utf-8'))
            for root_name, root_node in data.get('roots', {}).items():
                _walk(root_node, root_name, entries)
        except Exception:
            pass

    # Top Sites
    topsites_path = os.path.join(profile, 'Top Sites')
    if os.path.isfile(topsites_path):
        tmp = tempfile.mktemp(suffix='.db')
        try:
            shutil.copy2(topsites_path, tmp)
        except Exception as e:
            print(f"  [!] Top Sites (copy failed – Chrome may be open): {e}", file=sys.stderr)
            tmp = None
        if tmp:
            try:
                conn = sqlite3.connect(tmp)
                cur = conn.cursor()
                cur.execute("SELECT url, title FROM top_sites")
                for url, title in cur.fetchall():
                    entries.append((None, url or '', title or '', 'TOP_SITE', 'most visited thumbnail', username))
                conn.close()
            except Exception:
                pass
            finally:
                if os.path.exists(tmp): os.unlink(tmp)

    # Saved Passwords
    login_path = os.path.join(profile, 'Login Data')
    if os.path.isfile(login_path):
        tmp = tempfile.mktemp(suffix='.db')
        try:
            shutil.copy2(login_path, tmp)
        except Exception as e:
            print(f"  [!] Login Data (copy failed – Chrome may be open): {e}", file=sys.stderr)
            tmp = None
        if tmp:
            try:
                conn = sqlite3.connect(tmp)
                cur = conn.cursor()
                cur.execute("""
                    SELECT datetime((date_created/1000000)-11644473600,'unixepoch'),
                           origin_url, username_value, times_used
                    FROM logins ORDER BY date_created ASC
                """)
                for ts, url, username_val, times_used in cur.fetchall():
                    comment = f'username={username_val} | times_used={times_used} | password=<encrypted>'
                    entries.append((ts, url or '', username_val or '', 'PASSWORD', comment, username))
                conn.close()
            except Exception:
                pass
            finally:
                if os.path.exists(tmp): os.unlink(tmp)

    # Autofill + Addresses
    webdata_path = os.path.join(profile, 'Web Data')
    if os.path.isfile(webdata_path):
        tmp = tempfile.mktemp(suffix='.db')
        try:
            shutil.copy2(webdata_path, tmp)
        except Exception as e:
            print(f"  [!] Web Data (copy failed – Chrome may be open): {e}", file=sys.stderr)
            tmp = None
        if tmp:
            try:
                conn = sqlite3.connect(tmp)
                cur = conn.cursor()
                cur.execute("""
                    SELECT datetime(date_created,'unixepoch'),
                           name, value, count
                    FROM autofill WHERE value != '' ORDER BY date_created ASC
                """)
                for ts, name, value, count in cur.fetchall():
                    comment = f'field={name} | used={count} times'
                    entries.append((ts, '', f'{name}: {value}', 'AUTOFILL', comment, username))

                try:
                    cur.execute("""
                        SELECT ap.date_modified,
                               n.first_name, n.last_name,
                               e.email, p.number,
                               ap.street_address, ap.city, ap.state, ap.zipcode, ap.country_name
                        FROM autofill_profiles ap
                        LEFT JOIN autofill_profile_names n ON ap.guid = n.guid
                        LEFT JOIN autofill_profile_emails e ON ap.guid = e.guid
                        LEFT JOIN autofill_profile_phones p ON ap.guid = p.guid
                    """)
                    for row in cur.fetchall():
                        date_mod, first, last, email, phone, street, city, state_val, zipcode, country = row
                        ts = datetime.datetime.utcfromtimestamp(int(date_mod)).strftime('%Y-%m-%d %H:%M:%S') if date_mod else None
                        full_name = ' '.join(filter(None, [first, last]))
                        addr_parts = ', '.join(filter(None, [street, city, state_val, zipcode, country]))
                        comment = f'email={email or ""} | phone={phone or ""} | addr={addr_parts}'
                        entries.append((ts, '', full_name or '(no name)', 'ADDRESS', comment, username))
                except Exception:
                    pass

                conn.close()
            except Exception:
                pass
            finally:
                if os.path.exists(tmp): os.unlink(tmp)

    # Signed-in Account
    for prefs_file in ('Preferences', 'Secure Preferences'):
        prefs_path = os.path.join(profile, prefs_file)
        if not os.path.isfile(prefs_path): continue
        try:
            data = json.load(open(prefs_path, encoding='utf-8', errors='replace'))
            accounts = data.get('account_info', [])
            if not accounts:
                acc = data.get('google', {}).get('services', {}).get('last_account_info', {})
                if acc: accounts = [acc]
            for acc in accounts:
                email = acc.get('email', '')
                full_name = acc.get('full_name', '') or acc.get('name', '')
                acct_id = acc.get('account_id', '') or acc.get('id', '')
                if not email: continue
                comment = f'account_id={acct_id} | name={full_name}'
                entries.append((None, 'https://myaccount.google.com/', email, 'GOOGLE_ACCT', comment, username))
            if accounts: break
        except Exception:
            pass

    local_state = os.path.join(os.path.dirname(profile), 'Local State')
    if os.path.isfile(local_state):
        try:
            data = json.load(open(local_state, encoding='utf-8', errors='replace'))
            cache = data.get('profile', {}).get('info_cache', {})
            prof_name = os.path.basename(profile)
            info = cache.get(prof_name, {})
            email = info.get('user_name', '')
            name = info.get('name', '')
            if email:
                entries.append((None, 'https://myaccount.google.com/', email, 'GOOGLE_ACCT', f'name={name} | from=Local State', username))
            clear_ts_us = data.get('browser', {}).get('last_clear_browsing_data_time', 0)
            if clear_ts_us:
                ts = chrome_ts(int(clear_ts_us))
                entries.append((ts, '', 'Clear Browsing Data executed', 'CLEAR_EVENT', f'last_clear_browsing_data_time={ts}', username))
        except Exception:
            pass

    # Extensions
    # Extensions
    for prefs_file in ('Secure Preferences', 'Preferences'):
        prefs_path = os.path.join(profile, prefs_file)
        if not os.path.isfile(prefs_path): continue
        try:
            data = json.load(open(prefs_path, encoding='utf-8', errors='replace'))
            exts = data.get('extensions', {}).get('settings', {})
            if not exts: continue
            for eid, e in exts.items():
                name = e.get('manifest', {}).get('name', '')
                ver = e.get('manifest', {}).get('version', '')
                enabled = not e.get('disable_reasons', {})
                if not name: continue
                state = 'enabled' if enabled else 'disabled'
                install = e.get('install_time', '')
                comment = f'id={eid} | {state} | installed={install}'
                entries.append((None, f'chrome-extension://{eid}/', f'{name} v{ver}', 'EXTENSION', comment, username))
            break
        except Exception:
            pass

    return entries
# — Main —
args = sys.argv[1:]

# Resolve profiles to scan
profiles_to_scan = []  # list of (profile_path, username, browser_label)

if args:
    for arg in args:
        arg = normalise_path(arg)
        found = find_all_profiles(arg)
        if found:
            profiles_to_scan.extend(found)
        else:
            print(f"[!] No Chrome profiles found under: {arg}", file=sys.stderr)
else:
    home = os.path.expanduser('~')
    found = find_all_profiles(home)
    if found:
        profiles_to_scan.extend(found)
    else:
        print("[!] No Chrome profiles found. Pass a path explicitly.", file=sys.stderr)
        sys.exit(1)

if not profiles_to_scan:
    print("[!] No Chrome profiles found.", file=sys.stderr)
    sys.exit(1)

# Parse all profiles
all_entries = []

# — Build output file paths (same folder as this script, timestamped) ——
_ts_tag  = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
_out_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(_out_dir, f'chrome_forensic_{_ts_tag}.csv')
log_path = os.path.join(_out_dir, f'chrome_forensic_{_ts_tag}_skipped.log')

# Redirect stderr → log file (keeps console output too)
sys.stderr = _TeeStderr(log_path)
print(f"[*] CSV output  : {csv_path}", file=sys.stderr)
print(f"[*] Skipped log : {log_path}", file=sys.stderr)

print(f"\n[+] Found {len(profiles_to_scan)} Chrome profile(s)\n")

for profile_path, username, browser_label in profiles_to_scan:
    print(f"[Profile] {profile_path} | user={username} | browser={browser_label}")
    entries = parse_profile(profile_path, username)

    # Deduplicate HISTORY + SESSION by URL within this profile
    url_seen = {}
    other = []
    for e in entries:
        ts, url, title, source, comment, user = e
        if source in ('HISTORY', 'SESSION', 'BOTH'):
            if url not in url_seen:
                url_seen[url] = e
            else:
                ex = url_seen[url]
                ex_source = ex[3]
                best_src = 'BOTH' if {'HISTORY', 'SESSION'} <= {source, ex_source} else \
                           ('HISTORY' if 'HISTORY' in (source, ex_source) else source)
                best_ts = min(t for t in [ts, ex[0]] if t) if ts and ex[0] else (ts or ex[0])
                best_title = ex[2] or title
                best_comment = ex[4] or comment
                url_seen[url] = (best_ts, url, best_title, best_src, best_comment, user)
        else:
            other.append(e)

    all_entries.extend(list(url_seen.values()) + other)
    print()

all_entries.sort(key=lambda x: (x[5], x[0] or ''))

# — Output —

w = 200
SEP = '-' * w

source_counts = {}
for e in all_entries:
    source_counts[e[3]] = source_counts.get(e[3], 0) + 1

print(SEP)
print(f"| WINDOWS CHROME FORENSIC REPORT | Total entries: {len(all_entries)} | Users: {len(profiles_to_scan)}")
print(' | '.join(f"{k}: {v}" for k, v in sorted(source_counts.items())))
print(SEP)
print(f"{'#':<5} {'Source':<10} {'Date Time (UTC)':<22} {'URL':<55} {'Title':<35} {'Comments':<45} {'User'}")
print(SEP)

for i, (ts, url, title, source, comment, user) in enumerate(all_entries, 1):
    ts_str = (ts or '(no timestamp)')[:19]
    url_str = url[:53]
    title_str = title[:33]
    comment_str = comment[:43]
    print(f"{i:<5} {source:<10} {ts_str:<22} {url_str:<55} {title_str:<35} {comment_str:<45} {user}")

print(SEP)

# — Write CSV ——————————————————————————————————————
with open(csv_path, 'w', newline='', encoding='utf-8-sig') as fh:
    w_csv = csv.writer(fh)
    w_csv.writerow(['#', 'Source', 'Date Time (UTC)', 'URL', 'Title', 'Comments', 'User'])
    for i, (ts, url, title, source, comment, user) in enumerate(all_entries, 1):
        w_csv.writerow([i, source, (ts or '')[:19], url, title, comment, user])
print(f"\n[+] CSV saved  → {csv_path}  ({len(all_entries)} rows)")

# — Close log ——————————————————————————————————————
if hasattr(sys.stderr, 'close'):
    sys.stderr.flush()
    sys.stderr.close()
    sys.stderr = sys.__stderr__
print(f"[+] Log saved  → {log_path}")