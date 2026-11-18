#!/usr/bin/env python3
"""مزامنة أكواد الاشتراك من لوحة فكسر بلس إلى منتجات الأكواد الرقمية في سلة.

الأوضاع:
  sync   (افتراضي) يضيف الأكواد الجديدة المتاحة في اللوحة إلى منتجها الصحيح في سلة.
  check  الفحص اليومي: يقارن عدد الأكواد في سلة مع المتاح في اللوحة ويبلغ عن أي خلل.
  auth   ربط سلة لأول مرة: يحول كود الموافقة (SALLA_OAUTH_CODE) إلى توكن ويحفظه مشفراً.

الأمان: الأكواد لا تُطبع أبداً في السجلات (المستودع عام). السجل والتوكنات محفوظة في
state.enc مشفرة بمفتاح SYNC_KEY، والأكواد نفسها لا تُحفظ، فقط بصمة HMAC وآخر حرفين.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(HERE, 'config.json'), encoding='utf-8'))
STATE_PATH = os.path.join(HERE, 'state.enc')
KEY = os.environ.get('SYNC_KEY', '')
SECRETS = []  # كل قيمة حساسة تُضاف هنا وتُحجب من أي رسالة تُطبع


def now():
    return int(time.time())


def tail(code):
    return '…' + code[-2:]


def redact(s):
    s = str(s)
    for v in SECRETS:
        if v and len(v) >= 4:
            s = s.replace(v, '[محجوب]')
    return s[:400]


def log(*a):
    print(redact(' '.join(str(x) for x in a)), flush=True)


def fp(code):
    """بصمة الكود: HMAC بمفتاح سري، فما يقدر أحد يرجع منها للكود."""
    return hmac.new(KEY.encode(), code.strip().encode(), hashlib.sha256).hexdigest()[:32]


# ---------------------------------------------------------------- HTTP
class HttpError(Exception):
    def __init__(self, status, body):
        super().__init__('HTTP %s' % status)
        self.status, self.body = status, body


def http(method, url, headers=None, body=None, form=None, timeout=40):
    h = {'Accept': 'application/json', 'User-Agent': 'fxr-codesync/1.0'}
    h.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h['Content-Type'] = 'application/json'
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h['Content-Type'] = 'application/x-www-form-urlencoded'
    last = None
    for attempt in range(4):
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                j = json.loads(raw)
            except Exception:
                j = {'raw': raw[:300].decode('utf8', 'replace')}
            if e.code == 429 or e.code >= 500:
                last = HttpError(e.code, j)
                time.sleep(4 * (attempt + 1))
                continue
            raise HttpError(e.code, j)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
            time.sleep(4 * (attempt + 1))
    raise last if isinstance(last, Exception) else RuntimeError('network')


def err_text(e):
    if isinstance(e, HttpError):
        b = e.body if isinstance(e.body, dict) else {}
        msg = b.get('message') or b.get('error_description') or b.get('error') or ''
        if isinstance(b.get('error'), dict):
            msg = b['error'].get('message') or json.dumps(b['error'], ensure_ascii=False)
        return redact('HTTP %s %s' % (e.status, msg if isinstance(msg, str) else json.dumps(msg, ensure_ascii=False)))
    return redact(type(e).__name__ + ': ' + str(e))


# ---------------------------------------------------------------- الحالة المشفرة
def openssl(args, data):
    p = subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '200000', '-md', 'sha256', '-a', '-A'] + args +
                       ['-pass', 'env:SYNC_KEY'], input=data, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError('openssl failed (المفتاح SYNC_KEY غلط؟)')
    return p.stdout


def load_state():
    if not os.path.exists(STATE_PATH):
        return {'v': 1, 'salla': {}, 'ledger': {}, 'init': {}, 'alerts': {}}
    raw = open(STATE_PATH, 'rb').read().strip()
    st = json.loads(openssl(['-d'], raw + b'\n'))
    st.setdefault('salla', {}); st.setdefault('ledger', {}); st.setdefault('init', {}); st.setdefault('alerts', {})
    return st


def save_state(st):
    out = openssl(['-salt'], json.dumps(st, ensure_ascii=False, sort_keys=True).encode())
    with open(STATE_PATH, 'wb') as f:
        f.write(out + b'\n')
    open(os.path.join(HERE, '.state_changed'), 'w').write('1')


# ---------------------------------------------------------------- لوحة فكسر
def fxr_get(path, params):
    key = os.environ.get('FXR_API_KEY', '')
    if not key:
        raise RuntimeError('FXR_API_KEY ناقص')
    url = CFG['fxr_api'] + path + '?' + urllib.parse.urlencode(params)
    return http('GET', url, headers={'Authorization': 'Bearer ' + key})


def fxr_codes(package_id, status):
    out, page = [], 1
    while True:
        j = fxr_get('/codes', {'status': status, 'package': package_id, 'per_page': 100, 'page': page})
        data = (j or {}).get('data') or []
        out += data
        meta = (j or {}).get('meta') or {}
        last = meta.get('last_page') or 1
        if page >= last or not data:
            break
        page += 1
    return out


def fxr_package_names():
    try:
        j = fxr_get('/packages', {'per_page': 100})
        return {p.get('id'): p.get('name') for p in (j or {}).get('data') or []}
    except Exception as e:
        log('تنبيه: ما قدرت أقرأ الباقات من اللوحة:', err_text(e))
        return None


# ---------------------------------------------------------------- سلة
def salla_token(st):
    s = st['salla']
    if not s.get('refresh_token') and not s.get('access_token'):
        return None
    if s.get('access_token') and s.get('expires_at', 0) - now() > 2 * 86400:
        SECRETS.append(s['access_token'])
        return s['access_token']
    cid, csec = CFG.get('salla_client_id') or os.environ.get('SALLA_CLIENT_ID', ''), os.environ.get('SALLA_CLIENT_SECRET', '')
    j = http('POST', CFG['salla_token_url'], form={'grant_type': 'refresh_token', 'refresh_token': s['refresh_token'],
                                                    'client_id': cid, 'client_secret': csec})
    store_token(st, j)
    save_state(st)  # يُحفظ فوراً لأن توكن التحديث يُستخدم مرة وحدة
    log('تم تجديد توكن سلة')
    return st['salla']['access_token']


def store_token(st, j):
    if not j or not j.get('access_token'):
        raise RuntimeError('رد سلة ما فيه access_token')
    exp = j.get('expires_in')
    exp_at = now() + int(exp) if exp else int(j.get('expires') or now() + 13 * 86400)
    if exp_at > 10 ** 11:
        exp_at //= 1000
    st['salla'] = {'access_token': j['access_token'], 'refresh_token': j.get('refresh_token') or st['salla'].get('refresh_token'),
                   'expires_at': exp_at}
    SECRETS.append(j['access_token'])


def salla(method, path, tok, body=None):
    return http(method, CFG['salla_api'] + path, headers={'Authorization': 'Bearer ' + tok}, body=body)


def salla_quantity(tok, pid):
    j = salla('GET', '/products/%s' % pid, tok)
    d = (j or {}).get('data') or {}
    q = d.get('quantity')
    return None if q is None else int(q)


# ---------------------------------------------------------------- التنبيهات (GitHub Issues)
ALERTS = []


def alert(key, title, body, every=86400):
    ALERTS.append((key, title, body, every))


def flush_alerts(st):
    repo, tok = os.environ.get('GITHUB_REPOSITORY'), os.environ.get('GITHUB_TOKEN')
    sent = False
    for key, title, body, every in ALERTS:
        log('⚠️', title, '—', body.replace('\n', ' | '))
        last = st['alerts'].get(key, 0)
        if now() - last < every:
            continue
        if repo and tok:
            try:
                http('POST', 'https://api.github.com/repos/%s/issues' % repo,
                     headers={'Authorization': 'Bearer ' + tok, 'Accept': 'application/vnd.github+json'},
                     body={'title': '[أكواد سلة] ' + title, 'body': redact(body) + '\n\n_تنبيه آلي من مزامنة الأكواد._',
                           'labels': ['codesync']})
                st['alerts'][key] = now()
                sent = True
            except Exception as e:
                log('ما قدرت أفتح تنبيه في GitHub:', err_text(e))
    return sent


# ---------------------------------------------------------------- الفحص والتحقق
def collect(names):
    """يرجع الأكواد المتاحة لكل منتج بعد التحقق من: الحالة، الباقة الصحيحة، الشكل، وعدم التكرار."""
    pat = re.compile(CFG['code_pattern'])
    per, owner = {}, {}
    for k, m in CFG['products'].items():
        if names is not None:
            nm = names.get(m['panel_package_id'])
            if nm != m['panel_package_name']:
                alert('pkg-' + k, 'الباقة في اللوحة تغيّرت لـ ' + m['label'],
                      'كان المتوقع باقة «%s» (%s) لكن اللوحة ترجع: %s. وقفت مزامنة هذا المنتج لين تتأكد.' %
                      (m['panel_package_name'], m['panel_package_id'], nm or 'غير موجودة'))
                per[k] = None
                continue
        rows = fxr_codes(m['panel_package_id'], 'unused')
        good = []
        for r in rows:
            c = (r.get('code') or '').strip()
            if c:
                SECRETS.append(c)
            if r.get('status') != 'unused':
                continue  # 1) لازم يكون متاح في اللوحة
            if r.get('package_id') and r['package_id'] != m['panel_package_id']:
                alert('wrongpkg-' + fp(c), 'كود في غير باقته', 'كود ينتهي بـ %s رجع مع %s لكن باقته في اللوحة مختلفة. ما أضفته.' % (tail(c), m['label']))
                continue  # 2) لازم يكون من باقة هذا المنتج
            if not pat.match(c):
                alert('badfmt-' + fp(c), 'كود بشكل غريب', 'كود ينتهي بـ %s شكله غير متوقع، ما أضفته.' % tail(c))
                continue
            h = fp(c)
            if h in owner and owner[h] != k:
                alert('dup2-' + h, 'كود موجود في باقتين', 'كود ينتهي بـ %s موجود في %s و%s باللوحة. ما أضفته لأي منهم.' %
                      (tail(c), CFG['products'][owner[h]]['label'], m['label']))
                owner[h] = None
                continue
            owner[h] = k
            good.append((h, c))
        seen, uniq = set(), []
        for h, c in good:  # 3) بدون تكرار داخل نفس الدفعة
            if h not in seen:
                seen.add(h); uniq.append((h, c))
        per[k] = uniq
    for k in per:  # كود ظهر في باقتين يُستبعد من الاثنين
        if per[k] is not None:
            per[k] = [(h, c) for h, c in per[k] if owner.get(h) == k]
    return per


def push(st, tok, k, items):
    m = CFG['products'][k]
    pid, chunk = m['salla_product_id'], CFG.get('push_chunk', 50)
    added = 0
    for i in range(0, len(items), chunk):
        part = items[i:i + chunk]
        try:
            salla('POST', '/products/%s/digital-codes' % pid, tok, body={'codes': [c for _, c in part]})
            for h, c in part:
                st['ledger'][h] = {'p': k, 'at': now(), 't': c[-2:]}
            added += len(part)
        except HttpError as e:
            if e.status in (401, 403):
                raise
            log('سلة رفضت دفعة (%d) لـ %s: %s — أجرب واحد واحد' % (len(part), m['label'], err_text(e)))
            for h, c in part:
                try:
                    salla('POST', '/products/%s/digital-codes' % pid, tok, body={'codes': [c]})
                    st['ledger'][h] = {'p': k, 'at': now(), 't': c[-2:]}
                    added += 1
                except HttpError as e2:
                    if e2.status in (401, 403):
                        raise
                    alert('rej-' + h, 'سلة رفضت كود', 'سلة رفضت كود ينتهي بـ %s لـ %s: %s' % (tail(c), m['label'], err_text(e2)))
        save_state(st)  # يحفظ بعد كل دفعة عشان ما يتكرر أي كود لو انقطع التشغيل
    return added


def run_sync(st):
    per = collect(fxr_package_names())
    tok = salla_token(st)
    for k, items in per.items():
        if items is None:
            continue
        m = CFG['products'][k]
        if not st['init'].get(k):
            if m.get('init') == 'assume_on_salla':
                for h, c in items:
                    st['ledger'].setdefault(h, {'p': k, 'at': now(), 't': c[-2:], 'seed': 1})
                log('بداية %s: اعتبرت %d كود موجود مسبقاً في سلة' % (m['label'], len(items)))
            st['init'][k] = now()
            save_state(st)
            if m.get('init') == 'assume_on_salla':
                continue
        clash = [(h, c) for h, c in items if h in st['ledger'] and st['ledger'][h]['p'] != k]
        for h, c in clash:
            alert('moved-' + h, 'كود انتقل لباقة ثانية', 'كود ينتهي بـ %s أضفته سابقاً لـ %s والحين صار في %s باللوحة. ما كررته. راجعه.' %
                  (tail(c), CFG['products'][st['ledger'][h]['p']]['label'], m['label']))
        new = [(h, c) for h, c in items if h not in st['ledger']]
        log('%s: متاح في اللوحة %d، جديد %d' % (m['label'], len(items), len(new)))
        if not new:
            continue
        if not tok:
            alert('noauth', 'ربط سلة ناقص', 'فيه %d كود جديد جاهز لـ %s بس ربط سلة ما اكتمل. كمّل خطوات الربط.' % (len(new), m['label']), every=86400)
            continue
        n = push(st, tok, k, new)
        log('%s: أضفت %d كود لسلة' % (m['label'], n))
    st['last_sync'] = now()


def run_check(st):
    tok = salla_token(st)
    if not tok:
        alert('noauth', 'ربط سلة ناقص', 'الفحص اليومي ما اشتغل لأن ربط سلة ما اكتمل.')
        return
    names = fxr_package_names()
    lines = []
    for k, m in CFG['products'].items():
        unused = {fp((r.get('code') or '').strip()) for r in fxr_codes(m['panel_package_id'], 'unused') if r.get('code')}
        mine = [h for h, e in st['ledger'].items() if e['p'] == k]
        used_now = [h for h in mine if h not in unused]
        still = len(mine) - len(used_now)
        q = salla_quantity(tok, m['salla_product_id'])
        expected = still + int(m.get('foreign_on_salla') or 0)
        lines.append('%s: في سلة %s، المتوقع %d كحد أقصى (متاح باللوحة ومضاف %d + أكواد قديمة من خارج اللوحة %d)' %
                     (m['label'], q, expected, still, int(m.get('foreign_on_salla') or 0)))
        if q is not None and q > expected:
            cands = ', '.join('…' + st['ledger'][h]['t'] for h in used_now[-15:])
            alert('qty-' + k + '-' + str(q), 'أكواد مستخدمة باقية في سلة: ' + m['label'],
                  'سلة فيها %d كود لـ %s والمفروض ما يزيد عن %d. يعني فيه %d كود انستخدم من اللوحة وهو باقي معروض في سلة.\n'
                  'آخر الأكواد اللي انستخدمت باللوحة (آخر حرفين): %s\nالفحص اليومي في المتصفح بيحذفها، أو احذفها يدوياً من صفحة المنتج.' %
                  (q, m['label'], expected, q - expected, cands or '—'))
    if names is None:
        alert('panel-api', 'قراءة الباقات من اللوحة فشلت', 'تأكد إن مفتاح API اللوحة فعّال وفيه صلاحية read:codes و read:packages.')
    st['last_check'] = now()
    st['last_check_report'] = lines
    for l in lines:
        log(l)


def run_auth(st):
    code = os.environ.get('SALLA_OAUTH_CODE', '').strip()
    if not code:
        raise RuntimeError('حط كود الموافقة من سلة في خانة salla_code')
    SECRETS.append(code)
    cid, csec = CFG.get('salla_client_id') or os.environ.get('SALLA_CLIENT_ID', ''), os.environ.get('SALLA_CLIENT_SECRET', '')
    j = http('POST', CFG['salla_token_url'], form={'grant_type': 'authorization_code', 'code': code, 'client_id': cid,
                                                    'client_secret': csec, 'redirect_uri': CFG['salla_redirect_uri'],
                                                    'scope': 'offline_access'})
    store_token(st, j)
    save_state(st)
    tok = st['salla']['access_token']
    for k, m in CFG['products'].items():
        q = salla_quantity(tok, m['salla_product_id'])
        log('تم الربط ✓ — %s: في سلة %s كود' % (m['label'], q))


def main():
    mode = (sys.argv[1] if len(sys.argv) > 1 else 'sync').strip()
    if not KEY or len(KEY) < 16:
        print('SYNC_KEY ناقص أو قصير (لازم 16 حرف أو أكثر)')
        return 2
    for v in ('FXR_API_KEY', 'SALLA_CLIENT_SECRET'):
        SECRETS.append(os.environ.get(v, ''))
    st = load_state()
    for e in st['salla'].values():
        if isinstance(e, str):
            SECRETS.append(e)
    rc = 0
    try:
        {'sync': run_sync, 'check': run_check, 'auth': run_auth}[mode](st)
    except Exception as e:
        rc = 1
        t = err_text(e)
        log('خطأ:', t)
        if isinstance(e, HttpError) and e.status in (401, 403):
            alert('auth-' + mode, 'صلاحية مرفوضة', 'رجع %s أثناء %s. غالباً مفتاح اللوحة أو ربط سلة يحتاج تجديد.' % (t, mode))
        else:
            alert('err-' + mode, 'المزامنة واجهت خطأ', t, every=6 * 3600)
    if mode != 'auth':
        if flush_alerts(st) or mode == 'check':
            save_state(st)
    return rc


if __name__ == '__main__':
    sys.exit(main())
