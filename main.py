from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.core.window import Window
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem

import hashlib
import hmac
import requests
import time
import secrets
import socket
import json
import ssl
from ecdsa import SigningKey, SECP256k1
from ecdsa.curves import SECP256k1 as ecdsa_curve
from typing import Tuple, Optional, List

try:
    from mnemonic import Mnemonic
    MNEMONIC_AVAILABLE = True
except ImportError:
    MNEMONIC_AVAILABLE = False

try:
    import socks
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False

SHOW_RAW_RESPONSE = True
SCAN_COUNT = 20
GAP_LIMIT = 20

API_ENDPOINTS = [
    "https://blockstream.info/api/address/{}",
    "https://mempool.space/api/address/{}",
    "https://api.blockcypher.com/v1/btc/main/addrs/{}/balance",
    "https://blockchain.info/rawaddr/{}",
    "https://api.bitaps.com/btc/v1/blockchain/address/{}/state",
]

ELECTRUM_SERVERS = [
    "electrum.blockstream.info:50002:s",
    "electrum.hodlister.co:50002:s",
    "electrum3.hodlister.co:50002:s",
    "electrum5.hodlister.co:50002:s",
    "unholy.fiatfaucet.com:50002:s",
    "horsey.cryptocowboys.net:50002:s",
    "bitcoin.grey.pw:50002:s",
    "fulcrum.sethforprivacy.com:50002:s",
    "electrum.bitaroo.net:50002:s",
    "electrum.jochen-hoenicke.de:50006:s",
    "electrum.emzy.de:50002:s",
    "electrum.hsmiths.com:50002:s",
    "ecdsa.net:110:s",
    "fortress.qtornado.com:443:s",
    "smmalis37.ddns.net:50002:s",
    "stavver.dyshek.org:50002:s",
    "fulcrum.grey.pw:51002:s",
    "blackie.c3-soft.com:57002:s",
    "bitcoins.sk:56002:s",
    "exs.dyshek.org:50002:s",
    "node1.btccuracao.com:50002:s",
    "alviss.coinjoined.com:50002:s",
    "blockstream.info:700:s",
    "btc.electroncash.dk:60002:s",
    "elx.bitske.com:50002:s",
    "skbxmit.coinjoined.com:50002:s",
    "btc.ocf.sh:50002:s",
    "bitcoin.aranguren.org:50002:s",
    "2ex.digitaleveryware.com:50002:s",
    "bitcoin.lu.ke:50002:s",
    "VPS.hsmiths.com:50002:s",
    "tardis.bauerj.eu:50002:s"
]

def enable_tor_if_running():
    if not TOR_AVAILABLE:
        return False
    try:
        test_sock = socks.socksocket()
        test_sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        test_sock.settimeout(3)
        test_sock.connect(("www.blockstream.info", 443))
        test_sock.close()
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
        return True
    except Exception:
        return False

def connect_to_electrum_server(server: str):
    if not TOR_AVAILABLE:
        return None
    try:
        host, port, proto = server.split(':')
        port = int(port)
        use_ssl = proto == 's'
        sock = socket.create_connection((host, port), timeout=10)
        if use_ssl:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        return sock
    except Exception:
        return None

def query_address_via_electrum(address: str):
    using_tor = enable_tor_if_running()
    if not using_tor:
        return None, "Tor không hoạt động", None
    for server in ELECTRUM_SERVERS:
        sock = connect_to_electrum_server(server)
        if not sock:
            continue
        try:
            script_hash = address_to_scripthash(address)
            req = {
                "id": 1,
                "method": "blockchain.scripthash.get_balance",
                "params": [script_hash]
            }
            request = json.dumps(req) + '\n'
            sock.sendall(request.encode())
            response = sock.recv(2048).decode()
            data = json.loads(response)
            if 'result' in data:
                balance = data['result']
                confirmed = balance.get('confirmed', 0)
                unconfirmed = balance.get('unconfirmed', 0)
                total_sats = confirmed + unconfirmed
                return (total_sats / 100_000_000, None, balance)
        except Exception:
            pass
        finally:
            sock.close()
    return None, "Tất cả Electrum server đều lỗi", None

def address_to_scripthash(addr: str):
    if addr.startswith('1'):
        from base58 import b58decode_check
        decoded = b58decode_check(addr)
        pubkey_hash = decoded[1:]
        script = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
    elif addr.startswith('3'):
        from base58 import b58decode_check
        decoded = b58decode_check(addr)
        script_hash = decoded[1:]
        script = b'\xa9\x14' + script_hash + b'\x87'
    elif addr.startswith('bc1'):
        from segwit_addr import decode
        hrp, data = decode('bc', addr)
        if len(data) == 20:
            script = b'\x00\x14' + bytes(data)
        else:
            raise ValueError("Chưa hỗ trợ bc1 không phải P2WPKH")
    else:
        raise ValueError("Chưa hỗ trợ loại địa chỉ này")
    import hashlib
    h = hashlib.new('ripemd160', hashlib.sha256(script).digest()).digest()
    return h[::-1].hex()

def derive_private_key_from_seed(seed_bytes: bytes, path: str) -> bytes:
    h = hmac.new(b"Bitcoin seed", seed_bytes, hashlib.sha512).digest()
    master_key = h[:32]
    master_chain_code = h[32:]
    def derive_key(parent_key, parent_chain_code, index):
        index_bytes = (index + 0x80000000).to_bytes(4, 'big')
        data = b'\x00' + parent_key + index_bytes
        h = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
        return h[:32], h[32:]
    key = master_key
    chain_code = master_chain_code
    for level in path.split("/")[1:]:
        if level.endswith("'"):
            index = int(level[:-1])
        else:
            index = int(level)
        key, chain_code = derive_key(key, chain_code, index)
    return key

def seed_to_private_keys_multi_path(seed_phrase: str, max_addresses: int = 20) -> Optional[dict]:
    if not MNEMONIC_AVAILABLE:
        return None
    mnemo = Mnemonic("english")
    if not mnemo.check(seed_phrase):
        return None
    seed = mnemo.to_seed(seed_phrase, passphrase="")
    paths = {
        "BIP44_P2PKH": "m/44'/0'/0'/0/{}",
        "BIP49_P2SH": "m/49'/0'/0'/0/{}",
        "BIP84_P2WPKH": "m/84'/0'/0'/0/{}",
        "BIP86_P2TR": "m/86'/0'/0'/0/{}",
    }
    results = {}
    for name, path_template in paths.items():
        privkeys = []
        for i in range(max_addresses):
            path = path_template.format(i)
            try:
                privkey_bytes = derive_private_key_from_seed(seed, path)
                privkey_int = int.from_bytes(privkey_bytes, 'big')
                if 0 < privkey_int < ecdsa_curve.order:
                    privkeys.append(privkey_bytes.hex())
                else:
                    privkeys.append(None)
            except Exception:
                privkeys.append(None)
        results[name] = privkeys
    return results

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2bc830a3
SECP256K1_ORDER = ecdsa_curve.order

def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data, spec):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ spec
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, spec):
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + '1' + ''.join([BECH32_CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret, maxv, max_acc = 0, 0, [], (1 << tobits) - 1, (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def encode_segwit_address(hrp, witver, witprog):
    spec = BECH32M_CONST if witver > 0 else BECH32_CONST
    data = convertbits(witprog, 8, 5)
    if data is None:
        return None
    return bech32_encode(hrp, [witver] + data, spec)

def hash160(pubkey):
    return hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()

def encode_base58_checksum(data):
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(data + checksum, 'big')
    res = ''
    while n > 0:
        n, r = divmod(n, 58)
        res = b58_digits[r] + res
    pad = 0
    for b in data + checksum:
        if b == 0x00:
            pad += 1
        else:
            break
    return '1' * pad + res

def to_wif(privkey, compressed=True):
    extended = b'\x80' + privkey
    if compressed:
        extended += b'\x01'
    return encode_base58_checksum(extended)

def to_p2pkh_address(pubkey):
    return encode_base58_checksum(b'\x00' + hash160(pubkey))

def to_p2sh_segwit_address(pubkey_compressed):
    redeem_script = b'\x00\x14' + hash160(pubkey_compressed)
    return encode_base58_checksum(b'\x05' + hash160(redeem_script))

def to_p2wpkh_address(pubkey_compressed):
    return encode_segwit_address('bc', 0, hash160(pubkey_compressed))

def to_p2tr_address(pubkey_compressed):
    return encode_segwit_address('bc', 1, pubkey_compressed[1:])

def generate_new_private_key() -> str:
    while True:
        privkey_bytes = secrets.token_bytes(32)
        privkey_int = int.from_bytes(privkey_bytes, 'big')
        if 0 < privkey_int < SECP256K1_ORDER:
            return privkey_bytes.hex()

def get_address_balance(address: str, api_url_template: str) -> Tuple[Optional[float], Optional[str], Optional[dict]]:
    try:
        url = api_url_template.format(address)
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        if "balance" in data:
            balance_sats = data.get("balance", 0)
        else:
            stats = data.get('chain_stats', {})
            funded = stats.get('funded_txo_sum', 0)
            spent = stats.get('spent_txo_sum', 0)
            balance_sats = funded - spent
        return (balance_sats / 100_000_000, None, data)
    except Exception:
        return (None, "Lỗi truy vấn", None)

def get_balance_multi_api(address: str) -> Tuple[Optional[float], Optional[str], Optional[dict]]:
    for api in API_ENDPOINTS:
        balance, error, raw = get_address_balance(address, api)
        if balance is not None:
            return balance, error, raw
    return None, "Tất cả API đều lỗi", None

def get_balance_via_electrum(address: str) -> Tuple[Optional[float], Optional[str], Optional[dict]]:
    using_tor = enable_tor_if_running()
    if not using_tor:
        return None, "Tor không hoạt động", None
    for server in ELECTRUM_SERVERS:
        sock = connect_to_electrum_server(server)
        if not sock:
            continue
        try:
            script_hash = address_to_scripthash(address)
            req = {
                "id": 1,
                "method": "blockchain.scripthash.get_balance",
                "params": [script_hash]
            }
            request = json.dumps(req) + '\n'
            sock.sendall(request.encode())
            response = sock.recv(2048).decode()
            data = json.loads(response)
            if 'result' in data:
                balance = data['result']
                confirmed = balance.get('confirmed', 0)
                unconfirmed = balance.get('unconfirmed', 0)
                total_sats = confirmed + unconfirmed
                return (total_sats / 100_000_000, None, balance)
        except Exception:
            pass
        finally:
            sock.close()
    return None, "Tất cả Electrum server đều lỗi", None

class BitcoinApp(App):
    def build(self):
        self.title = "Bitcoin Toolkit v14.0"
        Window.clearcolor = (0.1, 0.1, 0.1, 1)

        panel = TabbedPanel()
        panel.do_default_tab = False

        # Tab 1: Nhập Private Key
        tab1 = TabbedPanelItem(text='Private Key')
        layout1 = BoxLayout(orientation='vertical', padding=10, spacing=10)

        self.pk_input = TextInput(hint_text='Nhập private key hex (64 ký tự)', multiline=False)
        btn_gen = Button(text='Tạo Private Key mới', size_hint_y=None, height=50)
        btn_gen.bind(on_press=self.generate_private_key)

        btn_check = Button(text='Kiểm tra số dư', size_hint_y=None, height=50)
        btn_check.bind(on_press=lambda x: self.check_private_key_balance(self.pk_input.text))

        layout1.add_widget(Label(text='Nhập Private Key Hex', size_hint_y=None, height=40))
        layout1.add_widget(self.pk_input)
        layout1.add_widget(btn_gen)
        layout1.add_widget(btn_check)

        tab1.content = layout1
        panel.add_widget(tab1)

        # Tab 2: Seed Phrase
        tab2 = TabbedPanelItem(text='Seed Phrase')
        layout2 = BoxLayout(orientation='vertical', padding=10, spacing=10)

        self.seed_input = TextInput(hint_text='Nhập seed phrase (12/24 từ)', multiline=True)
        btn_gen_seed = Button(text='Tạo Seed mới', size_hint_y=None, height=50)
        btn_gen_seed.bind(on_press=self.generate_seed)

        btn_scan_seed = Button(text='Quét Seed', size_hint_y=None, height=50)
        btn_scan_seed.bind(on_press=lambda x: self.scan_seed_phrase(self.seed_input.text))

        layout2.add_widget(Label(text='Nhập Seed Phrase', size_hint_y=None, height=40))
        layout2.add_widget(self.seed_input)
        layout2.add_widget(btn_gen_seed)
        layout2.add_widget(btn_scan_seed)

        tab2.content = layout2
        panel.add_widget(tab2)

        # Tab 3: Kiểm tra địa chỉ
        tab3 = TabbedPanelItem(text='Địa chỉ')
        layout3 = BoxLayout(orientation='vertical', padding=10, spacing=10)

        self.addr_input = TextInput(hint_text='Nhập địa chỉ Bitcoin', multiline=False)
        btn_check_addr = Button(text='Kiểm tra số dư', size_hint_y=None, height=50)
        btn_check_addr.bind(on_press=lambda x: self.check_address_balance(self.addr_input.text))

        layout3.add_widget(Label(text='Kiểm tra địa chỉ', size_hint_y=None, height=40))
        layout3.add_widget(self.addr_input)
        layout3.add_widget(btn_check_addr)

        tab3.content = layout3
        panel.add_widget(tab3)

        # Tab 4: Cài đặt
        tab4 = TabbedPanelItem(text='Cài đặt')
        layout4 = BoxLayout(orientation='vertical', padding=10, spacing=10)

        self.count_input = TextInput(text=str(SCAN_COUNT), multiline=False, size_hint_y=None, height=40)
        self.gap_input = TextInput(text=str(GAP_LIMIT), multiline=False, size_hint_y=None, height=40)

        layout4.add_widget(Label(text='Số lượng quét:', size_hint_y=None, height=40))
        layout4.add_widget(self.count_input)
        layout4.add_widget(Label(text='Gap limit:', size_hint_y=None, height=40))
        layout4.add_widget(self.gap_input)

        btn_save = Button(text='Lưu cài đặt', size_hint_y=None, height=50)
        btn_save.bind(on_press=self.save_settings)

        layout4.add_widget(btn_save)

        tab4.content = layout4
        panel.add_widget(tab4)

        return panel

    def generate_private_key(self, instance):
        pk = generate_new_private_key()
        popup = Popup(title='Private Key mới', content=Label(text=pk), size_hint=(0.8, 0.6))
        popup.open()

    def generate_seed(self, instance):
        if not MNEMONIC_AVAILABLE:
            popup = Popup(title='Lỗi', content=Label(text='Cần cài: pip install mnemonic'), size_hint=(0.8, 0.4))
            popup.open()
            return
        mnemo = Mnemonic("english")
        seed = mnemo.generate(strength=128)
        popup = Popup(title='Seed mới', content=Label(text=seed), size_hint=(0.8, 0.6))
        popup.open()

    def check_private_key_balance(self, pk_hex):
        if len(pk_hex) != 64 or not all(c in '0123456789abcdefABCDEF' for c in pk_hex):
            popup = Popup(title='Lỗi', content=Label(text='Private key không hợp lệ'), size_hint=(0.8, 0.4))
            popup.open()
            return

        num = int(pk_hex, 16)
        if not (0 < num < ecdsa_curve.order):
            popup = Popup(title='Lỗi', content=Label(text='Private key ngoài phạm vi'), size_hint=(0.8, 0.4))
            popup.open()
            return

        privkey_bytes = bytes.fromhex(pk_hex)
        sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        x_bytes = vk.pubkey.point.x().to_bytes(32, 'big')
        prefix = b'\x03' if vk.pubkey.point.y() % 2 else b'\x02'
        pubkey_compressed = prefix + x_bytes
        pubkey_uncompressed = b'\x04' + vk.to_string()

        addresses = [
            ("P2PKH (Không nén)", to_p2pkh_address(pubkey_uncompressed)),
            ("P2PKH (Nén)", to_p2pkh_address(pubkey_compressed)),
            ("P2SH-SegWit", to_p2sh_segwit_address(pubkey_compressed)),
            ("P2WPKH (Native)", to_p2wpkh_address(pubkey_compressed)),
            ("P2TR (Taproot)", to_p2tr_address(pubkey_compressed)),
        ]

        result = "Private Key: " + pk_hex + "\nWIF: " + to_wif(privkey_bytes, compressed=True) + "\n\n"
        for name, addr in addresses:
            balance_btc, error_msg, raw_data = get_balance_multi_api(addr)
            if balance_btc is None:
                balance_btc, error_msg, raw_data = get_balance_via_electrum(addr)
            if error_msg:
                balance_str = "Lỗi"
            elif balance_btc is not None:
                balance_str = f"{balance_btc:.8f} BTC"
            else:
                balance_str = "Lỗi"
            result += f"{name}: {addr} → {balance_str}\n"

        popup = Popup(title='Kết quả kiểm tra', content=ScrollView(size_hint=(1, 1)), size_hint=(0.9, 0.9))
        popup.content.add_widget(Label(text=result, text_size=(popup.width * 0.9, None), halign='left', valign='top'))
        popup.open()

    def scan_seed_phrase(self, seed_phrase):
        if not seed_phrase.strip():
            popup = Popup(title='Lỗi', content=Label(text='Seed không được để trống'), size_hint=(0.8, 0.4))
            popup.open()
            return

        all_privkeys = seed_to_private_keys_multi_path(seed_phrase.strip(), max_addresses=SCAN_COUNT)
        if not all_privkeys:
            popup = Popup(title='Lỗi', content=Label(text='Seed không hợp lệ'), size_hint=(0.8, 0.4))
            popup.open()
            return

        result = "Quét seed phrase:\n\n"
        total_found = 0
        for path_name, privkeys in all_privkeys.items():
            result += f"\n🔄 {path_name}\n"
            consecutive_empty = 0
            for i, privkey_hex in enumerate(privkeys):
                if privkey_hex is None:
                    consecutive_empty += 1
                    if consecutive_empty >= GAP_LIMIT:
                        result += f"  ⏹️ Dừng tại index {i}\n"
                        break
                    continue

                privkey_bytes = bytes.fromhex(privkey_hex)
                sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
                vk = sk.get_verifying_key()
                x_bytes = vk.pubkey.point.x().to_bytes(32, 'big')
