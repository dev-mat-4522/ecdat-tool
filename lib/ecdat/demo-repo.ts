/**
 * Bundled demo repository — "vulnbank", a deliberately quantum-vulnerable
 * multi-language codebase.
 *
 * This exists so the tool is demonstrable with zero network access and so every
 * detector path (Python AST, Java/JS/Go regex, config, manifest, PEM
 * certificate, key material, HSM/KMS references, JAR metadata) has a guaranteed
 * hit. Paths are chosen to exercise the classification heuristics too:
 * `payments/`, `auth/`, `tests/`.
 *
 * Nothing here is real key material. The `.key` fixture is a placeholder block
 * and the `.jar` fixture is generated below as an empty ZIP directory.
 */

export interface DemoFile {
  path: string
  content: string
}

export const DEMO_REPO_LABEL = "vulnbank (bundled demo repository)"

/**
 * Builds a minimal "stored" ZIP: one 30-byte local file header per zero-length
 * entry. This is a real ZIP entry table — which is exactly what the F9 JAR
 * detector reads — with no class bytes behind it, so the fixture stays text-safe.
 */
function storedZip(names: string[]): string {
  return names
    .map((name) => {
      const n = name.length
      const header = [
        0x50, 0x4b, 0x03, 0x04, // local file header signature
        20, 0, // version needed
        0, 0, // flags
        0, 0, // method: stored
        0, 0, 0, 0, // mod time + date
        0, 0, 0, 0, // crc32
        0, 0, 0, 0, // compressed size
        0, 0, 0, 0, // uncompressed size
        n & 0xff, (n >> 8) & 0xff, // file name length
        0, 0, // extra field length
      ]
      return String.fromCharCode(...header) + name
    })
    .join("")
}

export const DEMO_FILES: DemoFile[] = [
  {
    path: "payments/settlement.py",
    content: `"""Card settlement pipeline. Long-lived financial records."""
import hashlib
import hmac
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def settlement_reference(batch_id: str) -> str:
    # Legacy reference format kept for downstream reconciliation.
    return hashlib.md5(batch_id.encode()).hexdigest()


def sign_batch(private_key, payload: bytes) -> bytes:
    return private_key.sign(
        payload,
        padding.PKCS1v15(),
        hashes.SHA1(),
    )


def issue_settlement_key():
    # 2048-bit RSA for the acquirer channel.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def legacy_acquirer_key():
    return RSA.generate(1024)


def wrap_pan(key: bytes, pan: bytes) -> bytes:
    cipher = DES3.new(key, DES3.MODE_CBC)
    return cipher.encrypt(pan)


def batch_mac(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha1).hexdigest()
`,
  },
  {
    path: "auth/session.py",
    content: `"""Session and token handling."""
import random
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def new_session_id() -> str:
    # Statistical PRNG used for a security-relevant identifier.
    return "%032x" % random.getrandbits(128)


def issue_token(claims: dict, secret: str) -> str:
    return jwt.encode(claims, secret, algorithm="RS256")


def device_keypair():
    return ec.generate_private_key(ec.SECP256R1())


def seal(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
`,
  },
  {
    path: "auth/password.py",
    content: `import hashlib
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def hash_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return kdf.derive(password.encode())


def legacy_hash(password: str) -> str:
    # Pre-2015 accounts still carry this.
    return hashlib.sha1(password.encode()).hexdigest()


def reset_nonce() -> bytes:
    return os.urandom(32)
`,
  },
  {
    path: "kms/envelope.py",
    content: `"""Envelope encryption for archival records (25 year retention)."""
from cryptography.hazmat.primitives.asymmetric import dh, x25519
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def negotiate_archive_key(peer_public):
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private = parameters.generate_private_key()
    return private.exchange(peer_public)


def modern_exchange(peer_public):
    private = x25519.X25519PrivateKey.generate()
    return private.exchange(peer_public)


def wrap_dek(public_key, dek: bytes) -> bytes:
    return public_key.encrypt(
        dek,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
`,
  },
  {
    path: "identity/mldsa_pilot.py",
    content: `"""Pilot integration of the FIPS 204 signature scheme."""
import oqs


def pilot_sign(message: bytes) -> bytes:
    with oqs.Signature("ML-DSA-65") as signer:
        signer.generate_keypair()
        return signer.sign(message)


def pilot_kem():
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        public_key = kem.generate_keypair()
        return public_key
`,
  },
  {
    path: "gateway/TokenService.java",
    content: `package com.vulnbank.gateway;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class TokenService {

    public byte[] fingerprint(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(input);
    }

    public Signature signer() throws Exception {
        return Signature.getInstance("SHA1withRSA");
    }

    public KeyPairGenerator issuerKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator;
    }

    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }

    public Cipher modernCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public SecretKeySpec aesKey(byte[] raw) {
        return new SecretKeySpec(raw, "AES");
    }
}
`,
  },
  {
    path: "web/src/checkout.js",
    content: `import crypto from "node:crypto"
import jwt from "jsonwebtoken"

export function idempotencyKey(orderId) {
  return crypto.createHash("md5").update(orderId).digest("hex")
}

export function signReceipt(payload, privateKey) {
  return jwt.sign(payload, privateKey, { algorithm: "RS256" })
}

export function ephemeralKeys() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
}

export function agree() {
  const ecdh = crypto.createECDH("prime256v1")
  ecdh.generateKeys()
  return ecdh
}

export function encryptCard(key, iv, pan) {
  const cipher = crypto.createCipheriv("aes-128-cbc", key, iv)
  return Buffer.concat([cipher.update(pan), cipher.final()])
}
`,
  },
  {
    path: "edge/proxy.go",
    content: `package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
)

func LegacyDigest(data []byte) [16]byte {
	return md5.Sum(data)
}

func IssuerKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func EdgeKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS10}
}
`,
  },
  {
    path: "infra/nginx.conf",
    content: `server {
    listen 443 ssl;
    server_name api.vulnbank.example;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES128-SHA:DES-CBC3-SHA:RC4-MD5;
    ssl_prefer_server_ciphers on;
    ssl_certificate /etc/ssl/certs/api.pem;
    ssl_certificate_key /etc/ssl/private/api.key;
}
`,
  },
  {
    path: "infra/sshd_config",
    content: `Protocol 2
KexAlgorithms diffie-hellman-group14-sha1,ecdh-sha2-nistp256
HostKeyAlgorithms ssh-rsa,ecdsa-sha2-nistp256
Ciphers aes128-ctr,3des-cbc
MACs hmac-sha1
`,
  },
  {
    path: "infra/app.properties",
    content: `# Service crypto configuration
signing.algorithm=SHA1withRSA
jwt.algorithm=RS256
tls.minVersion=TLSv1.1
cipher.transformation=AES/CBC/PKCS5Padding
kdf.algorithm=PBKDF2WithHmacSHA1
`,
  },
  {
    path: "requirements.txt",
    content: `cryptography==41.0.7
pycryptodome==3.19.0
pyjwt==2.8.0
paramiko==3.4.0
liboqs-python==0.10.0
requests==2.31.0
`,
  },
  {
    path: "package.json",
    content: `{
  "name": "vulnbank-web",
  "version": "2.4.1",
  "dependencies": {
    "jsonwebtoken": "^9.0.2",
    "node-forge": "^1.3.1",
    "bcryptjs": "^2.4.3",
    "elliptic": "^6.5.4"
  }
}
`,
  },
  {
    path: "pki/acquirer.pem",
    content: `-----BEGIN CERTIFICATE-----
MIIC0jCCAbqgAwIBAgIUSMOKPQ4jL1nEXAMPLEONLYnotarealcertMA0GCSqGSIb3
DQEBBQUAMBUxEzARBgNVBAMMCmFjcXVpcmVyQ0EwHhcNMjMwMzE1MTAwMDAwWhcN
MjgwMzE0MTAwMDAwWjAdMRswGQYDVQQDDBJhcGkudnVsbmJhbmsudGVzdDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMEXAMPLEPUBLICKEYDATAdG9ub3Rf
dXNlX3RoaXNfY2VydGlmaWNhdGVfYW55d2hlcmVfaXRfaXNfYV9wbGFjZWhvbGRl
cl9mb3JfZGVtb19wdXJwb3Nlc19vbmx5X2FuZF9jb250YWluc19ub19rZXlfbWF0
ZXJpYWxfd2hhdHNvZXZlcl9zb19pdF9jYW5ub3RfYmVfbWlzdXNlZF9ieV9hbnlv
bmVfYXRfYWxsX2V2ZXJfdGhhbmtzX2Zvcl9yZWFkaW5nX3RoaXNfbG9uZ19zdHJp
bmdfb2ZfYmFzZTY0X3BhZGRpbmdfdGV4dF9oZXJlX29rYXlfZG9uZQIDAQABMA0G
CSqGSIb3DQEBBQUAA4IBAQBEXAMPLESIGNATUREdGhpc19pc19ub3RfYV9yZWFs
X3NpZ25hdHVyZV9hdF9hbGxfaXRfaXNfanVzdF9wYWRkaW5nX2Zvcl90aGVfZGVt
b19maXh0dXJlX3NvX3RoZV9wYXJzZXJfaGFzX3NvbWV0aGluZ190b19yZWFkX2hl
cmVfYW5kX25vdGhpbmdfc2Vuc2l0aXZlX2lzX2V4cG9zZWQ=
-----END CERTIFICATE-----
`,
  },
  {
    path: "tests/test_crypto.py",
    content: `import hashlib
from Crypto.Cipher import ARC4


def test_legacy_digest_matches_fixture():
    assert hashlib.md5(b"fixture").hexdigest() == "8d5e957f297893487bd98fa830fa6413"


def test_rc4_roundtrip():
    cipher = ARC4.new(b"testkeytestkey")
    assert cipher.encrypt(b"hello") != b"hello"
`,
  },
  {
    path: "scripts/rotate_keys.py",
    content: `import subprocess


def rotate():
    # Historic key rotation helper.
    subprocess.run(["openssl", "genrsa", "-out", "new.key", "2048"], check=True)
    subprocess.run(["openssl", "dgst", "-sha1", "-sign", "new.key", "manifest"], check=True)
`,
  },
  {
    // F1 — a loose private key committed into the tree is an artefact in its own
    // right, independent of any algorithm call site.
    path: "pki/service.key",
    content: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEXAMPLEPLACEHOLDERnotarealkeydonotusethisanywhereatalloAoGCCqG
SM49AwEHoUQDQgAEEXAMPLEPUBLICPOINTdG9ub3RfdXNlX3RoaXNfcGxhY2Vob2xkZXJf
a2V5X21hdGVyaWFsX2Zvcl9kZW1vX3B1cnBvc2VzX29ubHk9PQ==
-----END EC PRIVATE KEY-----
`,
  },
  {
    // F1 — a keystore container. ECDAT catalogues the container; it never opens
    // it to enumerate the contained keys.
    path: "pki/acquirer-truststore.jks",
    content: `# Placeholder Java KeyStore fixture for the demo scan.
# A real .jks is a binary container; ECDAT records its presence and flags it
# for manual inventory rather than parsing the keys inside.
`,
  },
  {
    // F3 — PKCS#11 HSM integration. Reference detection only: ECDAT never opens
    // a PKCS#11 session or queries the module.
    path: "hsm/pkcs11_signer.py",
    content: `"""Card-signing key lives in the payment HSM, accessed over PKCS#11."""
import pkcs11
from pkcs11 import Mechanism


def hsm_session(pin: str):
    lib = pkcs11.lib("/usr/lib/softhsm/libsofthsm2.so")
    token = lib.get_token(token_label="acquirer")
    return token.open(user_pin=pin)


def sign_settlement(session, data: bytes) -> bytes:
    key = session.get_key(label="settlement-signing")
    return key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
`,
  },
  {
    // F3 — HSM configuration surface (provider/slot/pin references).
    path: "infra/hsm.properties",
    content: `# Hardware security module wiring for the signing service.
hsm.provider=SunPKCS11
pkcs11.library=/opt/nfast/toolkits/pkcs11/libcknfast.so
hsm.slot=0
hsm.partition=acquirer-prod
`,
  },
  {
    // F4 — Cloud KMS integration (AWS SDK). Reference detection only: ECDAT makes
    // no API call and does not enumerate the keys held in the account.
    path: "kms/aws_kms.py",
    content: `"""Envelope keys are wrapped by AWS KMS."""
import boto3

kms = boto3.client("kms")


def generate_data_key(key_id: str):
    return kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")


def wrap(key_id: str, plaintext: bytes) -> bytes:
    return kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
`,
  },
  {
    // F4 — Cloud KMS declared as infrastructure. The Terraform resource is a
    // reference in code, not a live inventory of the key.
    path: "infra/kms.tf",
    content: `resource "aws_kms_key" "settlement_envelope" {
  description             = "Envelope key for settlement archives"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "settlement_envelope" {
  name          = "alias/settlement-envelope"
  target_key_id = aws_kms_key.settlement_envelope.key_id
}
`,
  },
  {
    // F10 — a Dockerfile is scanned as configuration text (never built or pulled).
    // The hardcoded secret below is also an F1 key-literal finding.
    path: "Dockerfile",
    content: `FROM python:3.11-slim

RUN pip install pycryptodome cryptography

ENV JWT_SIGNING_SECRET="s3cr3t_Hardcoded_Signing_Key_do_not_ship_9f3a"

COPY . /app
WORKDIR /app
CMD ["python", "-m", "payments.settlement"]
`,
  },
  {
    // F9 — binary scanning MVP. A synthetic but structurally valid stored-ZIP JAR:
    // real local file headers with crypto package/class entry names behind them,
    // and no class bytes, so the fixture stays text-safe. ECDAT reads the ZIP
    // directory only — it never decompiles bytecode.
    path: "libs/crypto-provider.jar",
    content: storedZip([
      "META-INF/MANIFEST.MF",
      "org/bouncycastle/crypto/engines/AESEngine.class",
      "org/bouncycastle/crypto/digests/SHA1Digest.class",
      "org/bouncycastle/pqc/crypto/mlkem/MLKEMEngine.class",
      "javax/crypto/Cipher.class",
      "javax/crypto/spec/GCMParameterSpec.class",
      "com/vulnbank/crypto/AESGCMEncryption.class",
      "com/vulnbank/crypto/TripleDESCipher.class",
    ]),
  },
]

export const DEMO_FILE_COUNT = DEMO_FILES.length
