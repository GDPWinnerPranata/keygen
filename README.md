# Keygen

- Generates 2 keypairs: Signing Keypair & Encryption Keypair
- Each keypair's private key is **encrypted using KMS SYMMETRIC_DEFAULT algorithm**
- Each keypair is **signed using KMS Asymmetric P256 key**

## Format

```bash
keys.json
├──── signerKey  : <JWT>
│                  ├ ─ ─ <header>
│                  │     └ ─ ─ alg: "ES256"
│                  ├ ─ ─ <payload>
│                  │     ├ ─ ─ privateKey: <SYMMETRIC_DEFAULT KMS-Encrypted PEM>
│                  │     └ ─ ─ publicKey
│                  │           ├ ─ ─ x: <x-coordinate>
│                  │           └ ─ ─ y: <y-coordinate>
│                  └ ─ ─ <signature>: <JWS signed by KMS signer>
│
└──── encryptKey : <JWT>
                   ├ ─ ─ <header>
                   │     └ ─ ─ alg: "ES256"
                   ├ ─ ─ <payload>
                   │     ├ ─ ─ privateKey: <SYMMETRIC_DEFAULT KMS-Encrypted PEM>
                   │     └ ─ ─ publicKey
                   │           ├ ─ ─ x: <x-coordinate>
                   │           └ ─ ─ y: <y-coordinate>
                   └ ─ ─ <signature>: <JWS signed by KMS signer>
```

## How to Run

1. Clone repository

```bash
git clone git@github.com:GDPWinnerPranata/keygen.git
cd keygen
```

2. Install Dependencies

```bash
npm install
```

3. Copy & setup `.env`

```bash
cp .env.example .env
```

4. Run script

```bash
npm start
```

## How to Test

```bash
npm test
```
