# Keygen

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
│                  └ ─ ─ <signature>: <JWS signed by signer private key>
│
└──── encryptKey : <JWT>
                   ├ ─ ─ <header>
                   │     └ ─ ─ alg: "ES256"
                   ├ ─ ─ <payload>
                   │     ├ ─ ─ privateKey: <SYMMETRIC_DEFAULT KMS-Encrypted PEM>
                   │     └ ─ ─ publicKey
                   │           ├ ─ ─ x: <x-coordinate>
                   │           └ ─ ─ y: <y-coordinate>
                   └ ─ ─ <signature>: <JWS signed by signer private key>
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
