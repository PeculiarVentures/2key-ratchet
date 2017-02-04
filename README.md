# 2key-ratchet
`2key-ratchet` is an implementation of a [Double Ratchet](https://whispersystems.org/docs/specifications/doubleratchet/) protocol and [X3DH](https://whispersystems.org/docs/specifications/x3dh) in TypeScript utilizing WebCrypto. There are a few [differences](https://github.com/PeculiarVentures/2key-ratchet/blob/master/DIFFERENCES.md) between the original specifciations and `2key-ratchet`, the most significant being, as it’s name suggests, it uses two keys, one for authentication and another for key exchange.

See the [ARCHITECTURE](https://github.com/PeculiarVentures/2key-ratchet/blob/master/ARCHITECTURE.md) file to better understand the library structure.

For licensing information, see the [LICENSE](https://github.com/PeculiarVentures/2key-ratchet/blob/master/LICENSE.md) file.

## Build Status

[![CircleCI](https://circleci.com/gh/PeculiarVentures/2key-ratchet.svg?style=svg&circle-token=29f5d4fefececbe5668f0c0858cc583e4e130765)](https://circleci.com/gh/PeculiarVentures/2key-ratchet)

## Instructions

### Installation

```
bash
npm install 2key-ratchet
```

### Usage

First you need to require the library:

```javascript
let DKeyRatchet = require("2key-ratchet");
```

Then generate an Identity Key:

```javascript
let AliceID;
DKeyRatchet.Identity.create(16453);
    .then((id) => {
        AliceID = id;
    });
```

You will also need to create your signed PreKeys:

```javascript
DKeyRatchet.PreKey.create(1)
    .then((preKey) => {
        AliceID.signedPreKeys.save(preKey.id.toString(), preKey);
    });
```

Create your PreKey message bundle:

```javascript
let bundle = new DKeyRatchet.PreKeyBundleProtocol();

bundle.identity.fill(AliceID)
    .then(() => {
        bundle.registrationId = AliceID.id;
        const preKey = AliceID.signedPreKeys.load("1");
        bundle.preKeySigned.id = 1;
        bundle.preKeySigned.key = preKey.key.publicKey;
        return bundle.preKeySigned.sign(AliceID.signingKey.privateKey);
    })
    .then(() => {
        return bundle.exportProtocol();
    })
    .then((ab) => {
        console.log(ab); // ArrayBuffer {byteLength: 348}
    });
``` 

Import the generated PreKey message bundle:

```javascript
DKeyRatchet.PreKeyBundleProtocol.importProtocol(ab)
    .then((bundle) => {
        // check signed prekey
        return bundle.preKeySigned.verify(AliceID.signingKey.public);
    })
    .then((trusted) => {
        if (!trusted)
            throw new Error("PreKey is not trusted");
    })
```

Start a session using the PreKey message bundle:

```javascript
DKeyRatchet.AsymmetricRatchet.create(BobID, bundle)
    .then((cipher) => {
        return cipher.encrypt(DKeyRatchet.Convert.FromUtf8String("Hello world!"));
    })
    .then((preKeyMessage) => {
        return preKeyMessage.exportProtocol();
    })
    .then((ab) => {
        console.log(ab); // ArrayBuffer {byteLength: 408}
    });
```

On the other side you would do the same:

```javascript
DKeyRatchet.AsymmetricRatchet.create(AliceID, preKeyMessage)
    .then((cipher) => {
        return cipher.decrypt(preKeyMessage.signedMessage);
    })
    .then((message) => {
        console.log(DKeyRatchet.Convert.ToUtf8String(message)); // Hello world!
    })
```

We have a [complete example you can look at here](https://github.com/PeculiarVentures/2key-ratchet/tree/master/src/examples).

## Contributing

If you've found an problem with 2key-ratchet, please open a new issue. Feature requests are welcome, too.

Pull requests – patches, improvements, new features – are a fantastic help. Please ask first before embarking on any significant pull request (e.g., implementing new features).

## Note

Bruce Schneier famously said "If you think cryptography can solve your problem, then you don't understand your problem and you don't understand cryptography". The point being, using 2key-ratchet, or any other "security related" library, will not make your product secure. 

In short, there is a lot more to making a secure product than adding cryptography, [this is a great book to get you familiar with thinking defensivly](https://www.amazon.com/Threat-Modeling-Designing-Adam-Shostack/dp/1118809998).

### WARNING
Though this protocol is based on [The Double Ratchet Algorithm](https://whispersystems.org/docs/specifications/doubleratchet/) and [The X3DH Key Agreement Protocol](https://whispersystems.org/docs/specifications/x3dh/) several changes have been made that could change the security properties of the protocol.

## Acknowlegements
The Double Ratchet protocol and X3DH were designed by Trevor Perrin and Moxie Marlinspike, we thank them for their work.

## Related
- [A Formal Security Analysis of the Signal Messaging Protocol](https://eprint.iacr.org/2016/1013.pdf)
- [Web Cryptography API](https://www.w3.org/TR/2016/PR-WebCryptoAPI-20161215/)
- [The X3DH Key Agreement Protocol](https://whispersystems.org/docs/specifications/x3dh/)
- [The Double Ratchet Algorithm](https://whispersystems.org/docs/specifications/doubleratchet/)
