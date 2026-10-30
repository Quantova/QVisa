# QVisa

QVisa is a live production post quantum visa record tool for consular authorities and border control on the Quantova network. It proves the grant, extension, entry, exit and revocation of a visa, and it lets any third party confirm that history without trusting the party that created it.

QVisa proves records without disclosing them. Names, visa numbers and travel history stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no personal detail is ever published. A holder is named only by a chain address.

## What it records

Each record is a signed envelope of one of five types.

1. grant, an authority states the visa type, number, holder, number of entries and expiry of a visa.
2. extend, the authority extends the expiry of the visa.
3. enter, a border officer records an entry at a named post.
4. exit, a border officer records an exit at a named post.
5. revoke, the authority revokes the visa and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole life of a visa forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qvisa
```

## Use

```js
const qvisa = require('@quantovainc/qvisa');

const authority = qvisa.generateKey();
const holder = qvisa.generateKey();
const visa = qvisa.grant({
  key: authority,
  visaType: 'tourist',
  visaNo: 'V 1234567',
  subject: qvisa.keyId(holder),
  entries: 'multiple',
  validUntil: '2027-01-01T00:00:00.000Z',
  authorityLabel: 'Consulate General',
});

const anchored = await qvisa.anchor(visa, { seed, index: 0, network: 'testnet' });
const result = await qvisa.verify(anchored[0], { type: 'grant', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural person. The holder and the authority are chain addresses, and linking an address to a person is a separate attestation held off the chain.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
