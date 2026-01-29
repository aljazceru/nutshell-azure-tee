# Cashu mint running in confidential containers 

### Mint
Mint is running on a custom fork of nutshell with [spark backend](https://sdk-doc-spark.breez.technology/) - [nutshell-tee](https://github.com/nostr-net/nutshell-tee)

```
git clone https://github.com/aljazceru/nutshell-azure-tee.git
python verify_attestation.py https://nuttee.freedom.cash --policy-file azure/cce-policy.base64
```
