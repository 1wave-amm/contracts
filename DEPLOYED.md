# WavePointToken - Contract Verification

## Deployed Contract

- **Address**: `0xC9c9C776C45768Ce84ECb3526AE05d02AEFf290F`
- **Network**: Base (Chain ID: 8453)
- **Compiler**: Solidity 0.8.30
- **Optimization**: 200 runs
- **Verified on**: Sourcify ✅

## Verification on Basescan

The contract is already verified on Sourcify, but for verification on Basescan:

### Quick Start

```bash
# 1. Get API key from https://basescan.org/apis
# 2. Add to .env:
nano .env  # or vim .env
# Add: BASESCAN_API_KEY=YOUR_KEY_HERE

# 3. Run verification
./verify-basescan.sh
```

### Useful Links

- **Contract on Basescan**: https://basescan.org/address/0xC9c9C776C45768Ce84ECb3526AE05d02AEFf290F
- **Get API Key**: https://basescan.org/apis (free, 2-minute registration)
- **Sourcify (already verified)**: https://repo.sourcify.dev/contracts/full_match/8453/0xC9c9C776C45768Ce84ECb3526AE05d02AEFf290F/

### Constructor Arguments (already encoded)
```
0x000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000049c562a15b05ffd5fdff57bd3c7a9e346e4a2b3900000000000000000000000049c562a15b05ffd5fdff57bd3c7a9e346e4a2b39000000000000000000000000000000000000000000000000000000000000000c315761766520506f696e7473000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045741564500000000000000000000000000000000000000000000000000000000
```

## Next Steps

1. ✅ Contract deployed and verified on Sourcify
2. ⏳ Verify on Basescan (optional, for visibility only)
3. ⏳ Configure Merkl with this address
4. ⏳ Update points-service with the token address
