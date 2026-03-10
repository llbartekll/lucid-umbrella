# Wallet Demo

WalletConnect v2 wallet demo that uses the ERC-7730 clear signing library to display human-readable transaction details.

## Setup

1. Copy the WalletConnect config template:

```sh
cp Config.xcconfig.template Config.xcconfig
```

2. Edit `Config.xcconfig` and replace `YOUR_PROJECT_ID_HERE` with your WalletConnect project ID (get one at [cloud.reown.com](https://cloud.reown.com)).

3. Build the XCFramework (if not already built):

```sh
./scripts/generate_uniffi_bindings.sh
./scripts/build-xcframework.sh
```

4. Open `Wallet.xcodeproj` and run on a simulator or device.

> The app works without a project ID — WalletConnect features are disabled and a message is shown instead. Key import and clear signing remain functional.
