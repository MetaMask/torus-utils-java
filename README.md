# Torus-Utils-Java

[![](https://jitpack.io/v/org.torusresearch/torus-utils-java.svg)](https://jitpack.io/#org.torusresearch/torus-utils-java)

## Introduction

Use this package to do threshold resolution of API calls to Torus nodes. 
Since Torus nodes operate on a threshold assumption, we need to ensure that API calls also follow such an assumption.
This is to prevent malicious nodes from withholding shares, or deliberately slowing down the entire process.

This utility library allows for early exits in optimistic scenarios, while handling rejection of invalid inputs from nodes in malicious/offline scenarios.
The general approach is to evaluate a threshold number of results instead of a list of (potentially incomplete) results, and then exit once a threshold number of valid results have been evaluated.

README.md
## Features
- Handles up to threshold number of failures.
- Optimistic early exit (eg. threshold number of nodes return valid shares = complete)

## Getting Started

Typically your application should depend on release versions of torus-utils-java, but you may also use snapshot dependencies for early access to features and fixes, refer to the Snapshot Dependencies section.
This project uses [jitpack](https://jitpack.io/docs/) for release management

Add the relevant dependency to your project:

```groovy
repositories {
        maven { url "https://jitpack.io" }
   }
   dependencies {
         implementation 'org.torusresearch:torus-utils-java:5.0.0'
   }
```

## Requirements

- Android - API level 26+
- Java 8 / 1.8+

## v5 migration

The v5 API replaces the positional share-retrieval arguments with
`RetrieveSharesParams`. The positional overload remains available but is
deprecated.

```java
import org.torusresearch.fetchnodedetails.types.BuildEnv;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;

TorusOptions options = new TorusOptions(
        clientId,
        Web3AuthNetwork.SAPPHIRE_MAINNET,
        BuildEnv.PRODUCTION,
        null,
        0,
        false,
        TorusKeyType.secp256k1,
        "android"
);

RetrieveSharesParams params = new RetrieveSharesParams(
        endpoints,
        nodeIndexes,
        nodePubkeys,
        verifier,
        verifierParams,
        idToken,
        extraParams,
        null, // useDkg: defaults to true for secp256k1
        null, // checkCommitment: defaults to true
        recordId,
        authConnection
);

TorusKey key = new TorusUtils(options).retrieveShares(params);
```

Signer allow requests now use Citadel query parameters and do not send the
legacy `x-api-key`, `Origin`, or gating headers. A caller-provided `recordId`
routes auth-flow analytics through the Citadel audit endpoint; otherwise the
SDK generates a UUID and reports through the signer allow endpoint. Analytics
reported after retrieval are non-blocking.

Legacy metadata hosts are selected by `BuildEnv` from
`fetch-node-details-java` (`LEGACY_METADATA_MAP`), and `TorusOptions` now also
accepts `source` and `keyType`. Ed25519 remains unsupported on legacy
networks; full Ed25519 encoding support is not part of this compatibility
change. `useDkg=false` is likewise rejected for legacy networks.