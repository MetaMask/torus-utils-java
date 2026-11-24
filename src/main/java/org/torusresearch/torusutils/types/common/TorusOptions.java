package org.torusresearch.torusutils.types.common;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.fetchnodedetails.types.BuildEnv;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;

public class TorusOptions {
    // in seconds
    public final Integer serverTimeOffset;
    public final Web3AuthNetwork network;
    public final String clientId;
    public final BuildEnv buildEnv;
    @Nullable
    public final String source;
    public boolean enableOneKey;
    public final TorusKeyType keyType;

    public TorusOptions(@NotNull String clientId, @NotNull Web3AuthNetwork network) {
        this(clientId, network, BuildEnv.PRODUCTION, 0, false, TorusKeyType.secp256k1, null);
    }

    public TorusOptions(@NotNull String clientId, @NotNull Web3AuthNetwork network, @Nullable Integer serverTimeOffset, @NotNull Boolean enableOneKey) {
        this(clientId, network, BuildEnv.PRODUCTION, serverTimeOffset, enableOneKey, TorusKeyType.secp256k1, null);
    }

    public TorusOptions(
            @NotNull String clientId,
            @NotNull Web3AuthNetwork network,
            @Nullable BuildEnv buildEnv,
            @Nullable Integer serverTimeOffset,
            @Nullable Boolean enableOneKey,
            @Nullable TorusKeyType keyType,
            @Nullable String source
    ) {
        if (clientId.isEmpty()) {
            throw new IllegalArgumentException("Please provide a valid clientId in constructor");
        }
        this.clientId = clientId;
        this.network = network;
        this.buildEnv = buildEnv == null ? BuildEnv.PRODUCTION : buildEnv;
        this.keyType = keyType == null ? TorusKeyType.secp256k1 : keyType;
        if (this.keyType == TorusKeyType.ed25519 && network.isLegacyNetwork()) {
            throw new IllegalArgumentException("keyType: " + this.keyType + " is not supported by " + network + " network");
        }
        this.serverTimeOffset = serverTimeOffset == null ? 0 : serverTimeOffset;
        this.enableOneKey = enableOneKey != null && enableOneKey;
        this.source = source;
    }

    /**
     * @deprecated {@code legacyMetadataHost} was removed in v6: the metadata nonce now comes only
     * from the node responses, so the host is ignored. Use the constructor without it.
     */
    @Deprecated
    public TorusOptions(@NotNull String clientId, @NotNull Web3AuthNetwork network, @Nullable String legacyMetadataHost, @Nullable Integer serverTimeOffset, @NotNull Boolean enableOneKey) {
        this(clientId, network, BuildEnv.PRODUCTION, serverTimeOffset, enableOneKey, TorusKeyType.secp256k1, null);
    }

    /**
     * @deprecated {@code legacyMetadataHost} was removed in v6 and is ignored. Use the constructor without it.
     */
    @Deprecated
    public TorusOptions(
            @NotNull String clientId,
            @NotNull Web3AuthNetwork network,
            @Nullable BuildEnv buildEnv,
            @Nullable String legacyMetadataHost,
            @Nullable Integer serverTimeOffset,
            @Nullable Boolean enableOneKey,
            @Nullable TorusKeyType keyType,
            @Nullable String source
    ) {
        this(clientId, network, buildEnv, serverTimeOffset, enableOneKey, keyType, source);
    }
}
