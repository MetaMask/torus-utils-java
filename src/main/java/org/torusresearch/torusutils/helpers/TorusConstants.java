package org.torusresearch.torusutils.helpers;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.types.common.BuildEnv;

import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * Temporary compatibility copy of constants pending a released FND v6 artifact.
 */
public final class TorusConstants {
    public static final Map<BuildEnv, String> CITADEL_SERVER_MAP;
    public static final Map<BuildEnv, String> LEGACY_METADATA_MAP;
    private static final Set<Web3AuthNetwork> LEGACY_NETWORKS = Collections.unmodifiableSet(
            EnumSet.of(
                    Web3AuthNetwork.MAINNET,
                    Web3AuthNetwork.TESTNET,
                    Web3AuthNetwork.AQUA,
                    Web3AuthNetwork.CELESTE,
                    Web3AuthNetwork.CYAN
            )
    );

    static {
        EnumMap<BuildEnv, String> citadelServers = new EnumMap<>(BuildEnv.class);
        citadelServers.put(BuildEnv.PRODUCTION, "https://api.web3auth.io/citadel-service");
        citadelServers.put(BuildEnv.STAGING, "https://api.web3auth.io/citadel-service");
        citadelServers.put(BuildEnv.DEVELOPMENT, "https://api-develop.web3auth.io/citadel-service");
        citadelServers.put(BuildEnv.TESTING, "https://api-develop.web3auth.io/citadel-service");
        CITADEL_SERVER_MAP = Collections.unmodifiableMap(citadelServers);

        EnumMap<BuildEnv, String> metadataServers = new EnumMap<>(BuildEnv.class);
        metadataServers.put(BuildEnv.PRODUCTION, "https://api.web3auth.io/metadata-service");
        metadataServers.put(BuildEnv.STAGING, "https://api.web3auth.io/metadata-service");
        metadataServers.put(BuildEnv.DEVELOPMENT, "https://api-develop.web3auth.io/metadata-service");
        metadataServers.put(BuildEnv.TESTING, "https://api-develop.web3auth.io/metadata-service");
        LEGACY_METADATA_MAP = Collections.unmodifiableMap(metadataServers);
    }

    private TorusConstants() {
    }

    public static boolean isLegacyNetwork(@NotNull Web3AuthNetwork network) {
        return LEGACY_NETWORKS.contains(network);
    }
}
