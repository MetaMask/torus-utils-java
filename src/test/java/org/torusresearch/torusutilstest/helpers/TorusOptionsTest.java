package org.torusresearch.torusutilstest.helpers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.types.common.BuildEnv;
import org.torusresearch.torusutils.types.common.TorusKeyType;
import org.torusresearch.torusutils.types.common.TorusOptions;

class TorusOptionsTest {
    @Test
    void defaultsMatchTorusJs() {
        TorusOptions options = new TorusOptions(
                "client-id",
                Web3AuthNetwork.SAPPHIRE_MAINNET,
                null,
                null,
                null,
                null,
                null,
                null
        );

        assertThat(options.buildEnv).isEqualTo(BuildEnv.PRODUCTION);
        assertThat(options.keyType).isEqualTo(TorusKeyType.secp256k1);
        assertThat(options.enableOneKey).isFalse();
        assertThat(options.serverTimeOffset).isZero();
        assertThat(options.legacyMetadataHost).isNull();
        assertThat(options.source).isNull();
    }

    @Test
    void resolvesLegacyMetadataByBuildEnvironment() {
        TorusOptions options = new TorusOptions(
                "client-id",
                Web3AuthNetwork.TESTNET,
                BuildEnv.DEVELOPMENT,
                null,
                0,
                false,
                TorusKeyType.secp256k1,
                "android"
        );

        assertThat(options.legacyMetadataHost).isEqualTo("https://api-develop.web3auth.io/metadata-service");
        assertThat(options.source).isEqualTo("android");
    }

    @Test
    void rejectsEd25519OnLegacyNetwork() {
        assertThatThrownBy(() -> new TorusOptions(
                "client-id",
                Web3AuthNetwork.MAINNET,
                BuildEnv.PRODUCTION,
                null,
                0,
                false,
                TorusKeyType.ed25519,
                null
        )).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ed25519");
    }
}
