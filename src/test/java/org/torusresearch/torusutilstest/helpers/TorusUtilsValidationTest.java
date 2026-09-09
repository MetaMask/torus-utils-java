package org.torusresearch.torusutilstest.helpers;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.helpers.TorusUtilError;
import org.torusresearch.torusutils.types.ImportPrivateKeyParams;
import org.torusresearch.torusutils.types.RetrieveSharesParams;
import org.torusresearch.torusutils.types.VerifierParams;
import org.torusresearch.torusutils.types.common.TorusOptions;

import java.math.BigInteger;

class TorusUtilsValidationTest {
    private static final String[] ENDPOINTS = {"https://node.example"};
    private static final BigInteger[] INDEXES = {BigInteger.ONE};
    private static final TorusNodePub[] NODE_PUBKEYS = {new TorusNodePub("x", "y")};
    private static final VerifierParams VERIFIER_PARAMS = new VerifierParams("user-id", null, null, null);

    @Test
    void newRetrieveSharesApiRequiresNodeDetails() throws Exception {
        TorusUtils torusUtils = new TorusUtils(new TorusOptions("client-id", Web3AuthNetwork.SAPPHIRE_MAINNET));
        RetrieveSharesParams params = new RetrieveSharesParams(
                ENDPOINTS,
                new BigInteger[0],
                new TorusNodePub[0],
                "google",
                VERIFIER_PARAMS,
                "token"
        );

        assertThatThrownBy(() -> torusUtils.retrieveShares(params))
                .isInstanceOf(TorusUtilError.class)
                .hasMessageContaining("nodePubkeys param is required");
    }

    @Test
    void useDkgFalseIsRejectedForLegacyNetworkBeforeNetworkCall() throws Exception {
        TorusUtils torusUtils = new TorusUtils(new TorusOptions("client-id", Web3AuthNetwork.MAINNET));
        RetrieveSharesParams params = new RetrieveSharesParams(
                ENDPOINTS,
                INDEXES,
                NODE_PUBKEYS,
                "google",
                VERIFIER_PARAMS,
                "token",
                null,
                false,
                true,
                null,
                null
        );

        assertThatThrownBy(() -> torusUtils.retrieveShares(params))
                .isInstanceOf(TorusUtilError.class)
                .hasMessageContaining("useDkg cannot be false for legacy network");
    }

    @Test
    void importPrivateKeyRejectsOversizedSecp256k1Key() throws Exception {
        TorusUtils torusUtils = new TorusUtils(new TorusOptions("client-id", Web3AuthNetwork.SAPPHIRE_MAINNET));
        ImportPrivateKeyParams params = new ImportPrivateKeyParams(
                ENDPOINTS,
                INDEXES,
                NODE_PUBKEYS,
                "google",
                VERIFIER_PARAMS,
                "token",
                new String(new char[65]).replace('\0', '1')
        );

        assertThatThrownBy(() -> torusUtils.importPrivateKey(params))
                .isInstanceOf(TorusUtilError.class)
                .hasMessageContaining("Invalid private key length");
    }
}
