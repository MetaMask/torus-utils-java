package org.torusresearch.torusutilstest.helpers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierKey;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.NodeUtils;
import org.torusresearch.torusutils.helpers.TorusUtilError;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyLookupResult;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyResult;
import org.torusresearch.torusutils.types.common.PubNonce;
import org.torusresearch.torusutils.types.common.TorusPublicKey;
import org.torusresearch.torusutils.types.common.TypeOfUser;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Ports torus.js v19 legacy-nonce.unit.test.ts: every network reads the nonce from the node
 * response only, with no metadata server call.
 */
class LegacyNonceFlowTest {
    private static String hex(long value) {
        return String.format("%064x", BigInteger.valueOf(value));
    }

    private static String[] pub(long privateKey) {
        try {
            return KeyUtils.getPublicKeyCoords(KeyUtils.privateToPublic(BigInteger.valueOf(privateKey)));
        } catch (TorusUtilError error) {
            throw new IllegalStateException(error);
        }
    }

    private static GetOrSetNonceResult v1Nonce(String nonce) {
        return new GetOrSetNonceResult(TypeOfUser.v1, nonce, new PubNonce("", ""), null, false);
    }

    private static GetOrSetNonceResult v2Nonce(long nonce) {
        String[] noncePub = pub(nonce);
        return new GetOrSetNonceResult(TypeOfUser.v2, "", new PubNonce(noncePub[0], noncePub[1]), null, false);
    }

    private static KeyLookupResult lookup(GetOrSetNonceResult nonceResult) {
        String[] oAuthPub = pub(1);
        KeyResult keyResult = new KeyResult(new VerifierKey[]{new VerifierKey(oAuthPub[0], oAuthPub[1], "0x0")}, false);
        return new KeyLookupResult(keyResult, Arrays.asList(1, 2, 3), 0, nonceResult, null);
    }

    private static void assertFinalKey(TorusPublicKey result, long finalPrivateKey) {
        String[] expected = pub(finalPrivateKey);
        assertThat(result.getFinalKeyData().getX()).isEqualTo(expected[0]);
        assertThat(result.getFinalKeyData().getY()).isEqualTo(expected[1]);
    }

    @Test
    void addsAV1NonceFromTheNodesToTheOAuthKeyWhetherOrNotOneKeyIsEnabled() throws Exception {
        for (boolean enableOneKey : new boolean[]{true, false}) {
            TorusPublicKey result = TorusUtils.formatPublicKeyData(lookup(v1Nonce(hex(2))), null, Web3AuthNetwork.MAINNET, enableOneKey, 0);

            assertFinalKey(result, 3);
            assertThat(result.getMetadata().getTypeOfUser()).isEqualTo(TypeOfUser.v1);
            assertThat(result.getMetadata().getNonce()).isEqualTo(BigInteger.valueOf(2));
            assertThat(result.getMetadata().getPubNonce()).isNull();
        }
    }

    @Test
    void usesTheOAuthKeyForAnExistingKeyWithNoNonce() throws Exception {
        TorusPublicKey result = TorusUtils.formatPublicKeyData(lookup(v1Nonce("")), null, Web3AuthNetwork.MAINNET, true, 0);

        assertFinalKey(result, 1);
        assertThat(result.getMetadata().getTypeOfUser()).isEqualTo(TypeOfUser.v1);
        assertThat(result.getMetadata().getNonce()).isEqualTo(BigInteger.ZERO);
    }

    @Test
    void addsAV2PubNonceWhenOneKeyIsEnabledOnALegacyNetwork() throws Exception {
        TorusPublicKey result = TorusUtils.formatPublicKeyData(lookup(v2Nonce(2)), null, Web3AuthNetwork.MAINNET, true, 0);

        assertFinalKey(result, 3);
        assertThat(result.getMetadata().getTypeOfUser()).isEqualTo(TypeOfUser.v2);
        assertThat(result.getMetadata().getPubNonce()).isNotNull();
    }

    @Test
    void ignoresAV2NonceWhenOneKeyIsDisabledOnALegacyNetwork() throws Exception {
        TorusPublicKey result = TorusUtils.formatPublicKeyData(lookup(v2Nonce(2)), null, Web3AuthNetwork.MAINNET, false, 0);

        assertFinalKey(result, 1);
        assertThat(result.getMetadata().getTypeOfUser()).isEqualTo(TypeOfUser.v1);
        assertThat(result.getMetadata().getNonce()).isEqualTo(BigInteger.ZERO);
        assertThat(result.getMetadata().getPubNonce()).isNull();
        assertThat(result.getMetadata().isUpgraded()).isFalse();
    }

    @Test
    void sapphireAddsAV2PubNonceAndRejectsAnEmptyOne() throws Exception {
        TorusPublicKey result = TorusUtils.formatPublicKeyData(lookup(v2Nonce(2)), null, Web3AuthNetwork.SAPPHIRE_MAINNET, true, 0);
        assertFinalKey(result, 3);

        assertThatThrownBy(() -> TorusUtils.formatPublicKeyData(
                lookup(new GetOrSetNonceResult(TypeOfUser.v2, "", new PubNonce("", ""), null, false)),
                null, Web3AuthNetwork.SAPPHIRE_MAINNET, true, 0))
                .isInstanceOf(TorusUtilError.class)
                .hasMessageContaining("Unable to fetch metadata nonce");
    }

    @Test
    void failsWhenNoNodeSendsANonce() {
        assertThatThrownBy(() -> TorusUtils.formatPublicKeyData(lookup(null), null, Web3AuthNetwork.MAINNET, true, 0))
                .isInstanceOf(TorusUtilError.class)
                .hasMessageContaining("metadata nonce is missing in share response");
    }

    @Test
    void needsNoNonceForAnExtendedVerifierId() throws Exception {
        TorusPublicKey result = TorusUtils.formatPublicKeyData(lookup(null), "tss-id", Web3AuthNetwork.SAPPHIRE_MAINNET, true, 0);

        assertFinalKey(result, 1);
    }

    @Test
    void skipsAV1AnswerWithNoNonceForANewKeyAndUsesTheNextNodeNonce() {
        List<GetOrSetNonceResult> answers = Arrays.asList(v1Nonce(""), v2Nonce(2), v2Nonce(2));

        GetOrSetNonceResult picked = NodeUtils.firstNodeNonce(answers, true);

        assertThat(picked).isSameAs(answers.get(1));
    }

    @Test
    void failsForANewKeyWhenNoNodeSendsANonce() {
        List<GetOrSetNonceResult> answers = Arrays.asList(v1Nonce(""), v1Nonce(""), v1Nonce(""));

        assertThat(NodeUtils.firstNodeNonce(answers, true)).isNull();
    }

    @Test
    void acceptsAnEmptyV1AnswerForAnExistingKey() {
        List<GetOrSetNonceResult> answers = Arrays.asList(v1Nonce(""), v1Nonce(""), v1Nonce(""));

        assertThat(NodeUtils.firstNodeNonce(answers, false)).isSameAs(answers.get(0));
    }

    @Test
    void acceptsAV1AnswerWithANonceForANewKey() {
        List<GetOrSetNonceResult> answers = Arrays.asList(v1Nonce(""), v1Nonce(hex(2)));

        assertThat(NodeUtils.firstNodeNonce(answers, true)).isSameAs(answers.get(1));
    }

    @Test
    void skipsNodesThatDoNotAgreeOnTheKey() {
        List<GetOrSetNonceResult> answers = new ArrayList<>(Arrays.asList(null, v2Nonce(2)));

        assertThat(NodeUtils.firstNodeNonce(answers, false)).isSameAs(answers.get(1));
        assertThat(NodeUtils.firstNodeNonce(Collections.singletonList(null), false)).isNull();
    }
}
