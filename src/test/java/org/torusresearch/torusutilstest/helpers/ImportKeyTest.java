package org.torusresearch.torusutilstest.helpers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.TorusUtilError;
import org.torusresearch.torusutils.types.FinalKeyData;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.common.ImportedShare;
import org.torusresearch.torusutils.types.common.TorusKey;
import org.torusresearch.torusutils.types.common.TorusKeyType;
import org.torusresearch.torusutils.types.common.TypeOfUser;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Ports torus.js v19 import-key-check.unit.test.ts and the "generateShares with no nonce" tests.
 */
class ImportKeyTest {
    private static final String IMPORT_KEY = String.format("%064x", 0x1234L);
    private static final List<BigInteger> NODE_INDEXES = Arrays.asList(BigInteger.valueOf(1), BigInteger.valueOf(2), BigInteger.valueOf(3));

    private static List<TorusNodePub> nodePubkeys() {
        try {
            List<TorusNodePub> result = new ArrayList<>();
            for (long key : new long[]{5, 6, 7}) {
                String[] coords = KeyUtils.getPublicKeyCoords(KeyUtils.privateToPublic(BigInteger.valueOf(key)));
                result.add(new TorusNodePub(coords[0], coords[1]));
            }
            return result;
        } catch (TorusUtilError error) {
            throw new IllegalStateException(error);
        }
    }

    private static TorusKey keyWithFinalPrivKey(String finalPrivKey) {
        return new TorusKey(
                new FinalKeyData("0x0", "x", "y", finalPrivKey),
                new OAuthKeyData("0x0", "x", "y", "key"),
                new SessionData(new ArrayList<>(), "auth-key"),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, null, 0),
                new NodesData(new ArrayList<>())
        );
    }

    @Test
    void generateSharesWithNoNonceSplitsTheKeyItselfAndSendsNoNonce() throws Exception {
        List<ImportedShare> shares = KeyUtils.generateShares(TorusKeyType.secp256k1, 0, NODE_INDEXES, nodePubkeys(), IMPORT_KEY, false);

        String[] importPub = KeyUtils.getPublicKeyCoords(KeyUtils.privateToPublic(new BigInteger(IMPORT_KEY, 16)));
        assertThat(shares).hasSize(3);
        for (ImportedShare share : shares) {
            assertThat(share.oauth_pub_key_x).isEqualTo(importPub[0]);
            assertThat(share.oauth_pub_key_y).isEqualTo(importPub[1]);
            assertThat(share.nonce_data).isEmpty();
            assertThat(share.nonce_signature).isEmpty();
        }
    }

    @Test
    void generateSharesWithANonceSplitsTheOAuthKeyAndSendsTheNonce() throws Exception {
        List<ImportedShare> shares = KeyUtils.generateShares(TorusKeyType.secp256k1, 0, NODE_INDEXES, nodePubkeys(), IMPORT_KEY);

        String[] importPub = KeyUtils.getPublicKeyCoords(KeyUtils.privateToPublic(new BigInteger(IMPORT_KEY, 16)));
        for (ImportedShare share : shares) {
            assertThat(share.nonce_data).isNotEmpty();
            assertThat(share.nonce_signature).isNotEmpty();
            // the oauth key is the imported key minus a random nonce
            assertThat(share.oauth_pub_key_x).isNotEqualTo(importPub[0]);
            assertThat(share.final_user_point.getX()).isEqualTo(new BigInteger(importPub[0], 16));
        }
    }

    @Test
    void generateSharesWithNoNonceRejectsEd25519() {
        assertThatThrownBy(() -> KeyUtils.generateShares(TorusKeyType.ed25519, 0, NODE_INDEXES, nodePubkeys(), IMPORT_KEY, false))
                .isInstanceOf(TorusUtilError.class)
                .hasMessageContaining("only secp256k1");
    }

    @Test
    void returnsTheKeyWhenTheNodesStoredTheImportNonce() throws Exception {
        TorusUtils.assertImportedKey(keyWithFinalPrivKey(IMPORT_KEY), IMPORT_KEY);
    }

    @Test
    void ignoresCaseAndLeadingZeroPaddingWhenComparing() throws Exception {
        TorusUtils.assertImportedKey(keyWithFinalPrivKey("ABCD"), "abcd");
    }

    @Test
    void failsWhenTheNodesKeptADifferentNonce() {
        assertThatThrownBy(() -> TorusUtils.assertImportedKey(keyWithFinalPrivKey(String.format("%064x", 0x9999L)), IMPORT_KEY))
                .isInstanceOf(TorusUtilError.class)
                .hasMessageContaining("imported key mismatch: the nodes returned a different final key than expected, this should never occur, please contact web3auth support.");
    }

    @Test
    void failsForAnEmptyFinalKeyFromAnUpgradedAccount() {
        assertThatThrownBy(() -> TorusUtils.assertImportedKey(keyWithFinalPrivKey(""), IMPORT_KEY))
                .isInstanceOf(TorusUtilError.class)
                .hasMessageContaining("imported key mismatch");
    }
}
