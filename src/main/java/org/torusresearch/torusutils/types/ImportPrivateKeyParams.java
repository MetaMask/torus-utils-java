package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;

import java.math.BigInteger;

public class ImportPrivateKeyParams {
    public final String[] endpoints;
    public final BigInteger[] nodeIndexes;
    public final TorusNodePub[] nodePubkeys;
    public final String verifier;
    public final VerifierParams verifierParams;
    public final String idToken;
    public final String newPrivateKey;
    @Nullable
    public final TorusUtilsExtraParams extraParams;
    @Nullable
    public final Boolean checkCommitment;
    @Nullable
    public final String recordId;

    public ImportPrivateKeyParams(
            @NotNull String[] endpoints,
            @NotNull BigInteger[] nodeIndexes,
            @NotNull TorusNodePub[] nodePubkeys,
            @NotNull String verifier,
            @NotNull VerifierParams verifierParams,
            @NotNull String idToken,
            @NotNull String newPrivateKey
    ) {
        this(endpoints, nodeIndexes, nodePubkeys, verifier, verifierParams, idToken, newPrivateKey, null, null, null);
    }

    public ImportPrivateKeyParams(
            @NotNull String[] endpoints,
            @NotNull BigInteger[] nodeIndexes,
            @NotNull TorusNodePub[] nodePubkeys,
            @NotNull String verifier,
            @NotNull VerifierParams verifierParams,
            @NotNull String idToken,
            @NotNull String newPrivateKey,
            @Nullable TorusUtilsExtraParams extraParams,
            @Nullable Boolean checkCommitment,
            @Nullable String recordId
    ) {
        this.endpoints = endpoints;
        this.nodeIndexes = nodeIndexes;
        this.nodePubkeys = nodePubkeys;
        this.verifier = verifier;
        this.verifierParams = verifierParams;
        this.idToken = idToken;
        this.newPrivateKey = newPrivateKey;
        this.extraParams = extraParams;
        this.checkCommitment = checkCommitment;
        this.recordId = recordId;
    }
}
