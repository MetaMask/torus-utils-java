package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;

import java.math.BigInteger;

public class RetrieveSharesParams {
    public final String[] endpoints;
    public final BigInteger[] indexes;
    public final TorusNodePub[] nodePubkeys;
    public final String verifier;
    public final VerifierParams verifierParams;
    public final String idToken;
    @Nullable
    public final TorusUtilsExtraParams extraParams;
    @Nullable
    public final Boolean useDkg;
    @Nullable
    public final Boolean checkCommitment;
    @Nullable
    public final String recordId;
    @Nullable
    public final String authConnection;

    public RetrieveSharesParams(
            @NotNull String[] endpoints,
            @NotNull BigInteger[] indexes,
            @NotNull TorusNodePub[] nodePubkeys,
            @NotNull String verifier,
            @NotNull VerifierParams verifierParams,
            @NotNull String idToken
    ) {
        this(endpoints, indexes, nodePubkeys, verifier, verifierParams, idToken, null, null, null, null, null);
    }

    public RetrieveSharesParams(
            @NotNull String[] endpoints,
            @NotNull BigInteger[] indexes,
            @NotNull TorusNodePub[] nodePubkeys,
            @NotNull String verifier,
            @NotNull VerifierParams verifierParams,
            @NotNull String idToken,
            @Nullable TorusUtilsExtraParams extraParams,
            @Nullable Boolean useDkg,
            @Nullable Boolean checkCommitment,
            @Nullable String recordId,
            @Nullable String authConnection
    ) {
        this.endpoints = endpoints;
        this.indexes = indexes;
        this.nodePubkeys = nodePubkeys;
        this.verifier = verifier;
        this.verifierParams = verifierParams;
        this.idToken = idToken;
        this.extraParams = extraParams;
        this.useDkg = useDkg;
        this.checkCommitment = checkCommitment;
        this.recordId = recordId;
        this.authConnection = authConnection;
    }
}
