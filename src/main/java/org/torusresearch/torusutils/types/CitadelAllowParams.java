package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.helpers.CitadelUtils.CitadelAllowParamsSetOrUnsetFlag;
import org.torusresearch.torusutils.types.common.BuildEnv;

public class CitadelAllowParams {
    public final BuildEnv buildEnv;
    public final String verifier;
    public final String verifierId;
    public final String network;
    public final String clientId;
    public final String recordId;
    @Nullable
    public final String source;
    @Nullable
    public final CitadelAllowParamsSetOrUnsetFlag oauthInitiated;
    @Nullable
    public final CitadelAllowParamsSetOrUnsetFlag oauthVerified;
    @Nullable
    public final CitadelAllowParamsSetOrUnsetFlag oauthCompleted;
    @Nullable
    public final CitadelAllowParamsSetOrUnsetFlag oauthVerificationFailed;
    @Nullable
    public final CitadelAllowParamsSetOrUnsetFlag oauthFailed;

    public CitadelAllowParams(
            @NotNull BuildEnv buildEnv,
            @NotNull String verifier,
            @NotNull String verifierId,
            @NotNull String network,
            @NotNull String clientId,
            @NotNull String recordId,
            @Nullable String source,
            @Nullable CitadelAllowParamsSetOrUnsetFlag oauthInitiated,
            @Nullable CitadelAllowParamsSetOrUnsetFlag oauthVerified,
            @Nullable CitadelAllowParamsSetOrUnsetFlag oauthCompleted,
            @Nullable CitadelAllowParamsSetOrUnsetFlag oauthVerificationFailed,
            @Nullable CitadelAllowParamsSetOrUnsetFlag oauthFailed
    ) {
        this.buildEnv = buildEnv;
        this.verifier = verifier;
        this.verifierId = verifierId;
        this.network = network;
        this.clientId = clientId;
        this.recordId = recordId;
        this.source = source;
        this.oauthInitiated = oauthInitiated;
        this.oauthVerified = oauthVerified;
        this.oauthCompleted = oauthCompleted;
        this.oauthVerificationFailed = oauthVerificationFailed;
        this.oauthFailed = oauthFailed;
    }
}
