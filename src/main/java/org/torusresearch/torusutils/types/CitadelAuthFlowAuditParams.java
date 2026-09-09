package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.Nullable;

public class CitadelAuthFlowAuditParams {
    @Nullable
    public Boolean oauthInitiated;
    @Nullable
    public Boolean oauthVerified;
    @Nullable
    public Boolean oauthCompleted;
    @Nullable
    public Boolean oauthVerificationFailed;
    @Nullable
    public Boolean oauthFailed;
}
