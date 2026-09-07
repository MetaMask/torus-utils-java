package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.types.common.TorusKeyType;

public class CommitmentRequestParams {
    public final String messageprefix;
    public final String tokencommitment;
    public final String temppubx;
    public final String temppuby;
    public final String timestamp;
    public final String verifieridentifier;
    @Nullable
    public final TorusKeyType keytype;
    @Nullable
    public final String verifier_id;
    @Nullable
    public final String extended_verifier_id;
    public final boolean is_import_key_flow;

    public CommitmentRequestParams(@NotNull String messageprefix, @NotNull String tokencommitment, @NotNull String temppubx, @NotNull String temppuby, @Nullable String timestamp, @NotNull String verifieridentifier) {
        this(messageprefix, tokencommitment, temppubx, temppuby, timestamp, verifieridentifier, null, null, null, false);
    }

    public CommitmentRequestParams(
            @NotNull String messageprefix,
            @NotNull String tokencommitment,
            @NotNull String temppubx,
            @NotNull String temppuby,
            @Nullable String timestamp,
            @NotNull String verifieridentifier,
            @Nullable TorusKeyType keytype,
            @Nullable String verifierId,
            @Nullable String extendedVerifierId,
            boolean isImportKeyFlow
    ) {
        this.messageprefix = messageprefix;
        this.tokencommitment = tokencommitment;
        this.temppubx = temppubx;
        this.temppuby = temppuby;
        this.timestamp = timestamp;
        this.verifieridentifier = verifieridentifier;
        this.keytype = keytype;
        this.verifier_id = verifierId;
        this.extended_verifier_id = extendedVerifierId;
        this.is_import_key_flow = isImportKeyFlow;
    }
}
