package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.types.common.TorusKeyType;

public class ShareRequestParams {
    @SuppressWarnings("unused")
    public final String encrypted = "yes";
    @SuppressWarnings("unused")
    public final boolean one_key_flow = true;
    @SuppressWarnings("unused")
    public final boolean use_temp = true;
    @SuppressWarnings("unused")
    public final boolean distributed_metadata = true;
    public final String client_time;
    public final ShareRequestItem[] item;
    @Nullable
    public final String verifieridentifier;
    @Nullable
    public final String temppubx;
    @Nullable
    public final String temppuby;
    @Nullable
    public final TorusKeyType key_type;

    public ShareRequestParams(@NotNull ShareRequestItem[] item, @NotNull String client_time) {
        this(item, client_time, null, null, null, null);
    }

    public ShareRequestParams(
            @NotNull ShareRequestItem[] item,
            @NotNull String client_time,
            @Nullable String verifieridentifier,
            @Nullable String temppubx,
            @Nullable String temppuby,
            @Nullable TorusKeyType keyType
    ) {
        this.item = item;
        this.client_time = client_time;
        this.verifieridentifier = verifieridentifier;
        this.temppubx = temppubx;
        this.temppuby = temppuby;
        this.key_type = keyType;
    }
}
