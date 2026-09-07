package org.torusresearch.torusutils.apis.responses;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class CommitmentRequestResult {
    public final String signature;
    public final String data;
    public final String nodepubx;
    public final String nodepuby;
    public final String nodeindex;
    @Nullable
    public final String pub_key_x;

    public CommitmentRequestResult(@NotNull String data, @NotNull String nodepubx, @NotNull String nodepuby, @NotNull String signature, @NotNull String nodeindex) {
        this(data, nodepubx, nodepuby, signature, nodeindex, null);
    }

    public CommitmentRequestResult(@NotNull String data, @NotNull String nodepubx, @NotNull String nodepuby, @NotNull String signature, @NotNull String nodeindex, @Nullable String pubKeyX) {
        this.data = data;
        this.nodeindex = nodeindex;
        this.signature = signature;
        this.nodepubx = nodepubx;
        this.nodepuby = nodepuby;
        this.pub_key_x = pubKeyX;
    }
}
