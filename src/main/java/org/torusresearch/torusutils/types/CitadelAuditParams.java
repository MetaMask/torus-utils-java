package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;

public class CitadelAuditParams extends CitadelAuthFlowAuditParams {
    public final String recordId;
    public final String authConnection;
    public final String authConnectionId;
    public final String groupedAuthConnectionId;
    public final String oAuthUserId;
    public final String web3AuthNetwork;
    public final String web3AuthClientId;

    public CitadelAuditParams(
            @NotNull String recordId,
            @NotNull String authConnection,
            @NotNull String authConnectionId,
            @NotNull String groupedAuthConnectionId,
            @NotNull String oAuthUserId,
            @NotNull String web3AuthNetwork,
            @NotNull String web3AuthClientId
    ) {
        this.recordId = recordId;
        this.authConnection = authConnection;
        this.authConnectionId = authConnectionId;
        this.groupedAuthConnectionId = groupedAuthConnectionId;
        this.oAuthUserId = oAuthUserId;
        this.web3AuthNetwork = web3AuthNetwork;
        this.web3AuthClientId = web3AuthClientId;
    }
}
