package org.torusresearch.torusutils.helpers;

import com.google.gson.Gson;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.types.CitadelAllowParams;
import org.torusresearch.torusutils.types.CitadelAuditParams;
import org.torusresearch.torusutils.types.CitadelAuthFlowAuditParams;
import org.torusresearch.torusutils.types.RetrieveSharesParams;
import org.torusresearch.torusutils.types.common.BuildEnv;

import java.util.UUID;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;

import okhttp3.HttpUrl;

public final class CitadelUtils {
    public enum CitadelAllowParamsSetOrUnsetFlag {
        SET(1),
        UNSET(0);

        private final int value;

        CitadelAllowParamsSetOrUnsetFlag(int value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return Integer.toString(value);
        }
    }

    private CitadelUtils() {
    }

    @NotNull
    public static String buildAllowUrl(@NotNull CitadelAllowParams params) {
        String server = TorusConstants.CITADEL_SERVER_MAP.get(params.buildEnv);
        if (server == null) {
            throw new IllegalArgumentException("Unsupported build environment: " + params.buildEnv);
        }

        HttpUrl baseUrl = HttpUrl.parse(server + "/v1/signer/allow");
        if (baseUrl == null) {
            throw new IllegalArgumentException("Invalid Citadel server URL");
        }

        HttpUrl.Builder url = baseUrl.newBuilder()
                .addQueryParameter("recordid", params.recordId)
                .addQueryParameter("verifier", params.verifier)
                .addQueryParameter("verifierid", params.verifierId)
                .addQueryParameter("network", params.network)
                .addQueryParameter("clientid", params.clientId);
        if (params.source != null && !params.source.isEmpty()) {
            url.addQueryParameter("source", params.source);
        }
        addOptional(url, "oauthInitiated", params.oauthInitiated);
        addOptional(url, "oauthVerified", params.oauthVerified);
        addOptional(url, "oauthCompleted", params.oauthCompleted);
        addOptional(url, "oauthVerificationFailed", params.oauthVerificationFailed);
        addOptional(url, "oauthFailed", params.oauthFailed);
        return url.build().toString();
    }

    @NotNull
    public static CitadelAuditParams buildAuditPayload(
            @NotNull Web3AuthNetwork network,
            @NotNull String clientId,
            @NotNull RetrieveSharesParams params,
            @NotNull CitadelAuthFlowAuditParams authFlowAuditParams
    ) {
        String recordId = params.recordId == null || params.recordId.isEmpty()
                ? generateRecordId()
                : params.recordId;
        return buildAuditPayload(network, clientId, params, recordId, authFlowAuditParams);
    }

    @NotNull
    public static CitadelAuditParams buildAuditPayload(
            @NotNull Web3AuthNetwork network,
            @NotNull String clientId,
            @NotNull RetrieveSharesParams params,
            @NotNull String recordId,
            @NotNull CitadelAuthFlowAuditParams authFlowAuditParams
    ) {
        String authConnectionId = "";
        if (params.verifierParams.sub_verifier_ids != null && params.verifierParams.sub_verifier_ids.length > 0) {
            authConnectionId = params.verifierParams.sub_verifier_ids[0];
        }

        CitadelAuditParams result = new CitadelAuditParams(
                recordId,
                params.authConnection == null ? "" : params.authConnection,
                authConnectionId,
                params.verifier,
                params.verifierParams.verifier_id,
                network.name().toLowerCase(Locale.ROOT),
                clientId
        );
        result.oauthInitiated = authFlowAuditParams.oauthInitiated;
        result.oauthVerified = authFlowAuditParams.oauthVerified;
        result.oauthCompleted = authFlowAuditParams.oauthCompleted;
        result.oauthVerificationFailed = authFlowAuditParams.oauthVerificationFailed;
        result.oauthFailed = authFlowAuditParams.oauthFailed;
        return result;
    }

    @NotNull
    public static CompletableFuture<String> callAllowApi(@NotNull CitadelAllowParams params) {
        return APIUtils.get(buildAllowUrl(params), false);
    }

    @NotNull
    public static CompletableFuture<String> callAuditApi(@NotNull BuildEnv buildEnv, @NotNull CitadelAuditParams params) {
        String server = TorusConstants.CITADEL_SERVER_MAP.get(buildEnv);
        if (server == null) {
            throw new IllegalArgumentException("Unsupported build environment: " + buildEnv);
        }
        return APIUtils.put(server + "/v1/auth/audit", new Gson().toJson(params), false);
    }

    @NotNull
    public static String generateRecordId() {
        return UUID.randomUUID().toString();
    }

    private static void addOptional(HttpUrl.Builder url, String name, Object value) {
        if (value != null) {
            url.addQueryParameter(name, value.toString());
        }
    }
}
