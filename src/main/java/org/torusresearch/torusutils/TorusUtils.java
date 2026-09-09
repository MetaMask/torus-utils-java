package org.torusresearch.torusutils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.fetchnodedetails.types.Utils;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.JsonRPCErrorInfo;
import org.torusresearch.torusutils.apis.requests.GetMetadataParams;
import org.torusresearch.torusutils.apis.responses.GetMetadataResponse;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.LegacyVerifierKey;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.LegacyVerifierLookupResponse;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierKey;
import org.torusresearch.torusutils.helpers.Common;
import org.torusresearch.torusutils.helpers.CitadelUtils;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.MetadataUtils;
import org.torusresearch.torusutils.helpers.NodeUtils;
import org.torusresearch.torusutils.helpers.TorusUtilError;
import org.torusresearch.torusutils.types.CitadelAllowParams;
import org.torusresearch.torusutils.types.CitadelAuditParams;
import org.torusresearch.torusutils.types.CitadelAuthFlowAuditParams;
import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.ImportPrivateKeyParams;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;
import org.torusresearch.torusutils.types.RetrieveSharesParams;
import org.torusresearch.torusutils.types.TorusUtilsExtraParams;
import org.torusresearch.torusutils.types.VerifierParams;
import org.torusresearch.torusutils.types.common.ImportedShare;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyLookupResult;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyResult;
import org.torusresearch.torusutils.types.common.PubNonce;
import org.torusresearch.torusutils.types.common.TorusKey;
import org.torusresearch.torusutils.types.common.TorusKeyType;
import org.torusresearch.torusutils.types.common.TorusOptions;
import org.torusresearch.torusutils.types.common.TorusPublicKey;
import org.torusresearch.torusutils.types.common.TypeOfUser;
import org.torusresearch.torusutils.helpers.CitadelUtils.CitadelAllowParamsSetOrUnsetFlag;

import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import io.reactivex.annotations.Nullable;

public class TorusUtils {
    private final String defaultHost;
    private final TorusOptions options;
    private int sessionTime = 86400;
    private final TorusKeyType keyType;
    private String apiKey = "torus-default";

    {
        setupBouncyCastle();
    }

    public TorusUtils(TorusOptions options) throws TorusUtilError {
        this.options = options;
        this.keyType = options.keyType;
        if (options.legacyMetadataHost == null) {
            if (isLegacyNetorkRouteMap(options.network)) {
                this.defaultHost = Utils.LEGACY_METADATA_MAP.get(options.buildEnv);
            } else {
                if (options.network.name().equalsIgnoreCase("sapphire_mainnet")) {
                    this.defaultHost = "https://node-1.node.web3auth.io/metadata";
                } else if (options.network.name().equalsIgnoreCase("sapphire_devnet")) {
                    this.defaultHost = "https://node-1.dev-node.web3auth.io/metadata";
                } else {
                    throw TorusUtilError.INVALID_INPUT;
                }
            }
        } else {
            this.defaultHost = options.legacyMetadataHost;
        }
    }

    public static boolean isLegacyNetorkRouteMap(@NotNull Web3AuthNetwork network) {
        return network.isLegacyNetwork();
    }

    @SuppressWarnings("unused")
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
        APIUtils.setApiKey(apiKey);
    }

    @SuppressWarnings("unused")
    public void removeApiKey() {
        this.apiKey = "torus-default";
        APIUtils.setApiKey("torus-default");
    }

    public void setSessionTime(int sessionTime) {
        this.sessionTime = sessionTime;
    }

    private void setupBouncyCastle() {
        final Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            // Web3j will set up the provider lazily when it's first used.
            return;
        }
        if (provider.getClass().equals(BouncyCastleProvider.class)) {
            // BC with same package name, shouldn't happen in real life.
            return;
        }
        // Android registers its own BC provider. As it might be outdated and might not include
        // all needed ciphers, we substitute it with a known BC bundled in the app.
        // Android's BC has its package rewritten to "com.android.org.bouncycastle" and because
        // of that it's possible to have another BC implementation loaded in VM.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    @SuppressWarnings("unused")
    public static String getPostboxKey(TorusKey torusKey) {
        if (torusKey.getMetadata().getTypeOfUser() == TypeOfUser.v1) {
            return (torusKey.getFinalKeyData().getPrivKey() == null || torusKey.getFinalKeyData().getPrivKey().isEmpty()) ? torusKey.getoAuthKeyData().getPrivKey() : torusKey.getFinalKeyData().getPrivKey();
        }
        return torusKey.getoAuthKeyData().getPrivKey();
    }

    public TorusKey retrieveShares(@NotNull RetrieveSharesParams params) throws Exception {
        return retrieveShares(params, false);
    }

    private TorusKey retrieveShares(@NotNull RetrieveSharesParams params, boolean allowMissingNodeDetails) throws Exception {
        validateRetrieveSharesParams(params, allowMissingNodeDetails);

        TorusUtilsExtraParams extraParams = params.extraParams == null ? new TorusUtilsExtraParams() : params.extraParams;
        if (extraParams.session_token_exp_second == null) {
            extraParams.session_token_exp_second = this.sessionTime;
        }

        boolean shouldUseDkg;
        if (params.useDkg != null) {
            if (!params.useDkg && isLegacyNetorkRouteMap(this.options.network)) {
                throw TorusUtilError.RUNTIME_ERROR("useDkg cannot be false for legacy network; " + this.options.network);
            }
            shouldUseDkg = this.keyType != TorusKeyType.ed25519 && params.useDkg;
        } else {
            shouldUseDkg = this.keyType != TorusKeyType.ed25519;
        }

        final boolean callerSuppliedRecordId = params.recordId != null && !params.recordId.isEmpty();
        final String recordId = callerSuppliedRecordId ? params.recordId : CitadelUtils.generateRecordId();
        final boolean checkCommitment = params.checkCommitment == null || params.checkCommitment;

        try {
            TorusKey result = NodeUtils.retrieveOrImportShare(
                    this.defaultHost,
                    this.options.serverTimeOffset,
                    this.options.enableOneKey,
                    this.options.network,
                    this.options.clientId,
                    this.options.buildEnv,
                    params.endpoints,
                    params.indexes,
                    params.nodePubkeys,
                    params.verifier,
                    params.verifierParams,
                    params.idToken,
                    null,
                    null,
                    extraParams,
                    this.keyType,
                    shouldUseDkg,
                    checkCommitment,
                    recordId,
                    this.options.source
            );

            if (callerSuppliedRecordId) {
                CitadelAuthFlowAuditParams audit = new CitadelAuthFlowAuditParams();
                audit.oauthCompleted = true;
                audit.oauthVerified = true;
                reportUserAuthFlowAudit(params, recordId, audit);
            } else {
                reportSignerAllow(createAllowParams(
                        params.verifier,
                        params.verifierParams.verifier_id,
                        recordId,
                        null,
                        CitadelAllowParamsSetOrUnsetFlag.SET
                ));
            }
            return result;
        } catch (Exception error) {
            if (callerSuppliedRecordId) {
                CitadelAuthFlowAuditParams audit = new CitadelAuthFlowAuditParams();
                audit.oauthCompleted = true;
                audit.oauthVerificationFailed = true;
                reportUserAuthFlowAudit(params, recordId, audit);
            } else {
                reportSignerAllow(createAllowParams(
                        params.verifier,
                        params.verifierParams.verifier_id,
                        recordId,
                        CitadelAllowParamsSetOrUnsetFlag.SET,
                        null
                ));
            }
            throw error;
        }
    }

    /**
     * @deprecated Use {@link #retrieveShares(RetrieveSharesParams)}.
     */
    @Deprecated
    public TorusKey retrieveShares(@NotNull String[] endpoints, @NotNull String verifier, @NotNull VerifierParams verifierParams, @NotNull String idToken, @Nullable TorusUtilsExtraParams extraParams) throws Exception {
        return retrieveShares(new RetrieveSharesParams(
                endpoints,
                new BigInteger[0],
                new TorusNodePub[0],
                verifier,
                verifierParams,
                idToken,
                extraParams,
                true,
                true,
                null,
                null
        ), true);
    }

    public TorusPublicKey getPublicAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId) throws Exception {
        return getNewPublicAddress(endpoints, verifier, verifierId, extendedVerifierId, getNetworkInfo(), this.options.enableOneKey);
    }

    private void validateRetrieveSharesParams(@NotNull RetrieveSharesParams params, boolean allowMissingNodeDetails) throws TorusUtilError {
        if (params.endpoints.length == 0) {
            throw TorusUtilError.RUNTIME_ERROR("endpoints param is required");
        }

        if (!allowMissingNodeDetails && params.nodePubkeys.length == 0) {
            throw TorusUtilError.RUNTIME_ERROR("nodePubkeys param is required");
        }
        if (!allowMissingNodeDetails && params.nodePubkeys.length != params.indexes.length) {
            throw TorusUtilError.RUNTIME_ERROR("nodePubkeys length must be same as indexes length");
        }
        if (!allowMissingNodeDetails && params.nodePubkeys.length != params.endpoints.length) {
            throw TorusUtilError.RUNTIME_ERROR("nodePubkeys length must be same as endpoints length");
        }
        if (Boolean.FALSE.equals(params.useDkg) && params.nodePubkeys.length == 0) {
            throw TorusUtilError.RUNTIME_ERROR("nodePubkeys and indexes are required when useDkg is false");
        }
    }

    private CitadelAllowParams createAllowParams(
            @NotNull String verifier,
            @NotNull String verifierId,
            @NotNull String recordId,
            @Nullable CitadelAllowParamsSetOrUnsetFlag oauthVerificationFailed,
            @Nullable CitadelAllowParamsSetOrUnsetFlag oauthVerified
    ) {
        return new CitadelAllowParams(
                this.options.buildEnv,
                verifier,
                verifierId,
                this.options.network.name().toLowerCase(Locale.ROOT),
                this.options.clientId,
                recordId,
                this.options.source,
                null,
                oauthVerified,
                null,
                oauthVerificationFailed,
                null
        );
    }

    void reportSignerAllow(@NotNull CitadelAllowParams params) {
        try {
            CitadelUtils.callAllowApi(params).exceptionally(error -> {
                System.err.println("Failed to log allow api: " + error.getMessage());
                return null;
            });
        } catch (Exception error) {
            System.err.println("Failed to log allow api: " + error.getMessage());
        }
    }

    void reportUserAuthFlowAudit(
            @NotNull RetrieveSharesParams params,
            @NotNull String recordId,
            @NotNull CitadelAuthFlowAuditParams authFlowAuditParams
    ) {
        try {
            CitadelAuditParams auditParams = CitadelUtils.buildAuditPayload(
                    this.options.network,
                    this.options.clientId,
                    params,
                    recordId,
                    authFlowAuditParams
            );
            CitadelUtils.callAuditApi(this.options.buildEnv, auditParams).exceptionally(error -> {
                System.err.println("Failed to log user auth flow audit: " + error.getMessage());
                return null;
            });
        } catch (Exception error) {
            System.err.println("Failed to log user auth flow audit: " + error.getMessage());
        }
    }

    public TorusKey importPrivateKey(@NotNull ImportPrivateKeyParams params) throws Exception {
        if (isLegacyNetorkRouteMap(this.options.network)) {
            throw TorusUtilError.RUNTIME_ERROR("importPrivateKey is not supported by legacy network; " + this.options.network);
        }
        if (params.endpoints.length != params.nodeIndexes.length) {
            throw TorusUtilError.RUNTIME_ERROR("Length of endpoints must be the same as length of nodeIndexes");
        }
        if (params.nodePubkeys.length != params.endpoints.length) {
            throw TorusUtilError.RUNTIME_ERROR("Length of nodePubkeys must be the same as length of endpoints");
        }
        if (!params.newPrivateKey.matches("^[0-9a-fA-F]{1,64}$")) {
            throw TorusUtilError.RUNTIME_ERROR("Invalid private key length for given secp256k1 key");
        }

        TorusUtilsExtraParams extraParams = params.extraParams == null ? new TorusUtilsExtraParams() : params.extraParams;
        if (extraParams.session_token_exp_second == null) {
            extraParams.session_token_exp_second = this.sessionTime;
        }

        List<ImportedShare> shares = KeyUtils.generateShares(
                this.keyType,
                this.options.serverTimeOffset,
                Arrays.asList(params.nodeIndexes),
                Arrays.asList(params.nodePubkeys),
                params.newPrivateKey
        );
        String recordId = params.recordId == null || params.recordId.isEmpty()
                ? CitadelUtils.generateRecordId()
                : params.recordId;

        return NodeUtils.retrieveOrImportShare(
                this.defaultHost,
                this.options.serverTimeOffset,
                this.options.enableOneKey,
                this.options.network,
                this.options.clientId,
                this.options.buildEnv,
                params.endpoints,
                params.nodeIndexes,
                params.nodePubkeys,
                params.verifier,
                params.verifierParams,
                params.idToken,
                shares.toArray(new ImportedShare[0]),
                params.newPrivateKey,
                extraParams,
                this.keyType,
                false,
                params.checkCommitment == null || params.checkCommitment,
                recordId,
                this.options.source
        );
    }

    /**
     * @deprecated Use {@link #importPrivateKey(ImportPrivateKeyParams)}.
     */
    @Deprecated
    public TorusKey importPrivateKey(
            @NotNull String[] endpoints,
            @NotNull BigInteger[] nodeIndexes,
            @NotNull TorusNodePub[] nodePubKeys,
            @NotNull String verifier,
            @NotNull VerifierParams verifierParams,
            @NotNull String idToken,
            @NotNull String newPrivateKey,
            @Nullable TorusUtilsExtraParams extraParams
    ) throws Exception {
        return importPrivateKey(new ImportPrivateKeyParams(
                endpoints,
                nodeIndexes,
                nodePubKeys,
                verifier,
                verifierParams,
                idToken,
                newPrivateKey,
                extraParams,
                true,
                null
        ));
    }

    public TorusPublicKey getUserTypeAndAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId) throws Exception {
        return getNewPublicAddress(endpoints, verifier, verifierId, extendedVerifierId, getNetworkInfo(), true);
    }

    private TorusPublicKey getNewPublicAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId, Web3AuthNetwork network, @NotNull Boolean enableOneKey) throws Exception {
        KeyLookupResult keyAssignResult = NodeUtils.getPubKeyOrKeyAssign(endpoints, network, verifier, verifierId, this.defaultHost, this.options.serverTimeOffset, extendedVerifierId);

        JsonRPCErrorInfo errorResult = keyAssignResult.errorResult;
        if (errorResult != null) {
            if (errorResult.message.toLowerCase().contains("verifier not supported")) {
                throw TorusUtilError.RUNTIME_ERROR("Verifier not supported. Check if you:\n1. Are on the right network (Torus testnet/mainnet)\n2. Have setup a verifier on dashboard.web3auth.io?");
            } else {
                throw TorusUtilError.RUNTIME_ERROR(errorResult.message);
            }
        }

        KeyResult keyResult = keyAssignResult.keyResult;
        if (keyResult == null || keyResult.keys.length == 0) {
            throw TorusUtilError.RUNTIME_ERROR("node results do not match at first lookup");
        }

        GetOrSetNonceResult nonceResult = keyAssignResult.nonceResult;
        if (nonceResult == null && extendedVerifierId == null && !isLegacyNetorkRouteMap(network)) {
            throw TorusUtilError.RUNTIME_ERROR("metadata nonce is missing in share response");
        }

        String pubKey = KeyUtils.getPublicKeyFromCoords(keyResult.keys[0].pub_key_X, keyResult.keys[0].pub_key_Y, false);

        PubNonce pubNonce = null;
        BigInteger nonce;
        if (nonceResult != null && nonceResult.nonce != null && !nonceResult.nonce.isEmpty()) {
            nonce = new BigInteger(nonceResult.nonce);
        } else {
            nonce = BigInteger.ZERO;
        }

        String oAuthPubKey;
        String finalPubKey;

        Integer finalServerTimeOffset = (this.options.serverTimeOffset != null) ? this.options.serverTimeOffset : keyAssignResult.server_time_offset;

        if (extendedVerifierId != null) {
            finalPubKey = pubKey;
            oAuthPubKey = finalPubKey;
        } else if (isLegacyNetorkRouteMap(network)) {
            ArrayList<LegacyVerifierKey> legacyKeys = new ArrayList<>();
            for (VerifierKey i : keyAssignResult.keyResult.keys) {
                legacyKeys.add(new LegacyVerifierKey(i.pub_key_X, i.pub_key_Y, i.address));
            }
            LegacyVerifierLookupResponse verifierLegacyLookupItem =
                    new LegacyVerifierLookupResponse(legacyKeys.toArray(new LegacyVerifierKey[0]), finalServerTimeOffset.toString());
            return formatLegacyPublicKeyData(verifierLegacyLookupItem, enableOneKey, keyAssignResult.keyResult.is_new_key, finalServerTimeOffset);
        } else {
            String[] pubKeyCoords = KeyUtils.getPublicKeyCoords(pubKey);
            String _X = pubKeyCoords[0];
            String _Y = pubKeyCoords[1];
            PubNonce finalPubNonce = null;
            if (nonceResult != null && nonceResult.pubNonce != null) {
                finalPubNonce = nonceResult.pubNonce;
            }
            oAuthPubKey = KeyUtils.getPublicKeyFromCoords(_X, _Y, true);
            finalPubKey = oAuthPubKey;
            pubNonce = finalPubNonce;
            if (pubNonce != null && !pubNonce.x.isEmpty() && !pubNonce.y.isEmpty()) {
                String pubNonceKey = KeyUtils.getPublicKeyFromCoords(pubNonce.x, pubNonce.y, true);
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPubKey, pubNonceKey), false);

            } else {
                throw TorusUtilError.METADATA_NONCE_MISSING;
            }
        }

        if (oAuthPubKey == null || finalPubKey == null) {
            throw new Error("could not derive private key");
        }
        String[] oAuthPubKeyCoords = KeyUtils.getPublicKeyCoords(oAuthPubKey);
        String[] finalPubKeyCoords = KeyUtils.getPublicKeyCoords(finalPubKey);

        String oAuthPubKeyX = oAuthPubKeyCoords[0];
        String oAuthPubKeyY = oAuthPubKeyCoords[1];
        String finalPubKeyX = finalPubKeyCoords[0];
        String finalPubKeyY = finalPubKeyCoords[1];

        String oAuthAddress = KeyUtils.generateAddressFromPubKey(oAuthPubKeyX, oAuthPubKeyY);
        String finalAddresss = KeyUtils.generateAddressFromPubKey(finalPubKeyX, finalPubKeyY);

        return new TorusPublicKey(new OAuthPubKeyData(oAuthAddress, oAuthPubKeyX, oAuthPubKeyY),
                new FinalPubKeyData(finalAddresss, finalPubKeyX, finalPubKeyY),
                new Metadata(pubNonce, nonce, TypeOfUser.v2, ((nonceResult != null) && (nonceResult.upgraded != null) && (nonceResult.upgraded)), finalServerTimeOffset),
                new NodesData(keyAssignResult.nodeIndexes));
    }

    private TorusPublicKey formatLegacyPublicKeyData(@NotNull LegacyVerifierLookupResponse finalKeyResult, boolean enableOneKey, boolean isNewKey,
                                                     @NotNull Integer serverTimeOffset) throws Exception {
        LegacyVerifierKey key = finalKeyResult.keys[0];
        String X = key.pub_key_X;
        String Y = key.pub_key_Y;
        GetOrSetNonceResult nonceResult = null;
        String finalPubKey;
        BigInteger nonce;
        TypeOfUser typeOfUser;
        PubNonce pubNonce = null;

        String oAuthPubKey = KeyUtils.getPublicKeyFromCoords(X, Y, true);
        Integer finalServerTimeOffset = (this.options.serverTimeOffset == null) ? serverTimeOffset : this.options.serverTimeOffset;

        if (enableOneKey) {
            nonceResult = MetadataUtils.getOrSetNonce(this.defaultHost, X, Y, finalServerTimeOffset, null, !isNewKey, null);
            nonce = (nonceResult.nonce == null) ? BigInteger.ZERO : new BigInteger(nonceResult.nonce, 16);
            typeOfUser = (nonceResult.typeOfUser == null) ? TypeOfUser.v1 : nonceResult.typeOfUser;

            if (typeOfUser == TypeOfUser.v1) {
                finalPubKey = oAuthPubKey;
                GetMetadataResponse metadataResponse = MetadataUtils.getMetadata(this.defaultHost, new GetMetadataParams(X, Y));
                nonce = new BigInteger(Common.isEmpty(metadataResponse.message) ? "0" : metadataResponse.message, 16);

                if (nonce.compareTo(BigInteger.ZERO) > 0) {
                    String noncePublicKey = KeyUtils.privateToPublic(nonce);
                    finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(finalPubKey, noncePublicKey), false);
                }
            } else if (typeOfUser == TypeOfUser.v2) {
                if (nonceResult.pubNonce == null) {
                    throw TorusUtilError.RUNTIME_ERROR("getOrSetNonce should always return typeOfUser.");
                }
                String pubNonceKey = KeyUtils.getPublicKeyFromCoords(nonceResult.pubNonce.x, nonceResult.pubNonce.y, true);
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPubKey, pubNonceKey), false);
                pubNonce = nonceResult.pubNonce;
            } else {
                throw TorusUtilError.RUNTIME_ERROR("getOrSetNonce should always return typeOfUser.");
            }
        } else {
            typeOfUser = TypeOfUser.v1;
            finalPubKey = oAuthPubKey;
            GetMetadataResponse metadataResponse = MetadataUtils.getMetadata(this.defaultHost, new GetMetadataParams(X, Y));
            nonce = new BigInteger(Common.isEmpty(metadataResponse.message) ? "0" : metadataResponse.message, 16);
            if (nonce.compareTo(BigInteger.ZERO) > 0) {
                String noncePublicKey = KeyUtils.privateToPublic(nonce);
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(finalPubKey, noncePublicKey), false);
            }
        }

        String oAuthAddress = KeyUtils.generateAddressFromPubKey(Common.padLeft(X, '0', 64), Common.padLeft(Y, '0', 64));

        if (typeOfUser == TypeOfUser.v2 && finalPubKey == null) {
            throw TorusUtilError.PRIVATE_KEY_DERIVE_FAILED;
        }

        String[] finalPubKeyCoords = KeyUtils.getPublicKeyCoords(finalPubKey);
        String finalAddress = KeyUtils.generateAddressFromPubKey(finalPubKeyCoords[0], finalPubKeyCoords[1]);

        return new TorusPublicKey(new OAuthPubKeyData(oAuthAddress, Common.padLeft(X, '0', 64), Common.padLeft(Y, '0', 64)),
                new FinalPubKeyData(finalAddress, finalPubKeyCoords[0], finalPubKeyCoords[1]),
                new Metadata(pubNonce, nonce, typeOfUser, (nonceResult != null && nonceResult.upgraded != null) ? nonceResult.upgraded : false, serverTimeOffset),
                new NodesData(new ArrayList<>()));
    }

    private Web3AuthNetwork getNetworkInfo() {
        return this.options.network;
    }
}
