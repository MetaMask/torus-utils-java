package org.torusresearch.torusutils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.JsonRPCErrorInfo;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.helpers.Common;
import org.torusresearch.torusutils.helpers.CitadelUtils;
import org.torusresearch.torusutils.helpers.KeyUtils;
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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import io.reactivex.annotations.Nullable;

public class TorusUtils {
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

        final boolean callerSuppliedRecordId = params.recordId != null && !params.recordId.isEmpty();
        final String recordId = callerSuppliedRecordId ? params.recordId : CitadelUtils.generateRecordId();
        final boolean checkCommitment = params.checkCommitment == null || params.checkCommitment;

        try {
            TorusKey result = NodeUtils.retrieveOrImportShare(
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
                    extraParams,
                    this.keyType,
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

        // a legacy dApp without OneKey uses the key itself, so it imports the key with no nonce
        boolean withNonce = !isLegacyNetorkRouteMap(this.options.network) || this.options.enableOneKey;
        List<ImportedShare> shares = KeyUtils.generateShares(
                this.keyType,
                this.options.serverTimeOffset,
                Arrays.asList(params.nodeIndexes),
                Arrays.asList(params.nodePubkeys),
                params.newPrivateKey,
                withNonce
        );
        String recordId = params.recordId == null || params.recordId.isEmpty()
                ? CitadelUtils.generateRecordId()
                : params.recordId;

        TorusKey torusKey = NodeUtils.retrieveOrImportShare(
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
                extraParams,
                this.keyType,
                params.checkCommitment == null || params.checkCommitment,
                recordId,
                this.options.source
        );
        assertImportedKey(torusKey, params.newPrivateKey);
        return torusKey;
    }

    /**
     * The final key must be the imported key. The metadata server keeps a nonce that already exists
     * and still answers with success, so if a different nonce was stored first, this check is the only
     * signal that the import nonce was dropped. An empty final key (an upgraded account without a
     * private nonce) also fails here.
     */
    public static void assertImportedKey(@NotNull TorusKey torusKey, @NotNull String importedPrivateKey) throws TorusUtilError {
        String finalPrivKey = torusKey.getFinalKeyData().getPrivKey();
        String finalKey = Common.padLeft(finalPrivKey == null ? "" : finalPrivKey, '0', 64).toLowerCase(Locale.ROOT);
        String importedKey = Common.padLeft(importedPrivateKey, '0', 64).toLowerCase(Locale.ROOT);
        if (!finalKey.equals(importedKey)) {
            throw TorusUtilError.RUNTIME_ERROR("imported key mismatch: the nodes returned a different final key than expected, this should never occur, please contact web3auth support.");
        }
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
        if (this.keyType == TorusKeyType.ed25519 && isLegacyNetorkRouteMap(network)) {
            throw TorusUtilError.RUNTIME_ERROR("keyType: " + this.keyType + " is not supported by " + network + " network");
        }
        KeyLookupResult keyAssignResult = NodeUtils.getPubKeyOrKeyAssign(endpoints, verifier, verifierId, this.options.serverTimeOffset, extendedVerifierId);
        return formatPublicKeyData(keyAssignResult, extendedVerifierId, network, enableOneKey, this.options.serverTimeOffset);
    }

    /**
     * Derives the public key data from a node key lookup. The metadata nonce is read only from the
     * node response, on every network, and no metadata server is called.
     */
    public static TorusPublicKey formatPublicKeyData(@NotNull KeyLookupResult keyAssignResult, @Nullable String extendedVerifierId, @NotNull Web3AuthNetwork network, boolean enableOneKey, @Nullable Integer serverTimeOffset) throws Exception {
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
        // no need of nonce for extendedVerifierId (tss verifier id)
        if (nonceResult == null && extendedVerifierId == null) {
            throw TorusUtilError.RUNTIME_ERROR("metadata nonce is missing in share response");
        }

        String oAuthPubKey = KeyUtils.getPublicKeyFromCoords(keyResult.keys[0].pub_key_X, keyResult.keys[0].pub_key_Y, true);
        BigInteger nonce = (nonceResult != null && nonceResult.nonce != null && !nonceResult.nonce.isEmpty())
                ? new BigInteger(nonceResult.nonce, 16)
                : BigInteger.ZERO;
        TypeOfUser typeOfUser = (nonceResult != null && nonceResult.typeOfUser == TypeOfUser.v1) ? TypeOfUser.v1 : TypeOfUser.v2;
        PubNonce pubNonce = null;
        String finalPubKey;

        Integer finalServerTimeOffset = (serverTimeOffset != null) ? serverTimeOffset : keyAssignResult.server_time_offset;

        if (extendedVerifierId != null) {
            // for tss key no need to add pub nonce
            finalPubKey = oAuthPubKey;
        } else if (nonceResult != null && nonceResult.typeOfUser == TypeOfUser.v1) {
            finalPubKey = oAuthPubKey;
            if (nonce.compareTo(BigInteger.ZERO) > 0) {
                String noncePublicKey = KeyUtils.privateToPublic(nonce);
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPubKey, noncePublicKey), false);
            }
        } else if (isLegacyNetorkRouteMap(network) && !enableOneKey) {
            // a legacy dApp without OneKey ignores a v2 nonce
            finalPubKey = oAuthPubKey;
            nonce = BigInteger.ZERO;
            typeOfUser = TypeOfUser.v1;
        } else {
            pubNonce = nonceResult == null ? null : nonceResult.pubNonce;
            if (pubNonce == null || pubNonce.x.isEmpty() || pubNonce.y.isEmpty()) {
                throw TorusUtilError.METADATA_NONCE_MISSING;
            }
            String pubNonceKey = KeyUtils.getPublicKeyFromCoords(pubNonce.x, pubNonce.y, true);
            finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPubKey, pubNonceKey), false);
        }

        String[] oAuthPubKeyCoords = KeyUtils.getPublicKeyCoords(oAuthPubKey);
        String[] finalPubKeyCoords = KeyUtils.getPublicKeyCoords(finalPubKey);

        String oAuthPubKeyX = oAuthPubKeyCoords[0];
        String oAuthPubKeyY = oAuthPubKeyCoords[1];
        String finalPubKeyX = finalPubKeyCoords[0];
        String finalPubKeyY = finalPubKeyCoords[1];

        String oAuthAddress = KeyUtils.generateAddressFromPubKey(oAuthPubKeyX, oAuthPubKeyY);
        String finalAddresss = KeyUtils.generateAddressFromPubKey(finalPubKeyX, finalPubKeyY);

        boolean upgraded = typeOfUser == TypeOfUser.v2 && nonceResult != null && nonceResult.upgraded != null && nonceResult.upgraded;

        return new TorusPublicKey(new OAuthPubKeyData(oAuthAddress, oAuthPubKeyX, oAuthPubKeyY),
                new FinalPubKeyData(finalAddresss, finalPubKeyX, finalPubKeyY),
                new Metadata(pubNonce, nonce, typeOfUser, upgraded, finalServerTimeOffset),
                new NodesData(keyAssignResult.nodeIndexes));
    }

    private Web3AuthNetwork getNetworkInfo() {
        return this.options.network;
    }
}
