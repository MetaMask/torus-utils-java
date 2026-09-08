package org.torusresearch.torusutilstest.helpers;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.torusresearch.fetchnodedetails.types.BuildEnv;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.helpers.CitadelUtils;
import org.torusresearch.torusutils.helpers.CitadelUtils.CitadelAllowParamsSetOrUnsetFlag;
import org.torusresearch.torusutils.types.CitadelAllowParams;
import org.torusresearch.torusutils.types.CitadelAuditParams;
import org.torusresearch.torusutils.types.CitadelAuthFlowAuditParams;
import org.torusresearch.torusutils.types.RetrieveSharesParams;
import org.torusresearch.torusutils.types.VerifierParams;

import java.math.BigInteger;
import java.util.UUID;

import okhttp3.HttpUrl;

class CitadelUtilsTest {
    @Test
    void buildsAllowUrlWithExactQueryNamesAndEncodedValues() {
        CitadelAllowParams params = new CitadelAllowParams(
                BuildEnv.DEVELOPMENT,
                "google",
                "user+alias@example.com",
                "sapphire_devnet",
                "client id",
                "record-id",
                "android sdk",
                CitadelAllowParamsSetOrUnsetFlag.SET,
                null,
                CitadelAllowParamsSetOrUnsetFlag.UNSET,
                CitadelAllowParamsSetOrUnsetFlag.SET,
                null
        );

        HttpUrl url = HttpUrl.parse(CitadelUtils.buildAllowUrl(params));

        assertThat(url).isNotNull();
        assertThat(url.scheme()).isEqualTo("https");
        assertThat(url.host()).isEqualTo("api-develop.web3auth.io");
        assertThat(url.encodedPath()).isEqualTo("/citadel-service/v1/signer/allow");
        assertThat(url.queryParameter("recordid")).isEqualTo("record-id");
        assertThat(url.queryParameter("verifier")).isEqualTo("google");
        assertThat(url.queryParameter("verifierid")).isEqualTo("user+alias@example.com");
        assertThat(url.queryParameter("network")).isEqualTo("sapphire_devnet");
        assertThat(url.queryParameter("clientid")).isEqualTo("client id");
        assertThat(url.queryParameter("source")).isEqualTo("android sdk");
        assertThat(url.queryParameter("oauthInitiated")).isEqualTo("1");
        assertThat(url.queryParameter("oauthCompleted")).isEqualTo("0");
        assertThat(url.queryParameter("oauthVerificationFailed")).isEqualTo("1");
        assertThat(url.queryParameter("oauthVerified")).isNull();
        assertThat(url.queryParameter("oauthFailed")).isNull();
    }

    @Test
    void buildsAuditPayloadFromRetrieveSharesParams() {
        VerifierParams verifierParams = new VerifierParams(
                "user-id",
                null,
                new String[]{"google"},
                null
        );
        RetrieveSharesParams retrieveParams = new RetrieveSharesParams(
                new String[]{"endpoint"},
                new BigInteger[]{BigInteger.ONE},
                new TorusNodePub[]{new TorusNodePub("x", "y")},
                "aggregate-verifier",
                verifierParams,
                "id-token",
                null,
                true,
                true,
                "record-id",
                "auth0"
        );
        CitadelAuthFlowAuditParams flags = new CitadelAuthFlowAuditParams();
        flags.oauthCompleted = true;
        flags.oauthVerified = true;

        CitadelAuditParams result = CitadelUtils.buildAuditPayload(
                Web3AuthNetwork.SAPPHIRE_DEVNET,
                "client-id",
                retrieveParams,
                "record-id",
                flags
        );

        assertThat(result.recordId).isEqualTo("record-id");
        assertThat(result.authConnection).isEqualTo("auth0");
        assertThat(result.authConnectionId).isEqualTo("google");
        assertThat(result.groupedAuthConnectionId).isEqualTo("aggregate-verifier");
        assertThat(result.oAuthUserId).isEqualTo("user-id");
        assertThat(result.web3AuthNetwork).isEqualTo("sapphire_devnet");
        assertThat(result.web3AuthClientId).isEqualTo("client-id");
        assertThat(result.oauthCompleted).isTrue();
        assertThat(result.oauthVerified).isTrue();
    }

    @Test
    void generatesUuidRecordId() {
        String recordId = CitadelUtils.generateRecordId();

        assertThat(UUID.fromString(recordId).toString()).isEqualTo(recordId);
    }
}
