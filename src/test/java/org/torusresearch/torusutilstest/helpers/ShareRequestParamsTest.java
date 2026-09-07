package org.torusresearch.torusutilstest.helpers;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import org.junit.jupiter.api.Test;
import org.torusresearch.torusutils.apis.requests.CommitmentRequestParams;
import org.torusresearch.torusutils.apis.requests.ShareRequestItem;
import org.torusresearch.torusutils.apis.requests.ShareRequestParams;
import org.torusresearch.torusutils.types.common.TorusKeyType;

class ShareRequestParamsTest {
    @Test
    void serializesSessionPublicKeyForNonCommitmentFlow() {
        ShareRequestParams params = new ShareRequestParams(
                new ShareRequestItem[0],
                "123",
                "google",
                "temp-x",
                "temp-y",
                TorusKeyType.secp256k1
        );

        JsonObject json = new Gson().toJsonTree(params).getAsJsonObject();

        assertThat(json.get("temppubx").getAsString()).isEqualTo("temp-x");
        assertThat(json.get("temppuby").getAsString()).isEqualTo("temp-y");
        assertThat(json.get("verifieridentifier").getAsString()).isEqualTo("google");
        assertThat(json.get("key_type").getAsString()).isEqualTo("secp256k1");
    }

    @Test
    void serializesV17CommitmentFields() {
        CommitmentRequestParams params = new CommitmentRequestParams(
                "mug00",
                "commitment",
                "temp-x",
                "temp-y",
                null,
                "google",
                TorusKeyType.secp256k1,
                "user-id",
                null,
                true
        );

        JsonObject json = new Gson().toJsonTree(params).getAsJsonObject();

        assertThat(json.get("keytype").getAsString()).isEqualTo("secp256k1");
        assertThat(json.get("verifier_id").getAsString()).isEqualTo("user-id");
        assertThat(json.get("is_import_key_flow").getAsBoolean()).isTrue();
    }
}
