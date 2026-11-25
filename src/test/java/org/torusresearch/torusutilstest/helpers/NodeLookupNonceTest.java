package org.torusresearch.torusutilstest.helpers;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.NodeUtils;
import org.torusresearch.torusutils.helpers.TorusUtilError;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyLookupResult;
import org.torusresearch.torusutils.types.common.TypeOfUser;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Like torus.js, the key lookup keeps reading node responses until one of them carries the nonce,
 * instead of stopping at the first threshold of matching keys.
 */
class NodeLookupNonceTest {
    private final List<HttpServer> servers = new ArrayList<>();

    @AfterEach
    void stopServers() {
        for (HttpServer server : servers) {
            server.stop(0);
        }
    }

    private static String[] pub(long privateKey) {
        try {
            return KeyUtils.getPublicKeyCoords(KeyUtils.privateToPublic(BigInteger.valueOf(privateKey)));
        } catch (TorusUtilError error) {
            throw new IllegalStateException(error);
        }
    }

    private String startNode(String body) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        servers.add(server);
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/jrpc";
    }

    private static String nodeBody(boolean withNonce, String nodeIndex) {
        String[] oAuthPub = pub(1);
        String[] noncePub = pub(2);
        String nonceData = withNonce
                ? ",\"nonce_data\":{\"typeOfUser\":\"v2\",\"nonce\":\"\",\"pubNonce\":{\"x\":\"" + noncePub[0] + "\",\"y\":\"" + noncePub[1] + "\"},\"upgraded\":false}"
                : "";
        return "{\"jsonrpc\":\"2.0\",\"id\":10,\"result\":{\"is_new_key\":false,\"keys\":[{\"pub_key_X\":\"" + oAuthPub[0]
                + "\",\"pub_key_Y\":\"" + oAuthPub[1] + "\",\"address\":\"0x0\"" + nonceData + "}],\"node_index\":\"" + nodeIndex
                + "\",\"server_time_offset\":\"0\"}}";
    }

    @Test
    void waitsForANodeThatCarriesTheNonceAfterThresholdKeysMatch() throws Exception {
        // 3 nodes, threshold is 2: the first two agree on the key but carry no nonce
        String[] endpoints = {
                startNode(nodeBody(false, "1")),
                startNode(nodeBody(false, "2")),
                startNode(nodeBody(true, "3")),
        };

        KeyLookupResult result = NodeUtils.getPubKeyOrKeyAssign(endpoints, "verifier", "user@example.com", 0, null);

        assertThat(result.nonceResult).isNotNull();
        assertThat(result.nonceResult.typeOfUser).isEqualTo(TypeOfUser.v2);
        assertThat(result.nonceResult.pubNonce.x).isEqualTo(pub(2)[0]);
    }

    @Test
    void usesTheNonceOfAnEarlyNode() throws Exception {
        String[] endpoints = {
                startNode(nodeBody(true, "1")),
                startNode(nodeBody(false, "2")),
                startNode(nodeBody(false, "3")),
        };

        KeyLookupResult result = NodeUtils.getPubKeyOrKeyAssign(endpoints, "verifier", "user@example.com", 0, null);

        assertThat(result.nonceResult).isNotNull();
        assertThat(result.nonceResult.pubNonce.y).isEqualTo(pub(2)[1]);
    }

    @Test
    void returnsNoNonceWhenNoNodeCarriesOne() throws Exception {
        String[] endpoints = {
                startNode(nodeBody(false, "1")),
                startNode(nodeBody(false, "2")),
                startNode(nodeBody(false, "3")),
        };

        KeyLookupResult result = NodeUtils.getPubKeyOrKeyAssign(endpoints, "verifier", "user@example.com", 0, null);

        assertThat(result.nonceResult).isNull();
        assertThat(result.keyResult).isNotNull();
    }

    @Test
    void anExtendedVerifierIdNeedsNoNonce() throws Exception {
        String[] endpoints = {
                startNode(nodeBody(false, "1")),
                startNode(nodeBody(false, "2")),
                startNode(nodeBody(false, "3")),
        };

        KeyLookupResult result = NodeUtils.getPubKeyOrKeyAssign(endpoints, "verifier", "user@example.com", 0, "user@example.com\u0015default\u00160");

        assertThat(result.keyResult).isNotNull();
        assertThat(result.nonceResult).isNull();
    }
}
