package org.torusresearch.torusutils.types.common;

/**
 * Deployment environment used by Web3Auth infrastructure services.
 *
 * <p>This enum is kept in torus-utils-java until the equivalent type is
 * available in a released fetch-node-details-java artifact.</p>
 */
public enum BuildEnv {
    PRODUCTION,
    STAGING,
    DEVELOPMENT,
    TESTING
}
