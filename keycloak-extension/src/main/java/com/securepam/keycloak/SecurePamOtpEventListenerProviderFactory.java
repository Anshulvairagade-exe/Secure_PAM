
package com.securepam.keycloak;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class SecurePamOtpEventListenerProviderFactory
        implements EventListenerProviderFactory {

    public static final String ID = "securepam-otp-audit";

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new SecurePamOtpEventListenerProvider();
    }

    @Override
    public void init(Config.Scope config) {
        // No additional configuration required.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization work required.
    }

    @Override
    public void close() {
        // No resources to release.
    }

    @Override
    public String getId() {
        return ID;
    }
}
