
package com.securepam.keycloak;

import java.util.Map;
import java.util.logging.Logger;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;

public class SecurePamOtpEventListenerProvider
        implements EventListenerProvider {

    private static final Logger LOGGER =
            Logger.getLogger(SecurePamOtpEventListenerProvider.class.getName());

    @Override
    public void onEvent(Event event) {
        if (event == null || event.getType() != EventType.LOGIN_ERROR) {
            return;
        }

        if (!"invalid_user_credentials".equals(event.getError())) {
            return;
        }

        Map<String, String> details = event.getDetails();

        if (details == null
                || details.get("selected_credential_id") == null
                || details.get("selected_credential_id").isBlank()) {
            return;
        }

        LOGGER.warning(
            "SECUREPAM_MFA_FAILURE"
            + " eventId=" + safe(event.getId())
            + " time=" + event.getTime()
            + " clientId=" + safe(event.getClientId())
        );
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // This listener does not process administrative events.
    }

    @Override
    public void close() {
        // No resources to release.
    }

    private static String safe(String value) {
        return value == null ? "unknown" : value.replaceAll("[\\r\\n]", "");
    }
}
