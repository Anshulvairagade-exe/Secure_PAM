
import Keycloak from 'keycloak-js';

const keycloak = new Keycloak({
  url: 'http://localhost:8080',
  realm: 'securepam',
  clientId: 'securepam-app',
});

export default keycloak;
