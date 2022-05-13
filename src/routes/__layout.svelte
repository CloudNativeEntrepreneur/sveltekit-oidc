<script lang="ts">
  import "../app.postcss";
  import { Keycloak } from "$lib";
  import { config } from "../config";
  import Header from "../components/shared/Header/index.svelte";
</script>

<Header />
<Keycloak
  issuer={config.oidc.issuer}
  client_id={config.oidc.clientId}
  scope={config.oidc.scope}
  redirect_uri={config.oidc.redirectUri}
  post_logout_redirect_uri={config.oidc.postLogoutRedirectUri}
  refresh_token_endpoint={config.oidc.refreshTokenEndpoint}
  refresh_page_on_session_timeout={config.oidc.refreshPageOnSessionTimeout}
>
  <slot />
</Keycloak>
