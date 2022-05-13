<script lang="ts">
  import { getContext } from "svelte";
  import { OIDC_CONTEXT_CLIENT_PROMISE, login } from "./Keycloak.svelte";
  import type { OidcContextClientPromise } from "../types";

  const oidcPromise: OidcContextClientPromise = getContext(
    OIDC_CONTEXT_CLIENT_PROMISE
  );
  let _class: string = "btn btn-primary";
  export { _class as class };
</script>

<button class={_class} on:click|preventDefault={() => login(oidcPromise)}>
  <slot />
</button>
