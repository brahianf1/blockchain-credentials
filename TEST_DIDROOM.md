# Test Manual para DIDRoom

Después de que DIDRoom obtenga el `request_uri`, intenta manualmente en el navegador:

```
https://api-credenciales.utnpf.site/oid4vc/authorize?client_id=did:dyne:sandbox.signroom:6nXcN63U4qGMFVFT3w7RMfg74gfnandtMCEAtgHd5U8C&request_uri=URN_QUE_RECIBISTE&redirect_uri=https://wallet.didroom.com/finalize-authentication
```

Reemplaza `URN_QUE_RECIBISTE` con el `request_uri` que aparece en los logs (ejemplo: `urn:ietf:params:oauth:request_uri:Q-Vm22lEm2zgOfese5zPQofcFOYWE26KMQvV07zgSyM`)

Esto debería:
1. Llamar a /authorize
2. Generar authorization_code
3. Redirigir a wallet.didroom.com con el code

Si eso funciona, entonces el problema es que DIDRoom no está haciendo esa redirección automáticamente.
