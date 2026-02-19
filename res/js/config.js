const config = {
    oidc: {
        authority: 'https://login.aai.lifescience-ri.eu/oidc/',
        client_id: '5142879a-3332-41de-a33e-a6b43220902c',
        response_type: 'code', //Authorization Code grant flow with Proof Key for Code Exchange (PKCE)
        scope: 'openid profile email ga4gh_passport_v1',
        redirect_uri: 'https://ga4gh-echo.aai.lifescience-ri.eu/callback.html',
        post_logout_redirect_uri: "https://ga4gh-echo.aai.lifescience-ri.eu/logout.html",
        filterProtocolClaims: true,
        loadUserInfo: true,
        response_mode: 'query'
    },
    supportTokenExchange: true
};


