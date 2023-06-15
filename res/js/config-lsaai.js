const config = {
    oidc: {
        authority: 'https://proxy.aai.lifescience-ri.eu',
        client_id: 'APP-77D5767F-2634-4203-BA79-1D33A36FA0D7',
        response_type: 'code', //Authorization Code grant flow with Proof Key for Code Exchange (PKCE)
        scope: 'openid profile email ga4gh_passport_v1',
        redirect_uri: 'https://ga4gh-echo.aai.lifescience-ri.eu/',
        post_logout_redirect_uri: "https://ga4gh-echo.aai.lifescience-ri.eu/logout.html",
        filterProtocolClaims: true,
        loadUserInfo: true
    },
    supportTokenExchange: false
};


