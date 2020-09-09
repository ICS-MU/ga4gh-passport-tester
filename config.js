var config = {
    authority: 'https://login.elixir-czech.org/oidc/',
    client_id: '7ceef937-6740-4774-aec3-40fb75b23e30',
    scope: 'openid profile email ga4gh_passport_v1',
    redirect_uri: 'https://echo.aai.elixir-czech.org/callback.html',
    response_type: 'code',
    post_logout_redirect_uri : "https://echo.aai.elixir-czech.org/logout.html",
    filterProtocolClaims: true,
    loadUserInfo: true
};
