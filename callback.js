new Oidc.UserManager(config).signinRedirectCallback().then(function () {
    window.location = "index.html";
}).catch(function (e) {
    document.getElementById('error_explanation').innerText
        = 'Problem occured when authenticating to OpenID Connect server:';
    document.getElementById('error_place').innerText = e;
});
