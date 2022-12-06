const ISSUERS = {
    'https://ega.ebi.ac.uk:8053/ega-openid-connect-server/': 'EGAtest',
    'https://ega.ebi.ac.uk:8443/ega-openid-connect-server/': 'EGA',
    'https://jwt-elixir-rems-proxy.rahtiapp.fi/': 'REMS',
    'https://permissions-sds.rahtiapp.fi/': 'REMS-SDS',
    'https://sd-apply.csc.fi/': 'REMS-SD',
    'https://login.elixir-czech.org/oidc': 'LS AAI (ELIXIR Legacy)',
    'https://rems-bp-demo.rahtiapp.fi/': 'REMS-BP-demo',
    'https://1mg-rems.sd.csc.fi/': 'REMS-1MG',
    'https://bp-rems.sd.csc.fi/': 'REMS-BP',
    'https://rems.etais.ee/': 'REMS-UT-EE'
};
const SIGNERS = {
    'https://login.elixir-czech.org/perun-ga4gh-broker/jwk': {
        name: 'LS AAI (ELIXIR Legacy)',
        jwks: {
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "kid": "rsa1",
                "n": "uVHPfUHVEzpgOnDNi3e2pVsbK1hsINsTy_1mMT7sxDyP-1eQSjzYsGSUJ3GHq9LhiVndpwV8y7Enjdj0purywtwk_D8z9IIN36RJAh1yhFfbyhLPEZlCDdzxas5Dku9k0GrxQuV6i30Mid8OgRQ2q3pmsks414Afy6xugC6u3inyjLzLPrhR0oRPTGdNMXJbGw4sVTjnh5AzTgX-GrQWBHSjI7rMTcvqbbl7M8OOhE3MQ_gfVLXwmwSIoKHODC0RO-XnVhqd7Qf0teS1JiILKYLl5FS_7Uy2ClVrAYd2T6X9DIr_JlpRkwSD899pq6PR9nhKguipJE0qUXxamdY9nw",
                "alg": "RS256"
            }]
        }
    },
    'https://sd-apply.csc.fi/api/jwk': {
        name: 'REMS-SD',
        jwks: {
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "kid": "fa67eeda",
                "alg": "RS256",
                "n": "7GYzx70RO-X9bqxKV8Fqd0Qw--goVNrSLW7v1pNy6fwwahMnrrXdb_GYdfP45NEgKlIqhzvYvGwWP63W2sdLNocf9GeGvmb2JgLYIG414OCSR9GgwAlxjALnrUCUT70j0U2SNANuZWrgpQAZzmfyo-NVE9ryX90SBdjIYgAb4hwrWnVOiPSkF7ihr0GV712JkBSF72GFx0GTj2qrl_soH9vLGXGkPj5byjoJZ9X8wsswgBDQB8ngJyM2m9NEUWqTyTfX2ZL6kz5ml0T4SHX_VLGcTNMypQjtOOW6Pmo5AmNVYznPKWxV8TKi96wsVHRXbffyAi2KwSvhQfKDhCr6uQ"
            }]
        }
    },
    'https://bp-rems.sd.csc.fi/api/jwk': {
        name: 'REMS-BP',
        jwks: {
            "keys": [{
                "kid": "1621408035",
                "e": "AQAB",
                "kty": "RSA",
                "alg": "RSA-OAEP-256",
                "n": "gzsvvjg96aaYoTwJlwXR8fxJriQ9FUHlJ0He6qiTOriF_ez2ZW0K8kydaxywK_dCnlV-pBAbGuN26Cp881S4fP0YfkVwN8pOd-AQ2XtfGBbgFzastRQhwG32Y0_mLA4vTULd5z1wptZ2rcbNn1plZedR3UbUReazAQe_f6ebkrqS8th0cQ95BG4xgB7g8epQaQ0gqLrGHsRvvjtVeI4y42R2Ptot1PfFZf1uChITJlKT0BcbjE97MznF7D4tE6rTnBnQNa2mU4i-KHhWwDjzk_6JTqUCJCNoWyKiUJLoZwhY9BdHOSGyztAyNjCkU8gC1QGvG8zEqU_-NxM9tG_Hfw"
            }]
        }
    },
    'https://rems-bp-demo.rahtiapp.fi/api/jwk': {
        name: 'REMS-BP-demo',
        jwks: {
            "keys": [{
                "alg": "RSA-OAEP-256",
                "n": "gzsvvjg96aaYoTwJlwXR8fxJriQ9FUHlJ0He6qiTOriF_ez2ZW0K8kydaxywK_dCnlV-pBAbGuN26Cp881S4fP0YfkVwN8pOd-AQ2XtfGBbgFzastRQhwG32Y0_mLA4vTULd5z1wptZ2rcbNn1plZedR3UbUReazAQe_f6ebkrqS8th0cQ95BG4xgB7g8epQaQ0gqLrGHsRvvjtVeI4y42R2Ptot1PfFZf1uChITJlKT0BcbjE97MznF7D4tE6rTnBnQNa2mU4i-KHhWwDjzk_6JTqUCJCNoWyKiUJLoZwhY9BdHOSGyztAyNjCkU8gC1QGvG8zEqU_-NxM9tG_Hfw",
                "kid": "1621408035",
                "e": "AQAB",
                "kty": "RSA"
            }]
        }
    },
    'https://ega.ebi.ac.uk:8053/ega-openid-connect-server/jwk': {
        name: 'EGAtest',
        jwks: {
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "kid": "rsa1",
                "n": "mr1sx838c1_easpPHIiFquOxye6imbA3eid7TD8DDYJRNPsFcZNuhNmu5BC8sfyKhGEdkQxIgxPZVHaD3PW1YJsOIe33ZYJHkVbGOG8rPNmspdgXLzymxT9yK77oLOhK18BRGZsVT689_lFCixyQTqNDCPh9pz6etWJWtWVu4P8"
            }]
        }
    },
    'https://ega.ebi.ac.uk:8443/ega-openid-connect-server/jwk': {
        name: 'EGA',
        jwks: {
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "kid": "rsa1",
                "n": "mr1sx838c1_easpPHIiFquOxye6imbA3eid7TD8DDYJRNPsFcZNuhNmu5BC8sfyKhGEdkQxIgxPZVHaD3PW1YJsOIe33ZYJHkVbGOG8rPNmspdgXLzymxT9yK77oLOhK18BRGZsVT689_lFCixyQTqNDCPh9pz6etWJWtWVu4P8"
            }]
        }
    },
    'https://jwt-elixir-rems-proxy.rahtiapp.fi/jwks.json': {
        name: 'REMS',
        jwks: {
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "kid": "7b795308",
                "n": "pYlDjYIje--qQsDabBmbEkrAur-UEiAZf8f42esrQeA-R99SNQacJKchbOTYO2ySLPFpvwqNLGaBx8su7LoXS72DL-ALs85i2K45xjS4dJ-jxNag3P0SGUYZOdYuzTX5gkPI0JRZBzeE6Yo2uK-APdTeCvE9cGqtuf0XVI12lk3052rQpoN0NuLndCECNZxFDzZYugqAvkNCWlVQ15trcPAoMKX6e06npz-EbysMt2L4ErZx4wUiLHK_U1D_-lHwR3UfLKbw6BwchOu9AuFhT-kqVXvJe69r1E4rZrNgs-gsjCdP325j3m07mcgWrvkWn9Fbvuj3iyu_RY6Dbotmrw",
                "alg": "RS256"
            }]
        }
    },
    'https://permissions-sds.rahtiapp.fi/jwks.json': {
        name: 'REMS-SDS',
        jwks: {
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "kid": "fa67eeda",
                "n": "7GYzx70RO-X9bqxKV8Fqd0Qw--goVNrSLW7v1pNy6fwwahMnrrXdb_GYdfP45NEgKlIqhzvYvGwWP63W2sdLNocf9GeGvmb2JgLYIG414OCSR9GgwAlxjALnrUCUT70j0U2SNANuZWrgpQAZzmfyo-NVE9ryX90SBdjIYgAb4hwrWnVOiPSkF7ihr0GV712JkBSF72GFx0GTj2qrl_soH9vLGXGkPj5byjoJZ9X8wsswgBDQB8ngJyM2m9NEUWqTyTfX2ZL6kz5ml0T4SHX_VLGcTNMypQjtOOW6Pmo5AmNVYznPKWxV8TKi96wsVHRXbffyAi2KwSvhQfKDhCr6uQ",
                "alg": "RS256"
            }]
        }
    },
    'https://login.elixir-czech.org/oidc/jwk': {
        name: 'ELIXIR',
        jwks: {
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "kid": "rsa1",
                "n": "uVHPfUHVEzpgOnDNi3e2pVsbK1hsINsTy_1mMT7sxDyP-1eQSjzYsGSUJ3GHq9LhiVndpwV8y7Enjdj0purywtwk_D8z9IIN36RJAh1yhFfbyhLPEZlCDdzxas5Dku9k0GrxQuV6i30Mid8OgRQ2q3pmsks414Afy6xugC6u3inyjLzLPrhR0oRPTGdNMXJbGw4sVTjnh5AzTgX-GrQWBHSjI7rMTcvqbbl7M8OOhE3MQ_gfVLXwmwSIoKHODC0RO-XnVhqd7Qf0teS1JiILKYLl5FS_7Uy2ClVrAYd2T6X9DIr_JlpRkwSD899pq6PR9nhKguipJE0qUXxamdY9nw",
                "alg": "RS256"
            }]
        }
    },
    'https://1mg-rems.sd.csc.fi/api/jwk': {
        name: 'REMS-1MG',
        jwks: {
            "keys": [{
                "alg": "RSA-OAEP-256",
                "use": "enc",
                "n": "kr_ZFRptOxLJOy8NwdeEuFz24zww8Kd0qrXeoMI8WRrXq2loo0NY1c5xpvSTIKhcxJTqFqBT0pbzlDW6oDD1_jukwgrvJL3nJjpcybl7Glvw-8LUf_TluAEF5CktFWi7p3fJH67rh4wpf89WmZevGuwU6cIvA69KRpawm1F_3YSvK7QbXkHjTVVAfydxygSrVL2pOiKAL2QnOLdJVolztMNwuMjH0VUcZT0Q2JwlqfqUxraP4dseuTW506myXIm00svbwjyVmfEDrw82qRt_1T4_bFJR6_-Of1xV9h6teNgRh42lNUuopE9OQnNULcRIfyH0M3vwuiRHzWTM90bJDQ",
                "kid": "enc-1625036853",
                "e": "AQAB",
                "kty": "RSA"
            }]
        },
    },
    'https://rems.etais.ee/api/jwk': {
        name: 'REMS-UT-EE',
        jwks: {
            "keys": [{
                "use": "sig",
                "n": "jnVEJJXGNWhQgPV8sRiaXovNqijI-JttThtWhekEJ_FhRvxB0XzAzmc0OU_63HUDB-uT_9iZQqiFnHWcOwqKdzs4dcgqD7y3XPCzQSY7Zdrb2u4cZluh5yTMSGY8Dp5fY48FQTvb5_5rmCDIy2EAzlL0T-wxCYw2N4Eq-jAAp2sHSZYcGypHn9oIY3UlsgkE3Uoq7JXxKi6FS_OHOO-6a9C2pVIvM9nqQBBOX9buHHMGJ8rWDKInkrMPzO-2E0RwtHqtsoTdCiNwda5OgdEq9octuzAx9MVh9YHMBvPFXDQ1KIxN6VnHCbb0PaTyKNeyM4F-DOf2XmcuzUhYZTzpnw",
                "kid": "sig-2022-09-08T12:28:51Z",
                "e": "AQAB",
                "kty": "RSA"
            }]
        },
    },
};
const POLICIES = {
    'https://doi.org/10.1038/s41431-018-0219-y': 'The attestations for registered access (<a href="https://elixir-europe.org/services/compute/aai/bonafide">link</a>)'
};
const STATUSES = {
    'https://doi.org/10.1038/s41431-018-0219-y': 'Bona Fide researcher for registered access (<a href="https://elixir-europe.org/services/compute/aai/bonafide">link</a>)'
}
const timeFormat = new Intl.DateTimeFormat('en-GB', {'dateStyle': 'full', 'timeStyle': 'full'});

mgr = new Oidc.UserManager(config);
expert = new URLSearchParams(window.location.search).has('expert');
mgr.getUser().then(function (user) {
    if (user) {
        console.log(user);

        document.getElementById("div_login").style.display = "block";
        document.getElementById("div_no_login").style.display = "none";
        if (expert) {
            document.getElementById("basic_view").style.display = "none";
            document.getElementById("expert_view").style.display = "block";
        } else {
            document.getElementById("basic_view").style.display = "block";
            document.getElementById("expert_view").style.display = "none";
        }

        document.getElementById("sub").innerHTML = user.profile.sub;
        document.getElementById("name").innerHTML = user.profile.name;
        document.getElementById("given_name").innerHTML = user.profile.given_name;
        document.getElementById("family_name").innerHTML = user.profile.family_name;
        document.getElementById("preferred_username").innerHTML = user.profile.preferred_username;
        document.getElementById("email").innerHTML = user.profile.email;
        document.getElementById("locale").innerHTML = user.profile.locale;
        document.getElementById("zoneinfo").innerHTML = user.profile.zoneinfo;

        document.getElementById("basic_id").innerHTML = user.profile.sub;

        // GA4GH passport

        // basic
        const linked_ids = new Map();
        const affiliations = new Set();
        const policies = new Set();
        const statuses = new Set();
        const accesses = new Map();
        let tablecounter = 0;

        // process all visas
        for (const jwt of user.profile.ga4gh_passport_v1) {
            // process visa for expert view
            const jwt_parts = jwt.split('.');
            const header = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(jwt_parts[0]));
            const visa = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(jwt_parts[1]));
            // process visa for expert view
            const visaInfo = {
                header: header,
                visa: visa,
                jwt: jwt
            };
            console.log('processing visa ... ');
            console.log(visaInfo);

            const now = new Date();
            const iat = new Date(visa.iat * 1000);
            const exp = new Date(visa.exp * 1000);
            const asserted = new Date(visa.ga4gh_visa_v1.asserted * 1000);

            // verify signature (at the time of issuance, otherwise expired tokens would be marked as invalid signatures)
            const signer_key = KEYUTIL.getKey(SIGNERS[visaInfo.header.jku].jwks.keys.filter(key => key.kid === visaInfo.header.kid)[0]);
            const verified = KJUR.jws.JWS.verifyJWT(jwt, signer_key, {alg: ['RS256'], verifyAt: visaInfo.visa.iat});

            document.getElementById(visaInfo.visa.ga4gh_visa_v1.type).innerHTML +=
                '<table class="ga4gh_expert" id="tab' + tablecounter + '">' +
                '<tr><th>value</th><td>' + visa.ga4gh_visa_v1.value + '</td></tr>' +
                '<tr><th>source</th><td>' + visa.ga4gh_visa_v1.source + '</td></tr>' +
                '<tr><th>by</th><td>' + visa.ga4gh_visa_v1.by + '</td></tr>' +
                '<tr><th>conditions</th><td>' + (visa.ga4gh_visa_v1.conditions ? visa.ga4gh_visa_v1.conditions : '') + '</td></tr>' +
                '<tr><th>issuer (iss)</th><td>' + visa.iss + ' (' + ISSUERS[visa.iss] + ')</td></tr>' +
                '<tr><th>subject (sub)</th><td>' + visa.sub + '</td></tr>' +
                '<tr><th>asserted at</th><td>' + visa.ga4gh_visa_v1.asserted + ' (' + timeFormat.format(asserted) + ')</td></tr>' +
                '<tr><th>issued at (iat)</th><td ' + (iat > now ? 'class="warning"' : '') + '>' + visa.iat + ' (' + timeFormat.format(iat) + ')' + (iat > now ? ' issued in the future ' : '') + '</td></tr>' +
                '<tr><th>expires at (exp)</th><td ' + (exp < now ? 'class="warning"' : '') + '>' + visa.exp + ' (' + timeFormat.format(exp) + ')' + (exp < now ? ' visa expired ' : '') + '</td></tr>' +
                '<tr><th>JWT id (jti)</th><td>' + visa.jti + '</td></tr>' +
                '<tr><th>signature</th><td ' + (!verified ? 'class="warning"' : '') + '>jku: ' + visaInfo.header.jku + ' kid: ' + visaInfo.header.kid
                + ' (' + SIGNERS[visaInfo.header.jku].name + ') ' + (!verified ? 'invalid signature' : '<span class="ok">verified</span>') + '</td></tr>' +
                '<tr><td colspan="2" class="rawjwt">' +
                '<button id="but' + tablecounter + '">Display raw decoded JWT</button>' +
                '<pre id="pre' + tablecounter + '">' + JSON.stringify(visaInfo.header, null, 2) + '<br>.<br>' + JSON.stringify(visaInfo.visa, null, 2) + '</pre>' +
                '</td></tr>' +
                '</table>'
            ;
            tablecounter++;

            // process visa for basic view
            switch (visa.ga4gh_visa_v1.type) {
                case 'LinkedIdentities':
                    if (visa.sub === user.profile.sub && visa.iss === config.authority) {
                        // issued by elixir aai
                        for (const lid of visa.ga4gh_visa_v1.value.split(';').map(pair => pair.split(','))) {
                            let linkedId = {};
                            linkedId.sub = decodeURIComponent(lid[0]); // linked sub
                            linkedId.iss = decodeURIComponent(lid[1]); // linked iss - issued the JWT
                            linkedId.source = visa.ga4gh_visa_v1.source; // linked source - collected the info
                            linkedId.key = linkedId.sub + linkedId.iss;
                            linked_ids.set(linkedId.key, linkedId);
                        }
                    } else {
                        let linkedId = {};
                        linkedId.sub = visa.sub;
                        linkedId.iss = visa.iss;
                        linkedId.source = visa.ga4gh_visa_v1.source;
                        linkedId.key = linkedId.sub + linkedId.iss;
                        for (const lid of visa.ga4gh_visa_v1.value.split(';').map(pair => pair.split(','))) {
                            let lidsub = decodeURIComponent(lid[0]);
                            let lidiss = decodeURIComponent(lid[1]);
                            if (lidsub === user.profile.sub && lidiss === config.authority) {
                                linked_ids.set(linkedId.key, linkedId);
                            }
                        }
                    }
                    break;

                case 'AffiliationAndRole':
                    affiliations.add(visa.ga4gh_visa_v1.value);
                    break;

                case 'AcceptedTermsAndPolicies':
                    policies.add(visa.ga4gh_visa_v1.value);
                    break;

                case 'ResearcherStatus':
                    statuses.add(visa.ga4gh_visa_v1.value);
                    break;

                case 'ControlledAccessGrants':
                    let access = {};
                    access.dataset = visa.ga4gh_visa_v1.value;
                    access.iss = visa.iss;
                    access.key = access.dataset + access.iss;
                    accesses.set(access.key, access);
                    break;
            }
        }

        // event for displaying raw JWTs
        for (let i = 0; i < tablecounter; i++) {
            document.getElementById("but" + i).addEventListener('click', () => {
                document.getElementById("but" + i).style.display = "none";
                document.getElementById("pre" + i).style.display = "block";
            });
        }
        console.log(tablecounter);

        // basic view linked identities
        for (let linkedId of linked_ids.values()) {
            document.getElementById("basic_linked_ids").innerHTML +=
                "in " + ISSUERS[linkedId.iss] + ': ' + linkedId.sub + '<br>';
        }
        // affiliations
        for (let aff of affiliations.values()) {
            document.getElementById("basic_affiliations").innerHTML += aff + '<br>';
        }
        // policies
        for (let policy of policies.values()) {
            document.getElementById("basic_policies").innerHTML += POLICIES[policy] + '<br>';
        }
        // statuses
        for (let status of statuses.values()) {
            document.getElementById("basic_statuses").innerHTML += STATUSES[status] + '<br>';
        }
        // accesses
        for (let access of accesses.values()) {
            document.getElementById("basic_accesses").innerHTML +=
                ISSUERS[access.iss] + ': ' + access.dataset + '<br>';
        }

        // access token
        let jwtac = user.access_token.split('.');
        let access_token_load = JSON.parse(atob(jwtac[1]));
        rawlog('raw_access_token', access_token_load);
        document.getElementById("access_token_iat").innerHTML = timeFormat.format(new Date(access_token_load.iat * 1000));
        document.getElementById("access_token_exp").innerHTML = timeFormat.format(new Date(access_token_load.exp * 1000));

        // id token
        let jwtid = user.id_token.split('.');
        let id_token_load = JSON.parse(atob(jwtid[1]));
        rawlog('raw_id_token', id_token_load);
        document.getElementById("id_token_auth_time").innerHTML = timeFormat.format(new Date(id_token_load.auth_time * 1000));
        document.getElementById("id_token_iat").innerHTML = timeFormat.format(new Date(id_token_load.iat * 1000));
        document.getElementById("id_token_exp").innerHTML = timeFormat.format(new Date(id_token_load.exp * 1000));

        // user info
        rawlog('raw_userinfo', user.profile);

        // v1.2 token exchange - Passport token
        callTokenExchange(user.access_token);

    } else {
        document.getElementById("div_login").style.display = "none";
        document.getElementById("div_no_login").style.display = "block";
    }
});

//autologin
if (new URLSearchParams(window.location.search).has('autologin')) {
    mgr.signinRedirect();
}

function login() {
    mgr.signinRedirect();
}

function relogin() {
    mgr.signinRedirect();
}

function logout() {
    mgr.signoutRedirect();
}

function expert_button() {
    expert = true;
    location.assign(window.location.pathname + "?expert");
}

function callTokenExchange(access_token) {
    const params = new URLSearchParams({
        requested_token_type: "urn:ga4gh:params:oauth:token-type:passport",
        subject_token: access_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange"
    });
    const query = params.toString();
    const xhr = new XMLHttpRequest();
    xhr.onload = function () {
        console.log('Token exchange response: ' + xhr.status);
        console.log(xhr.responseText);
        if (xhr.status === 200) {
            const jsonResponse = JSON.parse(xhr.responseText);
            const jwtPt = jsonResponse.access_token;
            document.getElementById("PassportToken").innerHTML +=
                '<p>Header</p>' +
                '<pre class="rawjwt">' + JSON.stringify(JSON.parse(atob(jwtPt.split('.')[0])), undefined, 2) + '</pre>' +
                '<p>Payload</p>' +
                '<pre class="rawjwt">' + JSON.stringify(JSON.parse(atob(jwtPt.split('.')[1])), undefined, 2) + '</pre>' +
                '<p>Token type</p>' +
                '<pre class="rawjwt">' + jsonResponse.token_type + '</pre>' +
                '<p>Issued Token Type</p>' +
                '<pre class="rawjwt">' + jsonResponse.issued_token_type + '</pre>' +
                '<p>Expires In</p>' +
                '<pre class="rawjwt">' + jsonResponse.expires_in + 'sec</pre>' +
                '<p>Refresh token</p>' +
                '<pre class="rawjwt">' + (jsonResponse.refresh_token === "" ? "-" : jsonResponse.refresh_token) + '</pre>' +
                '<p>Raw response:</p>';
            rawlog("raw_passport_token", jsonResponse);
        } else {
            document.getElementById("PassportToken").innerHTML = '<pre class="rawjwt">' + xhr.responseText + '</pre>';
        }
    }
    xhr.open("POST", config.authority + "token?" + query);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.setRequestHeader("Authorization", "Basic " + btoa(config.client_id + ":"));
    xhr.send();
}

document.getElementById("login").addEventListener("click", login, false);
document.getElementById("relogin").addEventListener("click", relogin, false);
document.getElementById("logout").addEventListener("click", logout, false);
document.getElementById("expert_button").addEventListener("click", expert_button, false);


function rawlog(area, msg) {
    document.getElementById(area).innerText = '';
    if (typeof msg !== 'string') {
        msg = JSON.stringify(msg, null, 2);
    }
    document.getElementById(area).innerHTML += msg + '\r\n';
}
