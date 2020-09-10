

const ISSUERS = {
    'https://ega.ebi.ac.uk:8053/ega-openid-connect-server/': 'EGA',
    'https://jwt-elixir-rems-proxy.rahtiapp.fi/':'REMS',
    'https://permissions-sds.rahtiapp.fi/':'REMS-SDS',
    'https://login.elixir-czech.org/oidc/': 'ELIXIR'
};
const SIGNERS = {
    'https://ega.ebi.ac.uk:8053/ega-openid-connect-server/jwk': 'EGA',
    'https://jwt-elixir-rems-proxy.rahtiapp.fi/jwks.json' : 'REMS',
    'https://permissions-sds.rahtiapp.fi/jwks.json': 'REMS-SDS',
    'https://login.elixir-czech.org/oidc/jwk': 'ELIXIR',
};
const POLICIES = {
    'https://doi.org/10.1038/s41431-018-0219-y': 'The attestations for registered access (<a href="https://elixir-europe.org/services/compute/aai/bonafide">link</a>)'
};
const STATUSES = {
    'https://doi.org/10.1038/s41431-018-0219-y': 'Bona Fide researcher or registered access (<a href="https://elixir-europe.org/services/compute/aai/bonafide">link</a>)'
}

mgr = new Oidc.UserManager(config);

mgr.getUser().then(function (user) {
    if (user) {
        console.log(user);
        // user
        document.getElementById("div_login").style.display = "block";
        document.getElementById("div_no_login").style.display = "none";
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
        let tablecounter = -1;

        // process all visas
        for(const jwt of user.profile.ga4gh_passport_v1) {
            // process visa for expert view
            const jwt_parts = jwt.split('.');
            const header = JSON.parse(atob(jwt_parts[0]));
            const visa = JSON.parse(atob(jwt_parts[1]));
            // process visa for expert view
            const visaInfo = {
                header: header,
                visa: visa,
                jwt: jwt
            };
            const timeFormat = new Intl.DateTimeFormat('en-GB', { 'dateStyle': 'full', 'timeStyle': 'full'});
            tablecounter++;
            document.getElementById(visaInfo.visa.ga4gh_visa_v1.type).innerHTML +=
                '<table class="ga4gh_expert" id="tab'+tablecounter+'">' +
                '<tr><th>value</th><td>' + visa.ga4gh_visa_v1.value + '</td></tr>' +
                '<tr><th>source</th><td>' + visa.ga4gh_visa_v1.source + '</td></tr>' +
                '<tr><th>by</th><td>' + visa.ga4gh_visa_v1.by + '</td></tr>' +
                '<tr><th>conditions</th><td>' + (visa.ga4gh_visa_v1.conditions ? visa.ga4gh_visa_v1.conditions : '') + '</td></tr>' +
                '<tr><th>issuer (iss)</th><td>' + visa.iss + ' (' + ISSUERS[visa.iss] + ')</td></tr>' +
                '<tr><th>subject (sub)</th><td>' + visa.sub + '</td></tr>' +
                '<tr><th>asserted at</th><td>' + visa.ga4gh_visa_v1.asserted + ' (' + timeFormat.format(new Date(visa.ga4gh_visa_v1.asserted * 1000)) + ')</td></tr>' +
                '<tr><th>issued at (iat)</th><td>' + visa.iat + ' (' + timeFormat.format(new Date(visa.iat * 1000)) + ')</td></tr>' +
                '<tr><th>expires at (exp)</th><td>' + visa.exp + ' (' + timeFormat.format(new Date(visa.exp * 1000)) + ')</td></tr>' +
                '<tr><th>JWT id (jti)</th><td>' + visa.jti + '</td></tr>' +
                '<tr><th>signature</th><td>jku: ' + visaInfo.header.jku + ' kid: ' + visaInfo.header.kid + ' (' + SIGNERS[visaInfo.header.jku] + ')</td></tr>' +
                '<tr><td colspan="2" class="rawjwt">'+
                '<button id="but'+tablecounter+'">Display raw decoded JWT</button>' +
                '<pre id="pre'+tablecounter+'">'+ JSON.stringify(visaInfo.header, null, 2) +'<br>.<br>' +  JSON.stringify(visaInfo.visa, null, 2) + '</pre>' +
                '</td></tr>' +
                '</table>'
            ;


            // process visa for basic view
            switch (visa.ga4gh_visa_v1.type) {
                case 'LinkedIdentities':
                    if (visa.sub === user.profile.sub && visa.iss === config.authority ) {
                        // issued by elixir aai
                        for(const lid of visa.ga4gh_visa_v1.value.split(';').map(pair => pair.split(','))) {
                            let linkedId = {};
                            linkedId.sub = decodeURIComponent(lid[0]); // linked sub
                            linkedId.iss = decodeURIComponent(lid[1]); // linked iss - issued the JWT
                            linkedId.source = visa.ga4gh_visa_v1.source; // linked source - collected the info
                            linkedId.key = linkedId.sub + linkedId.iss;
                            linked_ids.set(linkedId.key,linkedId);
                        }
                    } else {
                        let linkedId = {};
                        linkedId.sub = visa.sub;
                        linkedId.iss = visa.iss;
                        linkedId.source = visa.ga4gh_visa_v1.source;
                        linkedId.key = linkedId.sub + linkedId.iss;
                        for(const lid of visa.ga4gh_visa_v1.value.split(';').map(pair => pair.split(','))) {
                            let lidsub = decodeURIComponent(lid[0]);
                            let lidiss = decodeURIComponent(lid[1]);
                            if ( lidsub === user.profile.sub && lidiss === config.authority ) {
                                linked_ids.set(linkedId.key,linkedId);
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
                document.getElementById("but"+i).style.display = "none";
                document.getElementById("pre"+i).style.display = "block";
            });
        }

        // basic view linked identities
        for(let linkedId of linked_ids.values()) {
            document.getElementById("basic_linked_ids").innerHTML +=
                ISSUERS[linkedId.iss] + ': ' + linkedId.sub +'<br>';
        }
        // affiliations
        for(let aff of affiliations.values()) {
            document.getElementById("basic_affiliations").innerHTML += aff + '<br>';
        }
        // policies
        for(let policy of policies.values()) {
            document.getElementById("basic_policies").innerHTML += POLICIES[policy] + '<br>';
        }
        // statuses
        for(let status of statuses.values()) {
            document.getElementById("basic_statuses").innerHTML += STATUSES[status] + '<br>';
        }
        // accesses
        for(let access of accesses.values()) {
            document.getElementById("basic_accesses").innerHTML +=
                ISSUERS[access.iss] + ': ' + access.dataset +'<br>';
        }

        // access token
        let jwtac = user.access_token.split('.');
        let access_token_load = JSON.parse(atob(jwtac[1]));
        rawlog('raw_access_token',access_token_load);
        document.getElementById("access_token_iat").innerHTML = new Date(access_token_load.iat*1000).toISOString();
        document.getElementById("access_token_exp").innerHTML = new Date(access_token_load.exp*1000).toISOString();

        // id token
        let jwtid = user.id_token.split('.');
        let id_token_load = JSON.parse(atob(jwtid[1])); 
        rawlog('raw_id_token',id_token_load);
        document.getElementById("id_token_auth_time").innerHTML = new Date(id_token_load.auth_time*1000).toISOString();
        document.getElementById("id_token_iat").innerHTML = new Date(id_token_load.iat*1000).toISOString();
        document.getElementById("id_token_exp").innerHTML = new Date(id_token_load.exp*1000).toISOString();

        // user info
        rawlog('raw_userinfo',user.profile);

    }
    else {
        document.getElementById("div_login").style.display = "none";
        document.getElementById("div_no_login").style.display = "block";
    }
});

function login() {
    mgr.signinRedirect();
}

function logout() {
    mgr.signoutRedirect();
}

document.getElementById("login").addEventListener("click", login, false);
document.getElementById("logout").addEventListener("click", logout, false);


function rawlog(area, msg) {
    document.getElementById(area).innerText = '';
    if (typeof msg !== 'string') {
        msg = JSON.stringify(msg, null, 2);
    }
    document.getElementById(area).innerHTML += msg + '\r\n';
}



