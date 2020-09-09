function rawlog(area,msg) {
    document.getElementById(area).innerText = '';
    if(typeof msg !== 'string') {
        msg = JSON.stringify(msg, null, 2);
    }
    document.getElementById(area).innerHTML += msg + '\r\n';
}

function log() {
    document.getElementById(results).innerText = '';

    Array.prototype.forEach.call(arguments, function (msg) {
        if (msg instanceof Error) {
            msg = "Error: " + msg.message;
        }
        else if (typeof msg !== 'string') {
            msg = JSON.stringify(msg, null, 2);
        }
        document.getElementById('results').innerHTML += msg + '\r\n';
    });
}

document.getElementById("login").addEventListener("click", login, false);

var mgr = new Oidc.UserManager(config);

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

        // GA4GH passport
        const ga4gh_jwts = user.profile.ga4gh_passport_v1;
        const ga4gh_tokens = ga4gh_jwts.map( j => { let jwt = j.split('.'); return JSON.parse(atob(jwt[1])); } );
        rawlog('raw_passport',ga4gh_tokens);
        const ga4gh_table = document.getElementById("ga4gh_table");
        for(const visa of ga4gh_tokens) {
          let row = ga4gh_table.insertRow(-1); 
          row.insertCell(0).innerHTML = '<b>'+visa.ga4gh_visa_v1.type+'</b>';
          if(visa.ga4gh_visa_v1.type == 'LinkedIdentities') {
            let s = '<span class="small">{ '+visa.sub+', <br> '+visa.iss+' }';
            for(li of visa.ga4gh_visa_v1.value.split(';').map(pair => pair.split(','))) {
              s += '<br> = <br> { '+decodeURIComponent(li[0])+',<br> '+decodeURIComponent(li[1])+' }' ;
            }
            s += '</span>'
            row.insertCell(1).innerHTML = s;
          } else if(visa.ga4gh_visa_v1.value.length > 70 ) {
            row.insertCell(1).innerHTML = '<span class="tiny">'+visa.ga4gh_visa_v1.value+'</span>';
          } else if(visa.ga4gh_visa_v1.value.length > 30 ) {
            row.insertCell(1).innerHTML = '<span class="small">'+visa.ga4gh_visa_v1.value+'</span>';
          } else {
            row.insertCell(1).innerHTML = visa.ga4gh_visa_v1.value;
          }
          row.insertCell(2).innerHTML = visa.ga4gh_visa_v1.by;
          row.insertCell(3).innerHTML = '<span class="small"><a href="' + visa.ga4gh_visa_v1.source + '">' + visa.ga4gh_visa_v1.source + '</a><br>'+visa.iss+'</span>';
          row.insertCell(4).innerHTML = new Date(visa.ga4gh_visa_v1.asserted*1000).toISOString().substring(0, 10);
          row.insertCell(5).innerHTML = new Date(visa.exp*1000).toISOString().substring(0, 10);
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
