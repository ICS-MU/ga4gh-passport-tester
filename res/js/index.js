const ISSUERS = {
    'https://ega.ebi.ac.uk:8053/ega-openid-connect-server/': 'EGAtest',
    'https://ega.ebi.ac.uk:8443/ega-openid-connect-server/': 'EGA',
    'https://jwt-elixir-rems-proxy.rahtiapp.fi/': 'REMS',
    'https://permissions-sds.rahtiapp.fi/': 'REMS-SDS',
    'https://sd-apply.csc.fi/': 'REMS-SD',
    'https://login.aai.lifescience-ri.eu/oidc/': 'LS Login',
    'https://login.aai.lifescience-ri.eu/oidc': 'LS Login',
    'https://rems-bp-demo.rahtiapp.fi/': 'REMS-BP-demo',
    'https://1mg-rems.sd.csc.fi/': 'REMS-1MG',
    'https://bp-rems.sd.csc.fi/': 'REMS-BP',
    'https://rems.etais.ee/': 'REMS-UT-EE',
    'https://rems.gdi.nbis.se/': 'REMS-GDI-NBIS',
    'https://gdi-demo.sd.csc.fi/': 'REMS-GDI-CSC-DEMO',
    'https://rems.dev.gdi.lu/': 'REMS-GDI-LU-DEV',
    'https://rems.gdi.biodata.pt/': 'REMS-GDI-BIODATA-PT',
    'https://gdi.cloud.ut.ee/': 'REMS-GDI-EE',
    'https://gdi.vib.be/': 'REMS-GDI-BE',
    'https://rems.gdifr.lindan.se/': 'REMS-GDI-FR',
    'https://daam.portal.dev.gdi.lu/': 'GDI Portal',
    'https://rems.gdi.elixir-greece.org/': 'REMS-GDI-GR',
    'https://rems.ejprd.nbis.se/': 'REMS-EJPRD-NBIS',
    'https://id.portal.dev.gdi.lu/realms/gdi': 'GDI-USER-PORTAL',
};
const SIGNERS = {
    'https://rems.gdi.elixir-greece.org/api/jwk': {
        name: 'REMS-GDI-GR',
        jwks: {
            "keys": [{
                "n": "oCPS8qs2CWsPB2c_DudN0KwHVW28laEgsoaXk8mtucMKBeTWU0HxzrCHhrHeaaKp8IC7fF-cBp4fGrr2QV6bkofrDwrjcBERcRF4bTmybjb3v_9jahdQ6cbVaoEMkXiiuOk9lMg1tp4inE6ckqBzbCjZNyYY2LF1gbyRtMJgRQNyxvFCKqcmuo50mu_k0we7WLnnyALmOD4IAfRZnFgnbhMImDs4KFE5If366ghl_BCCWdfYMg-002n5_v9l_G7Z16HCJdD4VNtWY_Pz1o-CEEuGjr-afkaU4Ay42Iie0YItOY0nFvLlgppByUeE5GQj-S-EYhn59AALgTpK7SkeOQ",
                "kid": "gdi-demo",
                "e": "AQAB",
                "kty": "RSA"
            }]
        }
    },
    'https://daam.portal.dev.gdi.lu/api/jwk': {
        name: 'GDI Portal',
        jwks: {
            "keys": [{
                "n": "pOL2dpGI9dWLk-2AS-J9CyfvkQppVUkEQW70HrV2YHfoWCBfrnX_yeXTyXWEAcEmS9ToIo0OUJhovur1Fkeg_1Kk7CwDJNsjDDq-KLXoU_5faICe5hd5gs0Vk_WHMQYaJOOoymKWuBY0GEvhABlAa3Y9sNC535CTNgA-W7sIeiKLCVVooUqS4x8Rrk7FqbxL9H5ZxJOtjp7bn-uIESsXkDdORVBxkaMBH0EccpSJE-K2Qvfg6OvkbrEIf3owbjpXKN_OWc4BvQRL0lpfz2DGE6qi91P_qhbkS9yaN18XQTxYAKRxKVnBom75H_DIYaxK2JecqsoswQ690qFiqVw6Pw",
                "kid": "gdi-demo",
                "e": "AQAB",
                "kty": "RSA"
            }]
        }
    },
    'https://login.aai.lifescience-ri.eu/perun-ga4gh-broker/jwk': {
        name: 'LS Login',
        jwks: {
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "use": "sig",
                "kid": "rsa1",
                "alg": "RS256",
                "n": "zl6laZMB_VXBAUelEO2NSbDnJgsxzuQARYsxMuF38Z_0lf7WkTPDilJme7QEr90R-Q2lrWl8tMosJe4J4N1VL9hwtg1SgnAMlhnUH0ppqpq_M983HzdpzoaNh27E5m8bHzx9RX7_fqnNspCfUQEeEubWEcXGK8ow8zzDEcW16-OZQT24tDNjDHAO9ksAkcs7bg8C4Wz1WBw6KqOMWY2gPzVVUAqK_XWhCktQwHB19XB1xH8ujH7PSKR4eHUgGR2mLgBGFGOZgD-9SnLf7NiF7e2gC41ZfkVBls5UX32DxQzL6Zu0RauD2T4Iu_8EPhC2GKbHPmcIW_EBiocaw5SIst5g4iINiwDLGZ5Hcs2LyzN_HWgrgtUMGBN006KgNGYuSw5wG_OKdKQYMsfylDLKkCRwYuZisd0e3WF_RjCOmSFXvd7d7WhfGp5ElsyuIwaOZeswTjUFPkFxeJiNTVlA1TvgFLdBEJ_SBJOdO7_XMwVdRlVDRbGCEGJK1vh0xD-78VT4Wpyw6QsvJqrHmqoMt1KK1ehvN2qSEFhQAyJYl0hDKG75MQl4lxWOuRMlPFgiOgJuBcPsraAWXHYv6OpUe-9tBfY8Xa32rtaFbzr_WNOaLdq1pVQZzm2YM0YYKyn3WrmIBmNg4fpLNe_r0ZJiFmupNKfjv_xi6KQydSvNH2E"
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
    'https://login.aai.lifescience-ri.eu/oidc/jwk': {
        name: 'LS Login',
        jwks: {
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "use": "sig",
                "kid": "rsa1",
                "alg": "RS256",
                "n": "zl6laZMB_VXBAUelEO2NSbDnJgsxzuQARYsxMuF38Z_0lf7WkTPDilJme7QEr90R-Q2lrWl8tMosJe4J4N1VL9hwtg1SgnAMlhnUH0ppqpq_M983HzdpzoaNh27E5m8bHzx9RX7_fqnNspCfUQEeEubWEcXGK8ow8zzDEcW16-OZQT24tDNjDHAO9ksAkcs7bg8C4Wz1WBw6KqOMWY2gPzVVUAqK_XWhCktQwHB19XB1xH8ujH7PSKR4eHUgGR2mLgBGFGOZgD-9SnLf7NiF7e2gC41ZfkVBls5UX32DxQzL6Zu0RauD2T4Iu_8EPhC2GKbHPmcIW_EBiocaw5SIst5g4iINiwDLGZ5Hcs2LyzN_HWgrgtUMGBN006KgNGYuSw5wG_OKdKQYMsfylDLKkCRwYuZisd0e3WF_RjCOmSFXvd7d7WhfGp5ElsyuIwaOZeswTjUFPkFxeJiNTVlA1TvgFLdBEJ_SBJOdO7_XMwVdRlVDRbGCEGJK1vh0xD-78VT4Wpyw6QsvJqrHmqoMt1KK1ehvN2qSEFhQAyJYl0hDKG75MQl4lxWOuRMlPFgiOgJuBcPsraAWXHYv6OpUe-9tBfY8Xa32rtaFbzr_WNOaLdq1pVQZzm2YM0YYKyn3WrmIBmNg4fpLNe_r0ZJiFmupNKfjv_xi6KQydSvNH2E"
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
    'https://rems.gdi.nbis.se/api/jwk': {
        name: 'REMS-GDI-NBIS',
        jwks: {
            "keys": [{
                "n": "nCjfFp_GYoRYsROccIeHL5vEGuhxUsgM3jhrH_Bq1b7SsIyjxN5-qxeV2ZQ9SpFC9Piwlsf7-S3nHuDJqqrIyaecyvluxoUhd0uMKCAagEquY6JHUzh6iJQlEFmO8VStysgGuK5oXLFm6BaQFZqeJSgLrn_j6nXPlHepu-ZwIGa8gyk6SGYwe7sPW1lusNl3hyjiDg7m4pvYMJHWm3Cki1HNmXiTRAtubySJ5x_qbKADyuRKcpn1rg-EjJ8JLyLBJTeiIeQXrtTkYUnW1BQ0kRUGYvsfs-1YPzA467fDG_5j3kTFHxQTzAlh2zppu4zdeEGl5wMn7FXZk_ZOTqO91Q",
                "kid": "zjItCgeRKS6zJBfGegBXJYPN6eZRdKeqOXo9fxDsUYs",
                "e": "AQAB",
                "kty": "RSA"
            }]
        },
    },
    'https://gdi-demo.sd.csc.fi/api/jwk': {
        name: 'REMS-GDI-CSC-DEMO',
        jwks: {
            "keys":[{
                "n": "uBO5-5S9WxecLU5NyV4vcL8O5yM7bPw8ru2mP6AaajqXJO8xtV_17iszYuk3yLKrQKFcVLw37bOXCdmyzpqBq9ZVX_sjVDCYVt4MPQZ5dvW0l2lWy0iR30M5dfvwZit8aL15DW9TQOn0cHeSfzTWecdkH5EEICljeSzHdM3vk0JSkpMCmRRw2AgBOsdBD7otVc-T6uKun3NuWmtRGLDsfepF5mpGxPQDppvEAW_FFmgJKQAL74HWPs9xZLLwqLAxELz51PeFTiecJSkPUuHbuFvKY93CEF-ns43vt1wHKyHbLCPgCwBAk4RA6a20pIh3v9PScRiXJSucr0Xnk271vw",
                "kid": "gdi-demo",
                "e": "AQAB",
                "kty": "RSA"
            }]
        },
    },
    'https://rems.dev.gdi.lu/api/jwk': {
        name: 'REMS-GDI-LU-DEMO',
        jwks: {
            "keys":[{
                "n": "wrwPPlRUEJQPrQkc9LmBNTWzsZNfAumTbKC3d2FFoRTVsNaJZ_G0B_P1MLN_WapSe11VYRpY8vxhGw3a1HkZkOSRL9S_Vbxva0zpZNYDRxyHpSJJ0G9pSlZRo05kjMFVGuPn04qF7geDnFqMqSHv9rtdIAcLOAlBUI0EAVjcIkuaeFvr7UYklox5pj2F3jZrer3EJdfDUI3PfNKt1hJYUvvt5wQcLgcNWeyO_otdTtC30f4iI6tExf8GeMdUNvc23-giT2f9_ZzORDK3GIBWWLwD79K2V93AC3lXG4yQrchlEoSc6Z9PFZ3k_-wLGLYxOcNztZbzG_jV4v6tlq3qQw",
                "kid": "gdi-demo",
                "e": "AQAB",
                "kty": "RSA"
            }]
        }
    },
    'https://rems.gdi.biodata.pt/api/jwk': {
        name: 'REMS-GDI-BIODATA-PT',
        jwks: {
            "keys": [{
                "n": "2GPTcVXYDfajOFiOA18xIa0vj97hDQKHUKlxkz4zjZDXBAnfStmpA2U2Og0OMexUj-wzngeex7iCZNUyBsWtNzOfsy4kJJ5tRAnhSmld2zLLuFrroOadjKu-q5oa_Q4RcwTMLI3OjaWtj24e2Gn-qQPb8Ajh3e4Ia1vE7kuEglL157s9IblSHyubyk9--u3FpQs9VRK2hG-pD5xAj7Rl-ghatmWvfQN6K1vy3rwP1ECfDnSGpU9iQIMKCkP2XzsFAKg0WIzRu2CRzGV6HT58BGjE6AH9N92CwY0KQCEaIEzFkNzs7WDZYzMV1dbMoFyfXHxtPBXo5v6RtGcKJfAB1Q",
                "kid": "gdi-demo",
                "e": "AQAB",
                "kty": "RSA"
            }]
        }
    },
    'https://gdi.cloud.ut.ee/api/jwk': {
        name: 'REMS-GDI-EE',
        jwks: {
            "keys": [{
                "alg": "RS256",
                "use": "sig",
                "kty": "RSA",
                "e": "AQAB",
                "kid": "gdi-estonia-rems-2023-10-04",
                "n": "h9fwaZEN8i-20UJbUJE9csGm2HwNouogu5mX4efBEn7QrmYPRK47w320EqolhxEqc6HZvWzC5M_7QjIGYMsx4fqpSmspx7uxjTRF4VT-HAuyhL492xIvVLV4KAJ3MsDz5MbuOszewkdRGTW-8dLdPsychZkM16HYh_0S689ew5ppVGcKPEE0N8_hOusAUDt3KJyCIW31-qbkPc3hqd92Nli3N_Ww7RTg_6B9FXR9lB_dw5Aui3V55pnnVTnOq0E07iiiiNpb17D4f67V9CayAJQsQlpWXOagyb_-9cF-NQ4aOkc0LE4U8s_1l7WCxoLMNiEBpymb6Ck16pxQufFwuQ",
            }]
        }
    },
    'https://gdi.vib.be/api/jwk': {
        name: 'REMS-GDI-BE',
        jwks: {
            "keys": [{
                "n":"1YReX3VUNKLMYdNl2yXoLeq_AXYD9b6_3ZOObeD60tISvFawa_4TN1fPUYNx0QYSWmxf5ixA7WFwYD-_ZYFvncY61Z8QswqQSE8pHW3J0R3ITJdfAbLwsRwlbdEQdnsCXRPTbprlp0UY9YGmHvv5uBY9HQ9DIW0brl9ATPUR0kFjO4PE9sZriCfypu7iJ5ZcaRM1exAf7-vRFgaGDjnz8mthdALotFUH6RaV6C6kup4oD9jiRVB8OeePjPdXvVJYt5xB6gabNL6felROkFjPp4ZxQ82QXr-xsXPGj0xOZ79ayPJ63ddzISL2XxE7IjJIwsuVSxRDoIRbaCyfUICj-Q",
                "kid": "gdi-demo",
                "e": "AQAB",
                "kty": "RSA"
            }]
        }
    },
    'https://rems.ejprd.nbis.se/api/jwk': {
        name: 'REMS-EJPRD-NBIS',
        jwks: {
            "keys": [{
                "n": "lrypbF1I7yeU9MQPCz1eK7ckD7EX5AaB2cyEoeBWzog2GpMowPu8R1rIzvWA7C2Bz9ihISBB4kBF7CBhhFqQvVMjFFxtId5Kp-Nyb3PHTuPbieV79wjZ4RGuAPVlHzLG9jC5IZmu1kR9hetieooeXmSIMFtshPr7Iv1oqV6SbPkVdK3nHs_cpOEr0GMxC6YLcJ11v7z01bb_LRrA8MTShxVbNXL2sj6EK30UK7INjLnYKwwIRrABODPE80h1hPumuGatSTb0dVQs3ymncNDKhu-eCP26HamjetyPrEgarVTtf9psQt8SStZNN6ya8hCJ2U-vvsbXUnz7INfXeaj4bQ",
                "kid": "gdi-demo",
                "e": "AQAB",
                "kty": "RSA"
             }]
        }
    },
    'https://rems.gdifr.lindan.se/api/jwk': {
        name: 'REMS-GDI-FR',
        jwks: {
            
        } 
    },
    'https://id.portal.dev.gdi.lu/realms/gdi/protocol/openid-connect/certs': {
        name: 'GDI-USER-PORTAL',
        jwks: {
            "keys": [{
                "kid": "B5u27I_1ZijDs9VSZe9nnjmXJzerN8hcdw2ObhJZ0Wo",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "x5c": [
                    "MIIClzCCAX8CBgGMHVjjUjANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARja2FuMB4XDTIzMTEyOTIzMDgzM1oXDTMzMTEyOTIzMTAxM1owDzENMAsGA1UEAwwEY2thbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMURH583sY9NVU81ozXOE592Ksb6YU1m2dZ34k15Ck/gJy2pzBYs+G5i2sNsxL8fK5LYr1uvOo3eVehmi0ClejdXVQAoq82dzZY2xTcQCF7PoQnvR/dnWR0mMgWBoJzPwj57rMaVRN2qPcZDMU8Egp2662xftLcOekHQqWI8DDWCqvi8eKb7oPscRQu58Q0d+u0Pb5ECYaxwaCkc/+L2yuKhAcetx92WgeCDMcpFF1iteVIrDJ4Z20RRWDdoOJfiv85oSlGcq/7m8g2HI5r55AUxtSxMKbf7hbOX2nttz0qzVJZ5E15jwet9yxMRlwbMgctzWeAIC8p0ClbmT3FFR+sCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAjykLIjiCFjHmJCj60rC2CBq5MFf7knJuCIZKOMUU2e1zZI1kkI4IZ7yQT9iHURU2bZngvKd8EKwoPw1MDlNgGVDA/UvjOgCOXKOKkd9VuEMk7pGbjURBbRiPmJqv2mKs16/7Jzt3n/xBF513H35AO54JwoMg0gFjG40HnMz7OhIxnUgCls0Slk0BE7hGpVwXs9Iw7tPDrTnVSkObwpdlgQVaqI2igylPYsE6C7piMNEkmaPGwrLNsq9kVzph+Rj9C5/7HyK6N3M397JDTp9F1wpDWMB/ZQrwQ5EHUJxaBbkoQ6IbdFwBlVtz2CzhllpPsnIF3Pn7RGfrQXp0B9zjCg=="
                ],
                "x5t": "ycx1qWUXrtbr0WOSEJ1hJvxVBdg",
                "x5t#S256": "2JSGzMqerSzM1ZMt0WbvW20hCSH_rRF6Cf1EXsnNGqk",
                "n": "xREfnzexj01VTzWjNc4Tn3YqxvphTWbZ1nfiTXkKT-AnLanMFiz4bmLaw2zEvx8rktivW686jd5V6GaLQKV6N1dVACirzZ3NljbFNxAIXs-hCe9H92dZHSYyBYGgnM_CPnusxpVE3ao9xkMxTwSCnbrrbF-0tw56QdCpYjwMNYKq-Lx4pvug-xxFC7nxDR367Q9vkQJhrHBoKRz_4vbK4qEBx63H3ZaB4IMxykUXWK15UisMnhnbRFFYN2g4l-K_zmhKUZyr_ubyDYcjmvnkBTG1LEwpt_uFs5fae23PSrNUlnkTXmPB633LExGXBsyBy3NZ4AgLynQKVuZPcUVH6w",
                "e": "AQAB"
            },
            {
                "kid": "3h7HPbB1Xdx5kCTyxtoRTudc00r1dCEop5cFHponCCs",
                "kty": "RSA",
                "alg": "RSA-OAEP",
                "use": "enc",
                "x5c": [
                    "MIIClzCCAX8CBgGMHVjkPTANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARja2FuMB4XDTIzMTEyOTIzMDgzNFoXDTMzMTEyOTIzMTAxNFowDzENMAsGA1UEAwwEY2thbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK/YuafeRxwCIA9MnzX/GfH9Js073yX2tz6FjoZSTsFxpjHHKZLqBv6pQljMgDHhR/lArq6IqX1VTZq1c76Ez/acukw3JaFCW1FKof6QJ2qsUm8l3hqBICyQ5D20GM2ZKddKSY2Ux2Fl5HibCx5a8k7YMZZPSCT+mOfagWJvsqGqp9k1Za7vKKpvB0W+8MzRV+hQnBuSVujVfx0uMT9DSBoLIuyhT8LYblFt8ys+QKmr/GK+I0hyiQBHq2LwF61xwOXo/hQYR/3S2KE5qMT+PN0rNiykg9AZhX7QWHc62dKXA67mnTOR+T0utw1a2uTT3T/ppTtj4gwFLJ+J5wiib4ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAc494XGxjSw8yRicpnk00jIdbZ3SgeJadkXhAm13yeX+YYgUgk08MDIr4laPY4I6zBb/L3bz6j132TUBYDXriJ1EokHp6kOM2bN9UDMFQEmsaMs2wcFPDNu8p/fbMoljeGF3D5YiQPJUlBb1AX/3HWK6qFIJlQRdppUneJ2ANM2vBRN5mjX0Ss2dG0dXaM9NrTK5EmGc4io9yevWagK6/BNSgKVzZN6Sr0Yi5DX/NW8V43aGfUAxRZdLgTpbM1i/TKZGxYsL3KPquIYRn+SB9+U0uX7D6+5hKq5CJG4HAdawCtHqMGwLKlBkv2+Wj//zpM0LHv2vrmObUl3nJfDCU7A=="
                ],
                "x5t": "N3egWm3PL0N5Fo217HmGzomcHew",
                "x5t#S256": "aHCtbY5l7uBfnrxGuVKQ-LDiuXDzMusaYrVwNBBE8-0",
                "n": "r9i5p95HHAIgD0yfNf8Z8f0mzTvfJfa3PoWOhlJOwXGmMccpkuoG_qlCWMyAMeFH-UCuroipfVVNmrVzvoTP9py6TDcloUJbUUqh_pAnaqxSbyXeGoEgLJDkPbQYzZkp10pJjZTHYWXkeJsLHlryTtgxlk9IJP6Y59qBYm-yoaqn2TVlru8oqm8HRb7wzNFX6FCcG5JW6NV_HS4xP0NIGgsi7KFPwthuUW3zKz5Aqav8Yr4jSHKJAEerYvAXrXHA5ej-FBhH_dLYoTmoxP483Ss2LKSD0BmFftBYdzrZ0pcDruadM5H5PS63DVra5NPdP-mlO2PiDAUsn4nnCKJvgQ",
                "e": "AQAB"
            }]
        }
    },
};
const POLICIES = {
    'https://doi.org/10.1038/s41431-018-0219-y': 'The attestations for registered access (<a href="https://elixir-europe.org/services/compute/aai/bonafide">link</a>)'
};
const STATUSES = {
    'https://doi.org/10.1038/s41431-018-0219-y': 'Bona Fide researcher for registered access (<a href="https://elixir-europe.org/services/compute/aai/bonafide">link</a>)'
}
const timeFormat = new Intl.DateTimeFormat('en-GB', {'dateStyle': 'full', 'timeStyle': 'full'});

mgr = new Oidc.UserManager(config.oidc);
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
                jwt: jwt,
                verified: false,
                signerName: null
            };
            console.log('processing visa ', tablecounter, visaInfo.visa.ga4gh_visa_v1.type, visaInfo.visa.ga4gh_visa_v1.value);
            //console.log(visaInfo);

            const now = new Date();
            const iat = new Date(visa.iat * 1000);
            const exp = new Date(visa.exp * 1000);
            const asserted = new Date(visa.ga4gh_visa_v1.asserted * 1000);

            // verify signature (at the time of issuance, otherwise expired tokens would be marked as invalid signatures)
            const signer = SIGNERS[visaInfo.header.jku];
            if (signer) {
                const signer_key = KEYUTIL.getKey(signer.jwks.keys.filter(key => key.kid === visaInfo.header.kid)[0]);
                visaInfo.verified = KJUR.jws.JWS.verifyJWT(jwt, signer_key, {alg: ['RS256'], verifyAt: visaInfo.visa.iat});
                visaInfo.signerName = signer.name;
            } else {
                console.log("skipping visa verification, cannot find signer in SIGNERS for key ", visaInfo.header.jku);
            }

            // issuer friendly name
            let issuer = ISSUERS[visa.iss];
            if (! issuer) {
                issuer = 'unknown';
            }

            try {
                document.getElementById(visa.ga4gh_visa_v1.type).innerHTML +=
                    '<table class="ga4gh_expert" id="tab' + tablecounter + '">' +
                    '<tr><th>value</th><td>' + visa.ga4gh_visa_v1.value + '</td></tr>' +
                    '<tr><th>source</th><td>' + visa.ga4gh_visa_v1.source + '</td></tr>' +
                    '<tr><th>by</th><td>' + visa.ga4gh_visa_v1.by + '</td></tr>' +
                    '<tr><th>conditions</th><td>' + (visa.ga4gh_visa_v1.conditions ? visa.ga4gh_visa_v1.conditions : '') + '</td></tr>' +
                    '<tr><th>issuer (iss)</th><td>' + visa.iss + ' (' + issuer + ')</td></tr>' +
                    '<tr><th>subject (sub)</th><td>' + visa.sub + '</td></tr>' +
                    '<tr><th>asserted at</th><td>' + visa.ga4gh_visa_v1.asserted + ' (' + timeFormat.format(asserted) + ')</td></tr>' +
                    '<tr><th>issued at (iat)</th><td ' + (iat > now ? 'class="warning"' : '') + '>' + visa.iat + ' (' + timeFormat.format(iat) + ')' + (iat > now ? ' issued in the future ' : '') + '</td></tr>' +
                    '<tr><th>expires at (exp)</th><td ' + (exp < now ? 'class="warning"' : '') + '>' + visa.exp + ' (' + timeFormat.format(exp) + ')' + (exp < now ? ' visa expired ' : '') + '</td></tr>' +
                    '<tr><th>JWT id (jti)</th><td>' + (visa.jti ? visa.jti : '') + '</td></tr>' +
                    '<tr><th>signature</th><td ' + (!visaInfo.verified ? 'class="warning"' : '') + '>jku: ' + visaInfo.header.jku + ' kid: ' + visaInfo.header.kid
                    + ' (' + visaInfo.signerName + ') ' + (!visaInfo.verified ? 'invalid signature' : '<span class="ok">verified</span>') + '</td></tr>' +
                    '<tr><td colspan="2" class="rawjwt">' +
                    '<button id="but' + tablecounter + '">Display raw decoded JWT</button>' +
                    '<pre id="pre' + tablecounter + '">' + JSON.stringify(visaInfo.header, null, 2) + '<br>.<br>' + JSON.stringify(visa, null, 2) + '</pre>' +
                    '</td></tr>' +
                    '</table>'
                ;
            } catch (e) {
                console.log("visa ",tablecounter," problem");
                console.log(e);
            }
            tablecounter++;

            // process visa for basic view
            switch (visa.ga4gh_visa_v1.type) {
                case 'LinkedIdentities':
                    console.log(visa.ga4gh_visa_v1.value.split(';'));
                    if (visa.sub === user.profile.sub && visa.iss === config.oidc.authority) {
                        for (const lid of visa.ga4gh_visa_v1.value.split(';').map(pair => pair.split(','))) {
                            let linkedId = {};
                            linkedId.sub = decodeURIComponent(lid[0]); // linked sub
                            linkedId.iss = decodeURIComponent(lid[1]); // linked iss - issued the JWT
                            linkedId.source = visa.ga4gh_visa_v1.source; // linked source - collected the info
                            linkedId.key = linkedId.sub + linkedId.iss;
                            linked_ids.set(linkedId.key, linkedId);
                            console.log(linkedId);
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
                            if (lidsub === user.profile.sub && lidiss === config.oidc.authority) {
                                linked_ids.set(linkedId.key, linkedId);
                            }
                        }
                        console.log(linkedId);
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
        console.log('linked_ids', linked_ids);
        for (let linkedId of linked_ids.values()) {
            document.getElementById("basic_linked_ids").innerHTML +=
                "in " + ISSUERS[linkedId.iss] + ' as ' + linkedId.sub + '<br>';
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
        if (config.supportTokenExchange) {
            callTokenExchange(user.access_token);
        }

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
    mgr._metadataService.getTokenEndpoint(false).then(function(url) {
        const xhr = new XMLHttpRequest();
        xhr.onload = function () {
            console.log('Token exchange response: ' + xhr.status);
            // console.log(xhr.responseText);
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
                    '<pre class="rawjwt">' + jsonResponse.expires_in + ' sec</pre>' +
                    '<p>Refresh token</p>' +
                    '<pre class="rawjwt">' + (jsonResponse.refresh_token === "" ? "-" : jsonResponse.refresh_token) + '</pre>' +
                    '<p>Raw response:</p>';
                rawlog("raw_passport_token", jsonResponse);
            } else {
                document.getElementById("PassportToken").innerHTML = '<pre class="rawjwt">' + xhr.responseText + '</pre>';
            }
        }
        xhr.open("POST", url  + "?" + query);
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        xhr.setRequestHeader("Authorization", "Basic " + btoa(config.oidc.client_id + ":"));
        xhr.send();
    });
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
