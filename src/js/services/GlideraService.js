angular.module('blocktrail.wallet').factory(
    'glideraService',
    function(CONFIG, $log, $q, Wallet, dialogService, $translate, $http, $timeout, settingsService) {
        var clientId = "9074010d6e573bd7b06645735ba315c8";
        var clientSecret = "02cc9562bd2049b6fadb88578bc4c723";
        var returnuri = "http://localhost:3000/%23/wallet/buy/glidera/oaoth2/callback";
        // var returnuri = "http://localhost:3000/?glidera=oauth2";

        var decryptedAccessToken = null;

        var setDecryptedAccessToken = function(accessToken) {
            decryptedAccessToken = accessToken;

            $timeout(function() {
                decryptedAccessToken = null;
            }, 30 * 60 * 1000); // 30min
        };

        var createRequest = function(options, accessToken, twoFactor) {
            options = options || {};
            var headers = {};
            if (accessToken) {
                headers['Authorization'] = 'Bearer ' + accessToken;
            }
            if (twoFactor) {
                headers['X-2FA-CODE'] = twoFactor;
            }

            options = _.defaults({}, (options || {}), {
                https: true,
                host: 'sandbox.glidera.io',
                endpoint: '/api/v1',
                params: {},
                headers: _.defaults({}, (options.headers || {}), headers),
                contentMd5: false
            });

            return new blocktrailSDK.Request(options);
        };

        var oauth2 = function() {
            var uuid = Math.ceil((new Date).getTime() / 1000);
            var scope = ['transact'].join(',');
            var qs = [
                'response_type=code',
                'client_id=' + clientId,
                'state=' + uuid,
                'scope=' + scope,
                'required_scope=' + scope,
                'login_hint=' + (settingsService.email || "").replace(/\+.*@/, "@"), // name+label@mail.com isn't supported by glidera
                'redirect_uri=' + returnuri
            ];

            var glideraUrl = "https://sandbox.glidera.io/oauth2/auth?" + qs.join("&");

            $log.debug('oauth2', glideraUrl);

            window.open(glideraUrl, '_self');
        };

        var setup = function() {
            return accessToken().then(function(accessToken) {
                var qs = [
                    'redirect_uri=' + returnuri,
                    'access_token=' + accessToken
                ];

                var glideraUrl = "https://sandbox.glidera.io/user/setup?" + qs.join("&");

                $log.debug('setup', glideraUrl);

                window.open(glideraUrl, '_self');
            });
        };

        var handleOauthCallback = function(glideraCallback) {
            if (!glideraCallback) {
                return $q.reject(new Error("no glideraCallback"));
            }

            return $q.when(glideraCallback)
                .then(function(glideraCallback) {
                    var qs = parseQuery(glideraCallback);

                    $log.debug('qs? ', JSON.stringify(qs, null, 4));

                    if (!qs.code) {
                        throw new Error(qs.error_message.replace("+", " "));
                    }

                    var r = createRequest();

                    return r.request('POST', '/oauth/token', {}, {
                        grant_type: "authorization_code",
                        code: qs.code,
                        redirect_uri: returnuri,
                        client_id: clientId,
                        client_secret: clientSecret
                    })
                        .then(function(result) {
                            $log.debug('oauthtoken', JSON.stringify(result, null, 4));

                            var accessToken = result.access_token;
                            var glideraAccessToken = {
                                scope: result.scope
                            };

                            return settingsService.$isLoaded().then(function() {
                                return $cordovaDialogs.prompt(
                                        $translate.instant('MSG_BUYBTC_PIN_TO_ENCRYPT').sentenceCase(),
                                        $translate.instant('MSG_ENTER_PIN').sentenceCase(),
                                        [$translate.instant('OK'), $translate.instant('CANCEL').sentenceCase()],
                                        "",
                                        true,   //isPassword
                                        "tel"   //input type (uses html5 style)
                                    );
                                })
                                    .then(function(dialogResult) {
                                        if (dialogResult.buttonIndex == 2) {
                                            return $q.reject('CANCELLED');
                                        }
                                        //decrypt password with the provided PIN
                                        // $ionicLoading.show();

                                        return Wallet.unlockData(dialogResult.input1).then(function(unlockData) {

                                            // still gotta support legacy wallet where we encrypted the password instead of secret
                                            if (unlockData.secret) {
                                                glideraAccessToken.encryptedWith = 'secret';
                                                glideraAccessToken.encryptedAccessToken = CryptoJS.AES.encrypt(accessToken, unlockData.secret).toString();
                                            } else {
                                                glideraAccessToken.encryptedWith = 'password';
                                                glideraAccessToken.encryptedAccessToken = CryptoJS.AES.encrypt(accessToken, unlockData.password).toString();
                                            }
                                        })
                                    })
                                    .then(function() {
                                        setDecryptedAccessToken(accessToken);
                                        settingsService.glideraAccessToken = glideraAccessToken;

                                        return settingsService.$store().then(function() {
                                            $log.debug('SAVED');
                                            return settingsService.$syncSettingsUp();
                                        });
                                    })
                                    .then(function() {
                                        // $ionicLoading.hide();
                                    }, function(err) {
                                        // $ionicLoading.hide();
                                        throw err;
                                    })
                                ;
                            })
                        ;
                    })
                .then(function(result) { return result }, function(err) { $log.log(err); throw err; })
            ;
        };

        var userCanTransact = function() {
            return settingsService.$isLoaded().then(function() {
                if (!settingsService.glideraAccessToken) {
                    return false;
                }

                if (settingsService.glideraAccessToken.userCanTransact === true) {
                    return settingsService.glideraAccessToken.userCanTransact;
                }

                return accessToken().then(function(accessToken) {
                    if (!accessToken) {
                        return false;
                    }

                    var r = createRequest(null, accessToken);

                    return r.request('GET', '/user/status ', {}, null)
                        .then(function(result) {
                            $log.debug('status', JSON.stringify(result, null, 4));

                            return settingsService.$isLoaded().then(function() {
                                settingsService.glideraAccessToken.userCanTransact = result.userCanTransact;
                                settingsService.glideraAccessToken.userCanTransactInfo = _.defaults({}, result.userCanTransactInfo);

                                return settingsService.$store().then(function() {
                                    return result.userCanTransact;
                                });
                            });
                        })
                        ;
                });
            })
                .then(function(userCanTransact) { return userCanTransact; }, function(err) { $log.log(err); throw err; })
                ;
        };

        var twoFactor = function() {
            return twoFactorMode().then(function(twoFactorMode) {
                if (twoFactorMode === "NONE") {
                    return;
                } else {
                    return $cordovaDialogs.prompt(
                        $translate.instant('MSG_BUYBTC_GLIDERA_2FA_BODY', {
                            mode: twoFactorMode
                        }).sentenceCase(),
                        $translate.instant('MSG_BUYBTC_GLIDERA_2FA_TITLE').sentenceCase(),
                        [$translate.instant('OK'), $translate.instant('CANCEL').sentenceCase()],
                        ""
                    )
                    .then(function(dialogResult) {
                        if (dialogResult.buttonIndex == 2) {
                            return $q.reject('CANCELLED');
                        }

                        return dialogResult.input1;
                    });
                }
            });
        };

        var twoFactorMode = function() {
            return settingsService.$isLoaded().then(function() {
                if (!settingsService.glideraAccessToken) {
                    return false;
                }

                return accessToken().then(function(accessToken) {
                    if (!accessToken) {
                        return false;
                    }

                    var r = createRequest(null, accessToken);

                    return r.request('GET', '/authentication/get2faCode', {}, null)
                        .then(function(result) {
                            $log.debug('get2faCode', JSON.stringify(result, null, 4));

                            return result.mode;
                        })
                    ;
                });
            })
                .then(function(userCanTransact) { return userCanTransact; }, function(err) { $log.log(err); throw err; })
            ;
        };

        var accessTokenPromise = null; // use promise to avoid doing things twice
        var accessToken = function() {
            if (decryptedAccessToken) {
                $log.debug('decryptedAccessToken');
                return $q.when(decryptedAccessToken);
            } else if (accessTokenPromise) {
                $log.debug('accessTokenPromise');
                return accessTokenPromise;
            }

            var def = $q.defer();

            accessTokenPromise = def.promise;

            $timeout(function() {
                settingsService.$isLoaded().then(function() {
                    $log.debug('glideraAccessToken', JSON.stringify(settingsService.glideraAccessToken, null, 4));

                    return settingsService.glideraAccessToken ? settingsService.glideraAccessToken.encryptedAccessToken : null;
                }).then(function(encryptedAccessToken) {
                    if (!encryptedAccessToken) {
                        return;
                    }

                    var promptForPin = function() {
                        console.log('promptForPin');

                        return dialogService.prompt({
                            title: $translate.instant('MSG_BUYBTC_PIN_TO_DECRYPT').sentenceCase(),
                            body: $translate.instant('MSG_ENTER_PIN').sentenceCase(),
                            input_type: 'tel',
                            icon: 'key'
                        })
                            .result
                            .then(function(pin) {
                                console.log('dialogResult');
                                return pin;
                            }, function(err) {
                                console.log('dialogErr ' + err);
                            });
                    };

                    var decryptAccessToken = function() {
                        console.log('decryptAccessToken');
                        return promptForPin().then(function(pin) {
                            console.log('pin');
                            //decrypt password with the provided PIN
                            // $ionicLoading.show();

                            return Wallet.unlockData(pin).then(function(unlockData) {
                                console.log('unlockData');
                                // still gotta support legacy wallet where we encrypted the password instead of secret
                                var accessToken;
                                if (unlockData.secret) {
                                    accessToken = CryptoJS.AES.decrypt(encryptedAccessToken, unlockData.secret).toString(CryptoJS.enc.Utf8);
                                } else {
                                    accessToken = CryptoJS.AES.decrypt(encryptedAccessToken, unlockData.password).toString(CryptoJS.enc.Utf8);
                                }

                                setDecryptedAccessToken(accessToken);

                                return accessToken;
                            }, function(err) {
                                console.log('decryptAccessToken AGAIN');
                                return decryptAccessToken();
                            })
                                .then(function(r) {
                                    // $ionicLoading.hide();
                                    return r;
                                }, function(err) {
                                    // $ionicLoading.hide();
                                    throw err;
                                })
                            ;
                        })
                    };

                    return decryptAccessToken();
                })
                    .then(function(r) {
                        console.log('DONE');
                        accessTokenPromise = null;
                        def.resolve(r);
                    }, function(err) {
                        console.log('DONE ERR');
                        accessTokenPromise = null;
                        $log.debug(err);
                        def.reject(err);
                    });
            }, 100);

            return accessTokenPromise;
        };

        var buyPrices = function(qty, fiat) {
            return userCanTransact().then(function(userCanTransact) {
                if (!userCanTransact) {
                    throw new Error("User can't transact!");
                }

                return accessToken().then(function(accessToken) {
                    var r = createRequest(null, accessToken);
                    return r.request('POST', '/prices/buy', {}, {
                        qty: qty,
                        fiat: fiat
                    })
                        .then(function(result) {
                            $log.debug('buyPrices', JSON.stringify(result, null, 4));

                            return result;
                        })
                    ;
                });
            });
        };

        var buy = function(qty, priceUuid) {
            return userCanTransact().then(function(userCanTransact) {
                if (!userCanTransact) {
                    throw new Error("User can't transact!");
                }

                return accessToken().then(function(accessToken) {

                    return Wallet.getNewAddress().then(function(address) {

                        return twoFactor().then(function(twoFactor) {
                            var r = createRequest(null, accessToken, twoFactor);
                            return r.request('POST', '/buy', {}, {
                                destinationAddress: address,
                                qty: qty,
                                priceUuid: priceUuid,
                                useCurrentPrice: false
                            })
                                .then(function(result) {
                                    $log.debug('buy', JSON.stringify(result, null, 4));

                                    return result;
                                })
                            ;
                        });
                    });
                });
            });
        };

        return {
            createRequest: createRequest,
            oauth2: oauth2,
            setup: setup,
            twoFactor: twoFactor,
            handleOauthCallback: handleOauthCallback,
            accessToken: accessToken,
            userCanTransact: userCanTransact,
            buyPrices: buyPrices,
            buy: buy
        };
    }
);
