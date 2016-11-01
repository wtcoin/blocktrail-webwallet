angular.module('blocktrail.wallet').factory(
    'glideraService',
    function(CONFIG, $log, $q, Wallet, dialogService, $rootScope, $translate, $http, $timeout, $interval, settingsService, launchService, sdkService) {
        var clientId;
        var returnuri = CONFIG.WALLET_URL + "/#/wallet/buy/glidera/oaoth2/callback";
        var SANDBOX = CONFIG.GLIDERA_URL.indexOf('sandbox.') !== -1;
        var decryptedAccessToken = null;

        var encodeOpenURI = function(uri) {
            return uri.replace('#', '%23');
        };

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
                host: CONFIG.GLIDERA_URL.replace(/https?:\/\//, ''),
                endpoint: '/api/v1',
                params: {},
                headers: _.defaults({}, (options.headers || {}), headers),
                contentMd5: false
            });

            return new blocktrailSDK.Request(options);
        };

        var oauth2 = function() {
            var uuid = Math.ceil((new Date).getTime() / 1000);
            var scope = ['transact', 'transaction_history'].join(' ');
            var qs = [
                'response_type=code',
                'client_id=' + clientId,
                'state=' + uuid,
                'scope=' + scope,
                'required_scope=' + scope,
                'login_hint=' + (settingsService.email || "").replace(/\+.*@/, "@"), // name+label@mail.com isn't supported by glidera
                'redirect_uri=' + returnuri
            ];

            var glideraUrl = CONFIG.GLIDERA_URL + "/oauth2/auth?" + qs.join("&");

            $log.debug('oauth2', glideraUrl);

            window.open(encodeOpenURI(glideraUrl), '_self');
        };

        var setup = function() {
            return accessToken().then(function(accessToken) {
                var qs = [
                    'redirect_uri=' + returnuri,
                    'access_token=' + accessToken
                ];

                var glideraUrl = CONFIG.GLIDERA_URL + "/user/setup?" + qs.join("&");

                $log.debug('setup', glideraUrl);

                window.open(encodeOpenURI(glideraUrl), '_self');
            });
        };

        var handleOauthCallback = function(glideraCallback) {
            if (!glideraCallback) {
                return $q.reject(new Error("no glideraCallback"));
            }

            var spinner;

            return $q.when(glideraCallback)
                .then(function(glideraCallback) {
                    var qs = parseQuery(glideraCallback);

                    $log.debug('qs? ', JSON.stringify(qs, null, 4));

                    if (!qs.code) {
                        throw new Error(qs.error_message.replace("+", " "));
                    }

                    spinner = dialogService.spinner({title: 'WORKING'});

                    return sdkService.sdk().then(function(sdk) {
                        return sdk.glideraOauth(qs.code, returnuri, SANDBOX)
                            .then(function(result) {
                                $log.debug('oauthtoken', JSON.stringify(result, null, 4));

                                var accessToken = result.access_token;
                                var glideraAccessToken = {
                                    scope: result.scope
                                };

                                return settingsService.$isLoaded().then(function() {
                                    return launchService.getAccountInfo().then(function(accountInfo) {
                                        glideraAccessToken.encryptedWith = 'secret';
                                        glideraAccessToken.encryptedAccessToken = CryptoJS.AES.encrypt(accessToken, accountInfo.secret).toString();
                                    })
                                        .then(function() {
                                            setDecryptedAccessToken(accessToken);
                                            settingsService.glideraAccessToken = glideraAccessToken;

                                            return settingsService.$store().then(function() {
                                                return settingsService.$syncSettingsUp();
                                            })
                                                .then(function() {
                                                    updateAllTransactions();
                                                })
                                            ;
                                        })
                                    ;
                                })
                            })
                        ;
                    });
                })
                .then(function(result) { spinner.close(); return result; }, function(err) { if(spinner) { spinner.close(); } $log.log(err); throw err; })
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
                    return dialogService.prompt({
                        body: $translate.instant('MSG_BUYBTC_GLIDERA_2FA_BODY', {
                            mode: twoFactorMode
                        }).sentenceCase(),
                        title: $translate.instant('MSG_BUYBTC_GLIDERA_2FA_TITLE').sentenceCase()
                    })
                    .result;
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

                    var decryptAccessToken = function() {
                        return launchService.getAccountInfo().then(function(accountInfo) {
                            var accessToken = CryptoJS.AES.decrypt(encryptedAccessToken, accountInfo.secret).toString(CryptoJS.enc.Utf8);

                            setDecryptedAccessToken(accessToken);

                            return accessToken;
                        });
                    };

                    return decryptAccessToken();
                })
                    .then(function(r) {
                        $log.debug('DONE');
                        accessTokenPromise = null;
                        def.resolve(r);
                    }, function(err) {
                        $log.debug('DONE ERR');
                        accessTokenPromise = null;
                        $log.debug(err);
                        def.reject(err);
                    });
            }, 100);

            return accessTokenPromise;
        };

        var buyPrices = function(qty, fiat) {
            $log.debug('buyPrices', qty, fiat);
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

                                    settingsService.glideraTransactions.push({
                                        transactionUuid: result.transactionUuid,
                                        transactionHash: result.transactionHash || null,
                                        status: result.status,
                                        qty: result.qty,
                                        price: result.price,
                                        total: result.total,
                                        currency: result.currency
                                    });

                                    return settingsService.$store().then(function() {
                                        return settingsService.$syncSettingsUp().then(function() {
                                            updatePendingTransactions();

                                            return result;
                                        });
                                    });
                                })
                            ;
                        });
                    });
                });
            });
        };

        var setClientId = function(_clientId) {
            clientId = _clientId;
        };

        var pollPendingTransactions = true;
        var $updateStatus;
        var updatePendingTransactions = function() {
            $updateStatus = $q.defer();

            var _update = function() {
                pollPendingTransactions = false;
                var delay = 10000;

                return accessToken().then(function(accessToken) {
                    if (accessToken) {
                        var updateStatus = {};

                        $q.all(settingsService.glideraTransactions.map(function(transaction) {
                            if (transaction.status === 'PROCESSING' || !transaction.transactionHash) {
                                pollPendingTransactions = true;
                                var r = createRequest(null, accessToken);
                                return r.request('GET', '/transaction/' + transaction.transactionUuid, {})
                                    .then(function(result) {
                                        updateStatus[transaction.transactionUuid] = result;
                                    })
                                ;
                            } else {
                                return $q.when(null);
                            }
                        }))
                            .then(function() {
                                settingsService.glideraTransactions = settingsService.glideraTransactions.map(function(transaction) {
                                    if (typeof updateStatus[transaction.transactionUuid] !== "undefined") {
                                        var newTxInfo = updateStatus[transaction.transactionUuid];
                                        var oldStatus = transaction.status;

                                        // sometimes a tx is marked COMPLETE but missing a transactionHash,
                                        //  in that case we force another update
                                        if (newTxInfo.status === 'COMPLETE' && !newTxInfo.transactionHash) {
                                            delay = 0;
                                        } else {
                                            transaction.qty = newTxInfo.qty;
                                            transaction.status = newTxInfo.status;
                                            transaction.transactionHash = newTxInfo.transactionHash;

                                            if (oldStatus === 'PROCESSING' && transaction.status === 'COMPLETE') {
                                                $rootScope.$broadcast('glidera_complete', transaction);
                                            }
                                        }
                                    }

                                    return transaction;
                                });

                                return settingsService.$store().then(function() {
                                    return settingsService.$syncSettingsUp();
                                });
                            })
                        ;
                    }
                })
                    .then(function() {
                    }, function(e) {
                        $log.error('updatePendingTransactions ' + e);
                    })
                    .then(function() {
                        if (delay) {
                            $updateStatus.resolve();

                            if (pollPendingTransactions) {
                                $timeout(updatePendingTransactions, delay);
                            }
                        } else {
                            // do it again
                            return _update();
                        }
                    })
                ;
            };

            _update();
        };
        var updateAllTransactions = function(initLoop) {
            $updateStatus = $q.defer();

            return accessToken().then(function(accessToken) {
                if (accessToken) {
                    var updateTxs = [];

                    var r = createRequest(null, accessToken);
                    return r.request('GET', '/transaction', {})
                        .then(function(results) {
                            results.transactions.forEach(function(result) {
                                updateTxs.push(result);
                            });
                        })
                        .then(function() {
                            settingsService.glideraTransactions = updateTxs.map(function(updateTx) {
                                return {
                                    transactionUuid: updateTx.transactionUuid,
                                    transactionHash: updateTx.transactionHash,
                                    qty: updateTx.qty,
                                    status: updateTx.status,
                                    price: updateTx.price,
                                    total: updateTx.total,
                                    currency: updateTx.currency
                                };
                            });

                            return settingsService.$store().then(function() {
                                return settingsService.$syncSettingsUp().then(function() {
                                    return true;
                                });
                            });
                        })
                    ;
                } else {
                    return false;
                }
            })
                .then(function(r) { return r; }, function(e) { $log.error('updateAllTransactions ' + e); })
                .then(function(r) {
                    $updateStatus.resolve();

                    if (initLoop) {
                        if (r) {
                            $timeout(updatePendingTransactions, 10000);
                        } else {
                            $timeout(updateAllTransactions, 10000);
                        }
                    }
                })
            ;
        };
        // updateAllTransactions(); // @TODO: DEBUG
        updatePendingTransactions();

        Wallet.addTransactionMetaResolver(function(transaction) {
            return $updateStatus.promise.then(function() {
                settingsService.glideraTransactions.forEach(function(glideraTxInfo) {
                    if (glideraTxInfo.transactionHash === transaction.hash) {
                        transaction.buybtc = {
                            broker: 'glidera',
                            qty: glideraTxInfo.qty,
                            currency: glideraTxInfo.currency,
                            price: glideraTxInfo.price
                        };
                    }
                });

                return transaction;
            });
        });

        return {
            $updateStatus: function() {
                return $updateStatus.promise;
            },
            setClientId: setClientId,
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
