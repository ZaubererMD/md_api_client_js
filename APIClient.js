/**
 * Client for easy communication with an md_api_server
 */
class APIClient {
    
    /**
     * @typedef {Object} APIClientConfig
     * @param {string} url The URL of the md_api_server to connect to
     * @param {function (CallData) => void} [onCallStart=null] A callback which is called before an API-method is executed. Can be used e.g. to display an activity indicator. It will receive the call-details as an argument.
     * @param {function (CallData) => void} [onCallEnd=null] A callback which is called after a response to a method is received. Can be used e.g. to hide an activity indicator. It will receive the call-details as an argument.
     * @param {function (string) => void} onError A callback which is called upon any error. An error message will be passed.
     */
    /**
     * Creates a new API-client
     * @param {APIClientConfig} config
     */
    constructor({url, onCallStart = null, onCallEnd = null, onError = null}) {
        this.url = url;
        this.hooks = {
            callStart : onCallStart,
            callEnd : onCallEnd,
            error : onError
        };

        // holds the ID of the interval which sends a keep-alive signal when logged in
	    this.keepAliveInterval = null;
    
        // Here the developer can register calls to be sent alongside each login as a multicall.
        // Is used by the login and checkSession procedure.
        this.loginCalls = [];
	
        // setting this to true will generate a more verbose console output
        this.debug = false;
        
        // stores information about the current session, when logged in
	    this.session = null;
    }

    /**
     * Checks whether a user-defined callback is registered and calls it if that is the case
     * only used internally
     * @param {string} which name of the hook
     * @param {any} [data=null] data to pass to the callback
     */ 
    callHook(which, data = null) {
        if(typeof(this.hooks[which]) === 'function') {
            this.hooks[which](data);
        }
    }

    /**
     * @typedef {function} SuccessCallback
     * @param {Object} data The data returned from the API
     */
    /**
     * @typedef {function} ErrCallback
     * @param {string} msg Message describing the error that occured
     */
    /**
     * @typedef {Object} CallData
     * @property {string} method The method to call
     * @property {Object} [data] The parameters to pass to the method
     * @property {SuccessCallback} [callback=null] A callback-function that is called when this call executes successfully
     * @property {ErrCallback} [onError=null] A callback-function that is called when this call executes with an error
     * @property {boolean} [breaking=false] Only used in multicalls: If this is set to true, the execution of further calls after this one is skipped in case this call fails
     * @property {boolean} [doNotRetry=false] If this is set to true, there will be no retry attempt if the API responds with a code indicating a missing session. The APIClient uses this internally when a retry is performed so you dont end up with an infinite retry-loop.
     * @property {CallData[]} [rawCalls] Should only be set when called from the multicall-method. Provides information about the original calls that make up the multicall.
     * @property {APIResponse} [response] The API response will be set when the call finishes. It can then be used in callEnd- or error-hooks. You should not set this property yourself.
     * @property {string} [retryToken] If the API responds witha code indicating we are missing a valid session then it will issue a login-token we can use in the rety. This will be set internally by verifyResponseAndCallback and should not be set from the outside.
     */
	/**
     * Executes an API-Call, verifies the results and calls the callback if successful.
     * The Session-Token (callData.data.token) will be appended automatically if not present and session-data is present (user is logged in).
     * If the API responds with a code indicating that we did not provide a valid session token,
     * an automatic relogin will be triggered and the call will be sent again along with it as a multicall.
     * This Retry-Behaviour can be controlled via callData.doNotRetry.
     * @param {CallData} callData
     */
	call(callData) {

        // Set default values
		callData.data = callData.data || {};
        callData.callback = callData.callback || null;
        callData.onError = callData.onError || null;
        callData.breaking = (callData.breaking !== undefined && callData.breaking !== null ? callData.breaking : false);
        callData.doNotRetry = (callData.doNotRetry !== undefined && callData.doNotRetry !== null ? callData.doNotRetry : false);

        // Append session-token if it exists
		if(
            (typeof(this.session) === 'object' && this.session !== null)
            && (typeof(this.session.token) === 'string')
            && (typeof(callData.data.token) !== 'string')
        ) {
			callData.data.token = this.session.token;
		}
		
		if(this.debug) {
			console.log('----- BEGIN API CALL -----');
			console.log(callData);
			console.log('----- END API CALL -----');
		}
        
        // prepare formdata
        let formData = JSON.stringify(callData.data);
        let methodURL = this.url + '/' + callData.method;
        let headers = { 'Content-Type' : 'application/json' };

        // execute callStart-Hook if it exists
		this.callHook('callStart', callData);

        // execute the API-Call
        fetch(methodURL, {
            method : 'POST',
            body : formData,
            headers : headers,
            mode : 'cors'
        }).then((response) => {
        
            // If the HTTP-Response is OK (200), continue
            if(response.ok) {
                return response.text();
            } else {
                return Promise.reject('The API responded with an invalid HTTP status code ('+response.status+')');
            }

        }).then((responseText) => {

            // Try to parse the response body from JSON to a JS-Object
            try {
                let response = JSON.parse(responseText);
                return response;
            } catch(e) {
                console.error('Malformed JSON', responseText);
                return Promise.reject(e);
            }

        }).then((response) => {

            // Attach response to the call information object
            callData.response = response;
			
            if(this.debug) {
                console.log('----- BEGIN API RESPONSE -----');
                console.log(callData.response);
                console.log('----- END API RESPONSE -----');
            }
        
            // verify whether the response contains any API-errors and call the callback if not
            let retryCallData = this.verifyResponseAndCallback(callData);

            // If the call of verifyResponseAndCallback returns anything besides null,
            // this means the API signaled an invalid session and we retry the call after a relogin
            if(retryCallData !== null) {
                this.relogin([retryCallData], callData.onError);
            }

        }).catch((error) => {
            let errorMsg = callData.method + ' - ' + error;
            if(typeof(callData.onError) === 'function') {
                callData.onError(errorMsg);
            }
            this.callHook('error', errorMsg);
        }).finally(() => {
            // execute callEnd-Hook if it exists
            this.callHook('callEnd', callData);
        });
	}
	
    /**
     * Checks whether the success-flag is set to true in a response. If yes, the defined callback is executed with the response-data.
     * If it is not set, the response.code field is checked. When it contains 'PERMISSION_NO_SESSION' then a retry of the call is sent
     * alongside a relogin as a multicall, but only if callData.doNotRetry is set to false. The doNotRetry-flag will be set to true in
     * the retried call, no matter what it was originally, in order to prevent infinite retry-loops.
     * @param {CallData} callData
     * @returns {CallData|null} call-information enriched with a retry-login-token, if a retry is necessary due to an invalid session, null otherwise
     */
    verifyResponseAndCallback(callData) {
        // verify arguments
        if(typeof(callData.response) !== 'object' || typeof(callData.response.success) !== 'boolean') {
            let errorMsg = 'The response did not contain any data or is missing a success-flag';
            if(typeof(callData.onError) === 'function') {
                callData.onError(errorMsg);
            }
            this.callHook('error', errorMsg);
            return null;
        }

        let result = null;

        // check the success-flag
		if(callData.response.success === true) {
            // Is there a callback? if yes, call it
			if(typeof(callData.callback) === 'function') {
				if(typeof(callData.response.data) === 'object') {
					callData.callback(callData.response.data);
				} else {
					callData.callback();
				}
			}
            // set the result to null so no retry is performed
            result = null;

		} else {
			// Check if an error code was transmitted that signals an invalid session
            // and if yes, also check if this call should be retried
			if(typeof(callData.response.code) === 'string' && callData.response.code === 'PERMISSION_NO_SESSION' && !callData.doNotRetry) {

                // check whether the API issued a quick-relogin-token for us
                if(typeof(callData.response.token) !== 'string') {
                    result = null;
                    let errorMsg = 'A quick relogin-token is missing in the API response. ' + callData.method + ' - ' + callData.response.msg;
                    if(typeof(callData.onError) === 'function') {
                        callData.onError(errorMsg);
                    }
                    this.callHook('error', errorMsg);
                } else {
                    // Remove the old session token from the call data
                    if(typeof(callData.data) === 'object' && callData.data !== null) {
                        delete callData.data.token;
                    }
                    // Append the new quick-relogin token we received in the response
                    callData.retryToken = callData.response.token;

                    // Set the doNotRetry-flag to true in order to prevent infinite retry-loops
                    callData.doNotRetry = true;

                    // Remove the previous response from the call information
                    delete callData.response;

                    // set altered call-data as our return-object in order to signal a retry to the calling function
                    result = callData;
                }
			} else {
                // If the error occured due to any other problem besides the session, or the doNotRetry flag is set, raise the error
                let errorMsg = callData.method + ' - ' + callData.response.msg;
                if(typeof(callData.onError) === 'function') {
                    callData.onError(errorMsg);
                }
                this.callHook('error', errorMsg);
			}
		}

		return result;
	}
	
	/**
     * Executes a multicall request, carrying multiple Calls in one request.
     * Each call's callback will be individually called upon retrieval of a valid response.
     * Additionally, a callback for the multicall itself can be defined.
     * Calls can additionally have a breaking-attribute set to true which causes the API to stop executing further calls if one fails.
     * @param {CallData[]} calls the calls to execute
     * @param {SuccessCallback} [callback=null] a function that will be called when the multicall finished
     * @param {ErrCallback} [onError=null] a function that will be called when the multicall encounters any error
     */
	multicall(calls, callback = null, onError = null) {

        // Define the function that will be executed when we receive the response to the multicall
		let multicallCallback = (multicallData) => {
			let retryCalls = [];

            // loop over all individual responses and verify them
            // Then either execute their callback or schedule them for a retry
			for(let i = 0; i < multicallData.responses.length; i++) {
				calls[i].response = multicallData.responses[i];
				let retryCallData = this.verifyResponseAndCallback(calls[i]);
				if(retryCallData !== null) {
                    // schedule for retry
					retryCalls.push(retryCallData);
				}
			}

			// If we scheduled calls for a retry: Relogin and send these calls alongside the login
			if(retryCalls.length > 0) {
				this.relogin(retryCalls, onError);
			}

            // Call the Multicall-callback if any was provided
			if(typeof(callback) === 'function') {
				callback();
			}
		};
		
        // prepare the multicall data payload by copying method and data from the individual calls
        // breaking-attribute is pushed into the data object
		let multiCallContent = { calls : [] };
        calls.forEach((call) => {
			let callData = call.data || {};
			callData.method = call.method;
            if(typeof(call.breaking) === 'boolean') {
                callData.breaking = call.breaking;
            }
			multiCallContent.calls.push(callData);
		});

        // convert data of the calls into a JSON string
        let multiCallContentJSON = JSON.stringify(multiCallContent);
		
        // Send the multicall to the API
		this.call({
			method : 'multicall', 
			data : {
				content : multiCallContentJSON
			},
			rawCalls : calls,
			callback : multicallCallback,
            onError : onError
		});
	}

    /**
     * Builds a FormData Object from call information.
     * Every attribute of callData.data and also the method field will be set.
     * @param {CallData} callData Details of the call
     * @returns {FormData} FormData constructed from the call information
     */
    makeFormData(callData) {
        let formData = new FormData();
        formData.append('method', callData.method);
        Object.keys(callData.data).forEach((key) => {
            formData.append(key, callData.data[key]);
        });
        return formData;
    }
    
    /* -----------------------------------------------------
       Utility functions from https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
       ----------------------------------------------------- */
    sha256(str) {
        // We transform the string into an arraybuffer.
        let buffer = new TextEncoder('utf-8').encode(str);
        return crypto.subtle.digest('SHA-256', buffer).then((hash) => {
            return this.hex(hash);
        });
    }

    hex(buffer) {
        let hexCodes = [];
        let view = new DataView(buffer);
        for (let i = 0; i < view.byteLength; i += 4) {
            // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
            let value = view.getUint32(i)
            // toString(16) will give the hex representation of the number without padding
            let stringValue = value.toString(16)
            // We use concatenation and slice for padding
            let padding = '00000000'
            let paddedValue = (padding + stringValue).slice(-padding.length)
            hexCodes.push(paddedValue);
        }

        // Join all the hex strings into one
        return hexCodes.join('');
    }

	/* ----------------------------------------------------------
	   SESSION-FUNCTIONS
	   ---------------------------------------------------------- */
	/**
     * Performs a login for a given user
     * @param {string} username The username of the user to log in
     * @param {string} password Password of the user to login
     * @param {SuccessCallback} [callback=null] Function to call after successful Login
     * @param {ErrCallback} [onError=null] Function to call if any error occurs
     */
	login(username, password, callback = null, errorCallback = null) {
		// Calculate the password-hash
        // First translate the username to upper case and get the hash of that
		this.sha256(username.toUpperCase())
        .then((digest) => {

            // Then use that as a salt and hash the result of salt and password
			return this.sha256(digest + password);

        }).then((passwordHash) => {

            // Locally store the username and password-hash combination on the users device
            // This allows automatic relogin in the future
            localStorage.setItem('session_username', username);
            localStorage.setItem('session_password', passwordHash);

            // Request a login-token from the API
            this.getLoginToken((data) => {
                if(typeof(data.token) !== 'string') {
                    let errorMsg = 'The /session/request_login_token method returned no error, but also no token';
                    if(typeof(onError) === 'function') {
                        onError(errorMsg);
                    }
                    this.callHook('error', errorMsg);
                } else {
                    // Then use that token to login
                    api.loginWithToken(username, passwordHash, data.token, callback, onError, this.loginCalls);
                }
            }, onError);

		});
	}

    /**
     * Performs an automatic Relogin after a session expired and repeats a series of calls that were previously rejected due to the expired session.
     * This method is only for internal use and is called by the call or multicall methods.
     * @param {CallData[]} retryCalls Calls to be sent alongside the relogin as a multicall
     * @param {ErrCallback} [errorCallback=null] Function to call when any error occurs
     */
    relogin(retryCalls, errorCallback = null) {
		// Reset locally stored session data
		localStorage.removeItem('session_token');
		this.session = null;
		
        // Read username and password hash from local storage
		let username = localStorage.getItem('session_username');
		let passwordHash = localStorage.getItem('session_password');
		
		// Find the retry-token within the call information
        let retryToken = null;
		let retryTokenCall = retryCalls.find(
            (call) => {
                return typeof(call.retryToken) === 'string';
            }
        );
        if(retryTokenCall === null) {
            // for some reason we did not receive any quick-relogin-token
            let errorMsg = 'Retrying Calls failed because no quick-relogin-token was issued by the API';
            if(typeof(onError) === 'function') {
                onError(errorMsg);
            }
            this.callHook('error', errorMsg);
        } else {
            retryToken = retryTokenCall.retryToken;

            // Perform the Login
            this.loginWithToken(username, passwordHash, retryToken, null, onError, retryCalls);
        }
	}

	/**
     * Requests a Login-Token from the API. Only for internal use.
     * @param {SuccessCallback} callback The function to call after the token is received
     * @param {ErrCallback} [onError=null] Function to call when any error occurs
     */
	getLoginToken(callback, onError = null) {
		this.call({
			method : 'session/request_login_token',
			callback : callback,
            onError : onError
		});
	}

    /**
     * Perform the actual login with a login token. Only for internal use.
     * @param {string} username Username of the user to log in
     * @param {string} passwordHash Hash of the users password
     * @param {string} token The Login-Token issued by the API
     * @param {SuccessCallback} [callback=null] Function to call after successful login. This will be executed BEFORE potential callbacks of additionalCalls.
     * @param {ErrCallback} [onError=null] Function to call when any error occurs
     * @param {CallData[]} [additionalCalls=null] Calls to be executed directly after the Login-Call, will be sent alongside the login-call as a multicall
     * @param {SuccessCallback} [endCallback=null] Function to call after successful login. This will be executed AFTER potential callbacks of additionalCalls and only if any additionalCalls are present.
     */
	loginWithToken(username, passwordHash, token, loginCallback = null, onError = null, additionalCalls = null, endCallback = null) {
        // salt the password with the token and create a new hash
        // This will only be valid one time for the current token and thus prevents replay-attacks
		this.sha256(passwordHash + token)
        .then((hash) => {
            // prepare the function to be executed upon successful login
			let loginCallback = (data) => {
				// store the session key locally, this enables quick reestablishment of the session in the future if it has not expired
				localStorage.setItem('session_token', data.session.token);
				// execute miscellaneous tasks (start keep alive etc.)
				this.sessionEstablished(data, callback, onError);
			};
			
            // If we have additionalCalls set then this must be executed as a multicall
			if(Array.isArray(additionalCalls) && additionalCalls.length > 0) {
				// Build individual Calls of the multicall
                // all will be flagged as doNotRetry, because if the login fails there is no use in retrying it
				let calls = [];

				// First the Login call
                // It has the breaking-Flag set, if it fails all the other calls should not be executed by the API
				let login = {
					method : 'session/login',
					data : {
						username : username,
						password_hash : hash
					},
					callback : callback,
                    onError : onError,
					doNotRetry : true,
                    breaking : true
				};
				calls.push(login);

				// Then attach the additionalCalls
                additionalCalls.forEach((additionalCall) => {
					additionalCall.doNotRetry = true;
					calls.push(additionalCall);
				});
				
                // Execute the multicall
				this.multicall(calls, endCallback, onError);
			} else {
                // If no additionalCalls are present, just execute a normal login
                // it will be flagged with doNotRetry, as retrying it would just fail again
				this.call({
					method : 'session/login',
					data : {
						username : username,
						password_hash : hash
					},
					callback : callback,
                    onError : onError,
					doNotRetry : true
				});
			}
		});
	}

    /**
     * Only for internal use. It is called after a successful login.
     * Stores the session data, starts the keepalive-timer and calls the login-callback.
     * @param {APIResponse} data contains Session-Data received from login-call
     * @param {SuccessCallback} [callback=null] Function to execute after the successful login
     * @param {ErrCallback} [onError=null] Function to call when any error occurs
     */
	sessionEstablished(data, callback = null, onError = null) {
        // store session data
		this.session = data.session;
		
		// start Keep-Alive
		this.startKeepAlive();
		
		// Callback
		if(typeof(callback) === 'function') {
			callback();
		}
	}

    /**
     * Verifies whether a session with a given token is still valid.
     * If not, an automatic login will be performed with stored username and password-hash, if present.
     * If any of the two processes lead to a valid session, the loginCalls will also be executed!
     * @param {string} token The session token to check
     * @param {SuccessCallback} [callback=null] Function to be called upon successful establishment of session
     * @param {ErrCallback} [onError=null] Function to call when any error occurs
     */
	checkSession(token, callback = null, onError = null) {
        // Define Callback to execute when the request returns
        let checkSessionCallback = (data) => {
            // Check whether the session is still valid
            if(data.session_valid === true) {
                this.sessionEstablished(data, callback, onError);
            } else {
                // Session is expired, remove the stored token
                localStorage.removeItem('session_token');
                // Try an automatic relogin
                let username = localStorage.getItem('session_username');
                let passwordHash = localStorage.getItem('session_password');
                if(typeof(username) === 'string' && typeof(passwordHash) === 'string') {
                    this.loginWithToken(username, passwordHash, data.token, callback, onError, this.loginCalls);
                }
            };
        };

        // If we have loginCalls set then this must be executed as a multicall
        if(Array.isArray(this.loginCalls) && this.loginCalls.length > 0) {
            // Build individual Calls of the multicall
            // all will be flagged as doNotRetry, because if the checkSession fails there is no use in retrying it
            let calls = [];

            // First the checkSession call
            // It has the breaking-Flag set, if it fails all the other calls will not be executed by the API
            let login = {
                method : 'session/check_session',
                data : {
                    token : token
                },
                callback : checkSessionCallback,
                onError : onError,
                doNotRetry : true,
                breaking : true
            };
            calls.push(login);

            // Then attach the loginCalls, add our session token to all of them
            this.loginCalls.forEach((loginCall) => {
                loginCall.doNotRetry = true;
                if(typeof(loginCall.data) !== 'object') {
                    loginCall.data = {};
                }
                loginCall.data.token = token;
                calls.push(loginCall);
            });
            
            // Execute the multicall
            this.multicall(calls, null, onError);
        } else {
            // If no loginCalls are present, just execute a normal login
            // it will be flagged with doNotRetry, as retrying it would just fail again
            this.call({
                method : 'session/check_session',
                data : {
                    token : token
                },
                callback : checkSessionCallback,
                onError : onError,
                doNotRetry : true
            });
        }
	}
	
    /**
     * Starts an internal interval that calls /sesseion/keep_alive every 30 minutes,
     * so the API server does not kill the session.
     */
	startKeepAlive() {
		// Set interval to 30 minutes
		this.keepAliveInterval = window.setInterval(() => {
			this.keepAlive();
		}, 1800000);
	}

    /**
     * Stops the interval that keeps the session alive
     */
	stopKeepAlive() {
		window.clearInterval(this.keepAliveInterval);
		this.keepAliveInterval = null;
	}
	
    /**
     * This sends a keepAlive call to the API
     * @param {SuccessCallback} [callback=null] Function to be called upon response
     */
	keepAlive(callback = null) {
		this.call({
			method : 'session/keep_alive',
			callback : callback
		});
	}
	
    /**
     * Terminates the current session
     * @param {SuccessCallback} [callback=null] Function to be called upon successful logout
     * @param {ErrCallback} [onError=null] Function to call when any error occurs
     */
	logout(callback = null, onError = null) {
		this.call({
			method : 'session/logout', 
			callback : () => {
				// delete locally stored data
				api.session = null;
				localStorage.removeItem('session_token');
				localStorage.removeItem('session_username');
				localStorage.removeItem('session_password');
				
				// stop Keep-Alive
				api.stopKeepAlive();
				
				// Callback
				if(typeof(callback) === 'function') {
					callback();
				}
			},
            onError : onError
		});
	};
}